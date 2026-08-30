using System.Buffers.Binary;

namespace Nexus.Core.Security.StaticAnalysis;

/// <summary>One section of a PE file.</summary>
public sealed record PeSection
{
    public required string Name { get; init; }
    public required uint VirtualSize { get; init; }
    public required uint VirtualAddress { get; init; }
    public required uint RawSize { get; init; }
    public required uint RawOffset { get; init; }
    public required uint Characteristics { get; init; }

    public bool IsExecutable => (Characteristics & 0x20000000) != 0;
    public bool IsWritable => (Characteristics & 0x80000000) != 0;
    public bool IsReadable => (Characteristics & 0x40000000) != 0;

    /// <summary>Shannon entropy of the section's raw bytes, 0–8. Above ~7.2 usually
    /// means compressed or encrypted content.</summary>
    public double Entropy { get; init; }
}

/// <summary>
/// A parsed PE file — just enough structure for the heuristics, and nothing that
/// requires executing or loading it.
///
/// Every field is read with explicit bounds checks against the buffer length. This
/// parser's entire input is hostile by definition, and the historical record of
/// antivirus file parsers is not reassuring, so it does no pointer arithmetic, keeps
/// to managed slices, and returns null rather than throwing on anything malformed.
/// </summary>
public sealed record PeImage
{
    public required bool Is64Bit { get; init; }
    public required bool IsDll { get; init; }
    public required bool IsManaged { get; init; }
    public required uint TimeDateStamp { get; init; }
    public required uint EntryPointRva { get; init; }
    public required uint SizeOfImage { get; init; }
    public required ushort Subsystem { get; init; }
    public required ushort DllCharacteristics { get; init; }
    public required IReadOnlyList<PeSection> Sections { get; init; }

    /// <summary>Names of the DLLs in the import table.</summary>
    public required IReadOnlyList<string> ImportedLibraries { get; init; }

    /// <summary>Imported function names across all libraries.</summary>
    public required IReadOnlyList<string> ImportedFunctions { get; init; }

    /// <summary>Bytes past the end of the last section — installers and self-extracting
    /// archives put data here, and so do droppers.</summary>
    public required long OverlayBytes { get; init; }

    public required long FileSize { get; init; }

    /// <summary>ASLR is on.</summary>
    public bool HasDynamicBase => (DllCharacteristics & 0x0040) != 0;

    /// <summary>DEP is on.</summary>
    public bool HasNxCompat => (DllCharacteristics & 0x0100) != 0;

    // ---- Parsing ----

    private const int MaxSections = 96;          // the loader's own limit
    private const int MaxImportDescriptors = 1024;
    private const int MaxFunctionsPerLibrary = 4096;

    /// <summary>Parse a PE file, or return null if it is not one / is malformed.</summary>
    public static PeImage? TryParse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 0x40)
            return null;

        // "MZ"
        if (data[0] != 0x4D || data[1] != 0x5A)
            return null;

        // Every bounds check below is written as a subtraction rather than
        // `offset + size > length`, because a hostile file can set an offset near
        // int.MaxValue and make that addition overflow into a negative number that
        // passes the check. The header offset here is attacker-controlled.
        int peOffset = ReadInt32(data, 0x3C);
        if (peOffset <= 0 || peOffset > data.Length - 24)
            return null;

        // "PE\0\0"
        if (ReadUInt32(data, peOffset) != 0x00004550)
            return null;

        int coff = peOffset + 4;
        if (coff > data.Length - 20)
            return null;

        ushort sectionCount = ReadUInt16(data, coff + 2);
        uint timeDateStamp = ReadUInt32(data, coff + 4);
        ushort optionalHeaderSize = ReadUInt16(data, coff + 16);
        ushort characteristics = ReadUInt16(data, coff + 18);

        if (sectionCount == 0 || sectionCount > MaxSections)
            return null;

        int optionalHeader = coff + 20;
        if (optionalHeader > data.Length - 2)
            return null;

        ushort magic = ReadUInt16(data, optionalHeader);
        bool is64Bit = magic == 0x20B;
        if (magic is not (0x10B or 0x20B))
            return null;

        // Fields sit at different offsets in PE32 and PE32+.
        int minimumOptionalSize = is64Bit ? 112 : 96;
        if (optionalHeader > data.Length - minimumOptionalSize)
            return null;

        uint entryPoint = ReadUInt32(data, optionalHeader + 16);
        uint sizeOfImage = ReadUInt32(data, optionalHeader + 56);
        ushort subsystem = ReadUInt16(data, optionalHeader + 68);
        ushort dllCharacteristics = ReadUInt16(data, optionalHeader + 70);

        int dataDirectoryOffset = optionalHeader + (is64Bit ? 112 : 96);
        int rvaCountOffset = optionalHeader + (is64Bit ? 108 : 92);
        uint numberOfRvaAndSizes = rvaCountOffset >= 0 && rvaCountOffset <= data.Length - 4
            ? ReadUInt32(data, rvaCountOffset)
            : 0;

        var sectionTable = optionalHeader + optionalHeaderSize;
        var sections = ReadSections(data, sectionTable, sectionCount);
        if (sections is null)
            return null;

        // Directory 1 is the import table, directory 14 is the CLR header.
        var importDirectory = ReadDataDirectory(data, dataDirectoryOffset, 1, numberOfRvaAndSizes);
        var clrDirectory = ReadDataDirectory(data, dataDirectoryOffset, 14, numberOfRvaAndSizes);

        var (libraries, functions) = ReadImports(data, sections, importDirectory.Rva);

        return new PeImage
        {
            Is64Bit = is64Bit,
            IsDll = (characteristics & 0x2000) != 0,
            IsManaged = clrDirectory.Rva != 0,
            TimeDateStamp = timeDateStamp,
            EntryPointRva = entryPoint,
            SizeOfImage = sizeOfImage,
            Subsystem = subsystem,
            DllCharacteristics = dllCharacteristics,
            Sections = sections,
            ImportedLibraries = libraries,
            ImportedFunctions = functions,
            OverlayBytes = ComputeOverlay(data.Length, sections),
            FileSize = data.Length,
        };
    }

    private static IReadOnlyList<PeSection>? ReadSections(ReadOnlySpan<byte> data, int tableOffset, int count)
    {
        const int entrySize = 40;
        if (tableOffset < 0 || count < 0 || count > (data.Length - tableOffset) / entrySize)
            return null;

        var sections = new List<PeSection>(count);

        for (int i = 0; i < count; i++)
        {
            int offset = tableOffset + i * entrySize;

            var nameBytes = data.Slice(offset, 8);
            int nameLength = nameBytes.IndexOf((byte)0);
            var name = System.Text.Encoding.ASCII.GetString(
                nameBytes[..(nameLength < 0 ? 8 : nameLength)]);

            uint rawSize = ReadUInt32(data, offset + 16);
            uint rawOffset = ReadUInt32(data, offset + 20);

            sections.Add(new PeSection
            {
                Name = name,
                VirtualSize = ReadUInt32(data, offset + 8),
                VirtualAddress = ReadUInt32(data, offset + 12),
                RawSize = rawSize,
                RawOffset = rawOffset,
                Characteristics = ReadUInt32(data, offset + 36),
                Entropy = ComputeEntropy(data, rawOffset, rawSize),
            });
        }

        return sections;
    }

    private static (uint Rva, uint Size) ReadDataDirectory(
        ReadOnlySpan<byte> data, int directoryOffset, int index, uint count)
    {
        if (index >= count)
            return (0, 0);

        int offset = directoryOffset + index * 8;
        if (offset < 0 || offset > data.Length - 8)
            return (0, 0);

        return (ReadUInt32(data, offset), ReadUInt32(data, offset + 4));
    }

    private static (IReadOnlyList<string> Libraries, IReadOnlyList<string> Functions) ReadImports(
        ReadOnlySpan<byte> data, IReadOnlyList<PeSection> sections, uint importRva)
    {
        var libraries = new List<string>();
        var functions = new List<string>();

        if (importRva == 0)
            return (libraries, functions);

        int descriptorOffset = RvaToOffset(sections, importRva);
        if (descriptorOffset < 0)
            return (libraries, functions);

        for (int i = 0; i < MaxImportDescriptors; i++)
        {
            int offset = descriptorOffset + i * 20;
            if (offset < 0 || offset > data.Length - 20)
                break;

            uint originalFirstThunk = ReadUInt32(data, offset);
            uint nameRva = ReadUInt32(data, offset + 12);
            uint firstThunk = ReadUInt32(data, offset + 16);

            // A zeroed descriptor terminates the table.
            if (originalFirstThunk == 0 && nameRva == 0 && firstThunk == 0)
                break;

            var libraryName = ReadAsciiAtRva(data, sections, nameRva, maxLength: 128);
            if (libraryName is { Length: > 0 })
                libraries.Add(libraryName);

            ReadThunks(data, sections, originalFirstThunk != 0 ? originalFirstThunk : firstThunk, functions);
        }

        return (libraries, functions);
    }

    private static void ReadThunks(
        ReadOnlySpan<byte> data, IReadOnlyList<PeSection> sections, uint thunkRva, List<string> functions)
    {
        if (thunkRva == 0)
            return;

        int thunkOffset = RvaToOffset(sections, thunkRva);
        if (thunkOffset < 0)
            return;

        // Only 32-bit thunks are walked; the low 31 bits of a 64-bit thunk hold the
        // same hint/name RVA, so this reads both layouts correctly enough for
        // heuristics without a second code path.
        for (int i = 0; i < MaxFunctionsPerLibrary; i++)
        {
            int offset = thunkOffset + i * 4;
            if (offset < 0 || offset > data.Length - 4)
                return;

            uint thunk = ReadUInt32(data, offset);
            if (thunk == 0)
                return;

            // High bit set means "imported by ordinal", which carries no name.
            if ((thunk & 0x80000000) != 0)
                continue;

            // The hint/name entry is a 2-byte hint followed by the ASCII name.
            var name = ReadAsciiAtRva(data, sections, thunk + 2, maxLength: 128);
            if (name is { Length: > 0 })
                functions.Add(name);
        }
    }

    private static string? ReadAsciiAtRva(
        ReadOnlySpan<byte> data, IReadOnlyList<PeSection> sections, uint rva, int maxLength)
    {
        int offset = RvaToOffset(sections, rva);
        if (offset < 0 || offset >= data.Length)
            return null;

        int available = Math.Min(maxLength, data.Length - offset);
        var slice = data.Slice(offset, available);

        int end = slice.IndexOf((byte)0);
        if (end < 0)
            end = available;

        return System.Text.Encoding.ASCII.GetString(slice[..end]);
    }

    /// <summary>Map a virtual address back to a file offset using the section table.</summary>
    private static int RvaToOffset(IReadOnlyList<PeSection> sections, uint rva)
    {
        foreach (var section in sections)
        {
            uint size = Math.Max(section.VirtualSize, section.RawSize);
            if (rva < section.VirtualAddress || rva >= section.VirtualAddress + size)
                continue;

            long offset = section.RawOffset + (rva - section.VirtualAddress);
            return offset is >= 0 and < int.MaxValue ? (int)offset : -1;
        }

        return -1;
    }

    private static long ComputeOverlay(int fileSize, IReadOnlyList<PeSection> sections)
    {
        long endOfLastSection = 0;

        foreach (var section in sections)
        {
            if (section.RawSize == 0)
                continue;

            long end = (long)section.RawOffset + section.RawSize;
            if (end > endOfLastSection)
                endOfLastSection = end;
        }

        return endOfLastSection > 0 && fileSize > endOfLastSection ? fileSize - endOfLastSection : 0;
    }

    /// <summary>Shannon entropy over a byte range, in bits per byte (0–8).</summary>
    public static double ComputeEntropy(ReadOnlySpan<byte> data, uint offset, uint length)
    {
        if (length == 0 || offset >= (uint)data.Length)
            return 0;

        int available = (int)Math.Min(length, (uint)(data.Length - offset));
        if (available <= 0)
            return 0;

        var slice = data.Slice((int)offset, available);

        Span<int> histogram = stackalloc int[256];
        foreach (byte b in slice)
            histogram[b]++;

        double entropy = 0;
        foreach (int count in histogram)
        {
            if (count == 0)
                continue;

            double probability = (double)count / available;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, 2));

    private static uint ReadUInt32(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));

    private static int ReadInt32(ReadOnlySpan<byte> data, int offset) =>
        BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
}
