using System.Buffers.Binary;
using System.Text;

namespace Nexus.Core.Tests;

/// <summary>
/// Builds synthetic PE files for the static-analysis tests.
///
/// Real malware samples cannot live in a repository, and a checked-in binary would
/// be both unreviewable and liable to trip the developer's own antivirus. Building
/// the exact structure a test needs is more precise anyway: a test for "packed code
/// section" can set the entropy directly instead of hoping a sample still has it.
/// </summary>
public sealed class PeBuilder
{
    private const int PeOffset = 0x80;
    private const uint FileAlignment = 0x200;
    private const uint SectionAlignment = 0x1000;
    private const int MaxDataDirectories = 16;

    private readonly List<(string Name, uint Characteristics, byte[] Data, uint VirtualSize)> _sections = [];
    private readonly Dictionary<string, string[]> _imports = new(StringComparer.Ordinal);

    private bool _is64Bit;
    private bool _isDll;
    private bool _isManaged;
    private uint _timeDateStamp = 0x60000000;
    private uint _entryPointRva;
    private ushort _dllCharacteristics = 0x0040 | 0x0100; // ASLR + DEP
    private byte[] _overlay = [];

    public const uint CodeCharacteristics = 0x60000020;      // read + execute + code
    public const uint DataCharacteristics = 0x40000040;      // read + initialised data
    public const uint WritableCodeCharacteristics = 0xE0000020; // read + write + execute

    public PeBuilder As64Bit() { _is64Bit = true; return this; }
    public PeBuilder AsDll() { _isDll = true; return this; }
    public PeBuilder AsManaged() { _isManaged = true; return this; }
    public PeBuilder WithTimestamp(DateTimeOffset when) { _timeDateStamp = (uint)when.ToUnixTimeSeconds(); return this; }
    public PeBuilder WithoutMitigations() { _dllCharacteristics = 0; return this; }
    public PeBuilder WithOverlay(int bytes) { _overlay = new byte[bytes]; return this; }

    public PeBuilder WithEntryPointRva(uint rva)
    {
        _entryPointRva = rva;
        return this;
    }

    public PeBuilder AddSection(string name, uint characteristics, byte[] data, uint? virtualSize = null)
    {
        _sections.Add((name, characteristics, data, virtualSize ?? (uint)data.Length));
        return this;
    }

    /// <summary>Adds a code section whose bytes are incompressible, so it reads as packed.</summary>
    public PeBuilder AddHighEntropySection(string name = ".text", uint characteristics = CodeCharacteristics, int size = 4096)
    {
        var random = new Random(1234);
        var data = new byte[size];
        random.NextBytes(data);
        return AddSection(name, characteristics, data);
    }

    /// <summary>Adds a code section of repetitive bytes, so it reads as unpacked.</summary>
    public PeBuilder AddLowEntropySection(string name = ".text", uint characteristics = CodeCharacteristics, int size = 4096)
    {
        var data = new byte[size];
        for (int i = 0; i < size; i++)
            data[i] = (byte)(i % 4 == 0 ? 0x90 : 0x00);
        return AddSection(name, characteristics, data);
    }

    public PeBuilder WithImports(string library, params string[] functions)
    {
        _imports[library] = functions;
        return this;
    }

    public byte[] Build()
    {
        if (_sections.Count == 0)
            AddLowEntropySection();

        if (_imports.Count > 0)
            AppendImportSection();

        int optionalHeaderSize = (_is64Bit ? 112 : 96) + MaxDataDirectories * 8;
        int sectionTableOffset = PeOffset + 4 + 20 + optionalHeaderSize;
        int headersSize = sectionTableOffset + _sections.Count * 40;
        uint sizeOfHeaders = Align((uint)headersSize, FileAlignment);

        // Lay the sections out in the file and in memory.
        var placed = new List<(string Name, uint Characteristics, byte[] Data, uint VirtualSize, uint Rva, uint RawOffset)>();
        uint rva = SectionAlignment;
        uint rawOffset = sizeOfHeaders;

        foreach (var (name, characteristics, data, virtualSize) in _sections)
        {
            placed.Add((name, characteristics, data, virtualSize, rva, rawOffset));
            rva += Align(Math.Max(virtualSize, (uint)data.Length), SectionAlignment);
            rawOffset += Align((uint)data.Length, FileAlignment);
        }

        int totalSize = (int)rawOffset + _overlay.Length;
        var image = new byte[totalSize];

        // ---- DOS header ----
        image[0] = (byte)'M';
        image[1] = (byte)'Z';
        WriteUInt32(image, 0x3C, PeOffset);

        // ---- PE signature ----
        WriteUInt32(image, PeOffset, 0x00004550);

        // ---- COFF header ----
        int coff = PeOffset + 4;
        WriteUInt16(image, coff, _is64Bit ? (ushort)0x8664 : (ushort)0x014C);
        WriteUInt16(image, coff + 2, (ushort)placed.Count);
        WriteUInt32(image, coff + 4, _timeDateStamp);
        WriteUInt16(image, coff + 16, (ushort)optionalHeaderSize);
        WriteUInt16(image, coff + 18, (ushort)(_isDll ? 0x2102 : 0x0102));

        // ---- Optional header ----
        int optional = coff + 20;
        WriteUInt16(image, optional, _is64Bit ? (ushort)0x20B : (ushort)0x10B);
        WriteUInt32(image, optional + 16, _entryPointRva == 0 ? SectionAlignment : _entryPointRva);
        WriteUInt32(image, optional + 56, rva);            // SizeOfImage
        WriteUInt32(image, optional + 60, sizeOfHeaders);  // SizeOfHeaders
        WriteUInt16(image, optional + 68, 3);              // Subsystem: console
        WriteUInt16(image, optional + 70, _dllCharacteristics);

        int rvaCountOffset = optional + (_is64Bit ? 108 : 92);
        WriteUInt32(image, rvaCountOffset, MaxDataDirectories);

        int dataDirectories = optional + (_is64Bit ? 112 : 96);

        // Directory 1: import table.
        var importSection = placed.FirstOrDefault(s => s.Name == ".idata");
        if (importSection.Name == ".idata")
            WriteUInt32(image, dataDirectories + 1 * 8, importSection.Rva);

        // Directory 14: CLR header, which is what marks a file as managed.
        if (_isManaged)
            WriteUInt32(image, dataDirectories + 14 * 8, placed[0].Rva);

        // ---- Section table ----
        for (int i = 0; i < placed.Count; i++)
        {
            var section = placed[i];
            int offset = sectionTableOffset + i * 40;

            var nameBytes = Encoding.ASCII.GetBytes(section.Name);
            Array.Copy(nameBytes, 0, image, offset, Math.Min(8, nameBytes.Length));

            WriteUInt32(image, offset + 8, section.VirtualSize);
            WriteUInt32(image, offset + 12, section.Rva);
            WriteUInt32(image, offset + 16, (uint)section.Data.Length);
            WriteUInt32(image, offset + 20, section.Data.Length == 0 ? 0 : section.RawOffset);
            WriteUInt32(image, offset + 36, section.Characteristics);

            if (section.Data.Length > 0)
                Array.Copy(section.Data, 0, image, (int)section.RawOffset, section.Data.Length);
        }

        if (_overlay.Length > 0)
            Array.Copy(_overlay, 0, image, totalSize - _overlay.Length, _overlay.Length);

        return image;
    }

    /// <summary>
    /// Builds a .idata section: descriptors, then per-library thunk arrays, names,
    /// and hint/name entries — all with RVAs relative to the section's own base.
    /// </summary>
    private void AppendImportSection()
    {
        // The section's RVA depends on the sections before it, so compute it the same
        // way Build() will.
        uint sectionRva = SectionAlignment;
        foreach (var (_, _, data, virtualSize) in _sections)
            sectionRva += Align(Math.Max(virtualSize, (uint)data.Length), SectionAlignment);

        int descriptorBytes = (_imports.Count + 1) * 20;
        var blob = new List<byte>();
        blob.AddRange(new byte[descriptorBytes]);

        var descriptors = new List<(uint ThunkRva, uint NameRva)>();

        foreach (var (library, functions) in _imports)
        {
            // Thunk array: one RVA per function, then a null terminator.
            uint thunkRva = sectionRva + (uint)blob.Count;
            var thunkSlot = blob.Count;
            blob.AddRange(new byte[(functions.Length + 1) * 4]);

            uint nameRva = sectionRva + (uint)blob.Count;
            blob.AddRange(Encoding.ASCII.GetBytes(library));
            blob.Add(0);

            for (int i = 0; i < functions.Length; i++)
            {
                // A hint/name entry is a 2-byte hint followed by the ASCII name; the
                // thunk points at the hint, so the parser reads the name at +2.
                uint hintNameRva = sectionRva + (uint)blob.Count;
                blob.AddRange(new byte[2]);
                blob.AddRange(Encoding.ASCII.GetBytes(functions[i]));
                blob.Add(0);
                if (blob.Count % 2 != 0)
                    blob.Add(0);

                var slot = blob.ToArray();
                BinaryPrimitives.WriteUInt32LittleEndian(slot.AsSpan(thunkSlot + i * 4), hintNameRva);
                blob.Clear();
                blob.AddRange(slot);
            }

            descriptors.Add((thunkRva, nameRva));
        }

        var final = blob.ToArray();
        for (int i = 0; i < descriptors.Count; i++)
        {
            int offset = i * 20;
            BinaryPrimitives.WriteUInt32LittleEndian(final.AsSpan(offset), descriptors[i].ThunkRva);
            BinaryPrimitives.WriteUInt32LittleEndian(final.AsSpan(offset + 12), descriptors[i].NameRva);
            BinaryPrimitives.WriteUInt32LittleEndian(final.AsSpan(offset + 16), descriptors[i].ThunkRva);
        }

        _sections.Add((".idata", DataCharacteristics, final, (uint)final.Length));
    }

    private static uint Align(uint value, uint alignment) =>
        value == 0 ? 0 : (value + alignment - 1) / alignment * alignment;

    private static void WriteUInt16(byte[] buffer, int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset), value);

    private static void WriteUInt32(byte[] buffer, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset), value);
}
