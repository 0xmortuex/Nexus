using System.IO.Compression;

namespace Nexus.Core.Security.StaticAnalysis;

/// <summary>
/// Reads ZIP archives and reports what is inside them.
///
/// This lives in Core rather than in the scanner worker for one reason: every limit
/// in here is a security control against an attacker-controlled file, and security
/// controls that cannot be unit-tested are security controls nobody has checked. A
/// 42 KB archive can expand to petabytes, an entry can be named
/// <c>..\..\Windows\System32\x.dll</c>, and a nested archive can recurse until
/// something falls over.
///
/// Nothing here writes to disk or executes anything. Entry contents are handed to a
/// caller-supplied analyser, which is how the worker plugs its PE and script engines
/// in without this type depending on either.
/// </summary>
public static class ArchiveInspector
{
    /// <summary>Entries examined before giving up. More than this is a bundle, not a payload.</summary>
    public const int MaxEntries = 256;

    /// <summary>Total bytes expanded across the whole archive.</summary>
    public const long MaxTotalUncompressedBytes = 64L * 1024 * 1024;

    /// <summary>Bytes read from any single entry.</summary>
    public const long MaxEntryBytes = 16L * 1024 * 1024;

    /// <summary>An entry claiming to expand more than this many times is a zip bomb.</summary>
    public const long MaxCompressionRatio = 200;

    /// <summary>How deep to open archives inside archives.</summary>
    public const int MaxNestingDepth = 2;

    /// <summary>Analyses one entry's bytes; the caller supplies the real engines.</summary>
    public delegate IReadOnlyList<SecuritySignal> EntryAnalyser(byte[] content, string entryName);

    /// <summary>
    /// The limits, carried across every level of nesting.
    ///
    /// This is the whole reason nesting is safe to allow. If each archive got a fresh
    /// budget, an attacker could nest ten archives and multiply the expansion ceiling
    /// by ten — which turns the zip-bomb defence into a zip-bomb amplifier. One budget
    /// is created at the top and every level spends from it.
    /// </summary>
    public sealed class ArchiveBudget
    {
        public int EntriesExamined { get; set; }
        public long BytesExpanded { get; set; }

        /// <summary>How many archives deep the current entry sits.</summary>
        public int Depth { get; set; }

        public bool Exhausted =>
            EntriesExamined >= MaxEntries || BytesExpanded >= MaxTotalUncompressedBytes;

        public bool CanDescend => Depth < MaxNestingDepth && !Exhausted;
    }

    /// <summary>
    /// One entry, as the limit checks need to see it.
    ///
    /// This exists so every archive format goes through the same rules. The limits
    /// above are security controls against an attacker-controlled file, and keeping a
    /// second copy of them for 7z and a third for RAR is how one copy quietly ends up
    /// missing a check.
    /// </summary>
    /// <param name="Read">Reads at most the given number of bytes. Returns empty when
    /// the entry cannot be decompressed — encrypted entries land here.</param>
    public sealed record ArchiveEntryView(
        string Name,
        long UncompressedLength,
        long CompressedLength,
        Func<long, byte[]> Read);

    /// <summary>Archive formats Nexus recognises from the bytes themselves.</summary>
    public enum ArchiveFormat
    {
        None,
        Zip,
        SevenZip,
        Rar,
        GZip,
        BZip2,
        Xz,
        Tar,
    }

    /// <summary>
    /// Identify an archive by its magic bytes rather than its extension. A file named
    /// .txt is still a 7z archive if it starts like one, and malware delivered in
    /// archives depends on the extension being believed.
    /// </summary>
    public static ArchiveFormat DetectFormat(ReadOnlySpan<byte> bytes)
    {
        if (LooksLikeZip(bytes))
            return ArchiveFormat.Zip;

        if (StartsWith(bytes, [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]))
            return ArchiveFormat.SevenZip;

        if (StartsWith(bytes, [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]))
            return ArchiveFormat.Rar;

        if (StartsWith(bytes, [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]))
            return ArchiveFormat.Xz;

        if (StartsWith(bytes, [0x1F, 0x8B]))
            return ArchiveFormat.GZip;

        if (StartsWith(bytes, [0x42, 0x5A, 0x68]))
            return ArchiveFormat.BZip2;

        // TAR has no leading magic; the marker sits 257 bytes in.
        if (bytes.Length >= 262
            && bytes[257] == (byte)'u' && bytes[258] == (byte)'s' && bytes[259] == (byte)'t'
            && bytes[260] == (byte)'a' && bytes[261] == (byte)'r')
        {
            return ArchiveFormat.Tar;
        }

        return ArchiveFormat.None;
    }

    private static bool StartsWith(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> magic) =>
        bytes.Length >= magic.Length && bytes[..magic.Length].SequenceEqual(magic);

    public static bool LooksLikeZip(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= 4
        && bytes[0] == 0x50 && bytes[1] == 0x4B
        && (bytes[2] == 0x03 || bytes[2] == 0x05 || bytes[2] == 0x07);

    public static IReadOnlyList<SecuritySignal> Inspect(Stream archiveStream, EntryAnalyser analyseEntry) =>
        Inspect(archiveStream, analyseEntry, new ArchiveBudget());

    /// <summary>The same, spending from a budget shared with any outer archive.</summary>
    public static IReadOnlyList<SecuritySignal> Inspect(
        Stream archiveStream, EntryAnalyser analyseEntry, ArchiveBudget budget)
    {
        try
        {
            using var archive = new ZipArchive(archiveStream, ZipArchiveMode.Read, leaveOpen: true);
            return InspectEntries(archive, analyseEntry, budget);
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentException)
        {
            return
            [
                new SecuritySignal(SignalSource.StaticRules, SignalWeight.Weak, "archive-corrupt",
                    "This looks like an archive but could not be opened. That happens with damaged " +
                    "downloads, and also with archives deliberately malformed to defeat scanners."),
            ];
        }
    }

    private static IReadOnlyList<SecuritySignal> InspectEntries(
        ZipArchive archive, EntryAnalyser analyseEntry, ArchiveBudget budget) =>
        InspectEntries(
            archive.Entries.Select(e => new ArchiveEntryView(
                e.FullName, e.Length, e.CompressedLength, limit => ReadEntry(e, limit))),
            analyseEntry,
            budget);

    /// <summary>
    /// Apply every limit and rule to a sequence of entries, whatever produced them.
    /// This is the single place the archive rules live.
    /// </summary>
    public static IReadOnlyList<SecuritySignal> InspectEntries(
        IEnumerable<ArchiveEntryView> entries, EntryAnalyser analyseEntry) =>
        InspectEntries(entries, analyseEntry, new ArchiveBudget());

    /// <summary>
    /// The same, spending from a caller-supplied budget so that an archive opened
    /// inside another archive shares the outer one's limits.
    /// </summary>
    public static IReadOnlyList<SecuritySignal> InspectEntries(
        IEnumerable<ArchiveEntryView> entries, EntryAnalyser analyseEntry, ArchiveBudget budget)
    {
        var signals = new List<SecuritySignal>();
        var executableNames = new List<string>();
        bool truncated = false;

        foreach (var entry in entries)
        {
            if (budget.Exhausted)
            {
                truncated = true;
                break;
            }

            // Counted here, before any of the skips below. Counting only entries whose
            // contents were read let an archive of a million empty or undecodable
            // entries walk the whole directory without ever exhausting the budget:
            // every one still costs a traversal check and a bomb-ratio check.
            budget.EntriesExamined++;

            if (entry.UncompressedLength == 0)
                continue;

            if (HasTraversalPath(entry.Name))
            {
                signals.Add(new SecuritySignal(
                    SignalSource.StaticRules, SignalWeight.Strong, "archive-path-traversal",
                    $"An entry in this archive ({entry.Name}) is named so that extracting it would " +
                    "write outside the folder you extract into. Archive tools do not do this by accident."));
                continue;
            }

            if (IsZipBomb(entry))
            {
                signals.Add(new SecuritySignal(
                    SignalSource.StaticRules, SignalWeight.Moderate, "archive-zip-bomb",
                    "An entry in this archive expands " +
                    $"{entry.UncompressedLength / Math.Max(1, entry.CompressedLength)}× " +
                    "its stored size. That pattern is used to exhaust disk or memory."));
                continue;
            }

            if (IsNestedArchive(entry.Name) && !budget.CanDescend)
            {
                signals.Add(new SecuritySignal(
                    SignalSource.StaticRules, SignalWeight.Weak, "archive-nested-unopened",
                    $"This archive contains another archive ({entry.Name}) that Nexus did not open, " +
                    (budget.Depth >= MaxNestingDepth
                        ? $"because it is more than {MaxNestingDepth} archives deep. "
                        : "because the limits for this file were already reached. ") +
                    "Its contents have not been cleared — they have not been looked at."));
                continue;
            }

            var content = entry.Read(MaxEntryBytes);
            if (content.Length == 0)
                continue;

            budget.BytesExpanded += content.Length;

            if (IsExecutableName(entry.Name))
                executableNames.Add(entry.Name);

            foreach (var signal in analyseEntry(content, entry.Name))
                signals.Add(Requalify(signal, entry.Name));
        }

        if (executableNames.Count > 0)
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules, SignalWeight.Informational, "archive-contains-executable",
                $"This archive contains {executableNames.Count} program file(s): " +
                string.Join(", ", executableNames.Take(5))));
        }

        if (truncated)
        {
            // Say so rather than letting a partial look read as a clean bill of health.
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules, SignalWeight.Informational, "archive-not-fully-examined",
                "This archive is large enough that Nexus stopped partway through it. What was not " +
                "examined has not been cleared."));
        }

        return signals;
    }

    /// <summary>
    /// Rewrite a finding so it names the entry it came from. Without this the report
    /// says "the code section is packed" about a file the user cannot see, which is
    /// worse than saying nothing.
    /// </summary>
    private static SecuritySignal Requalify(SecuritySignal signal, string entryName) =>
        signal with
        {
            // Prefixed once, however deep the nesting goes. An archive inside an
            // archive would otherwise produce "archive-archive-script-download-and-run",
            // and codes are what suppression and tests match on.
            Code = signal.Code.StartsWith("archive-", StringComparison.Ordinal)
                ? signal.Code
                : "archive-" + signal.Code,
            Explanation = $"Inside the archive, {entryName}: " +
                          char.ToLowerInvariant(signal.Explanation[0]) + signal.Explanation[1..],
        };

    /// <summary>
    /// An entry claiming to expand far beyond its stored size.
    ///
    /// A compressed size of zero means the format did not report one, not that the
    /// entry expands out of nothing. 7-Zip's solid compression gives no per-entry
    /// compressed size at all, so treating zero as an infinite ratio flagged every
    /// single 7z archive as a bomb — and, because a flagged entry is skipped, it hid
    /// the very payload the scan was looking for. That was measured, not theorised: a
    /// 7z containing a known dropper came back reporting only "archive-zip-bomb".
    ///
    /// So an unknown ratio stays unknown. The defence against actual expansion is not
    /// this label anyway — it is MaxEntryBytes and MaxTotalUncompressedBytes, which
    /// are enforced against bytes genuinely read rather than against anything the
    /// archive claims about itself.
    /// </summary>
    private static bool IsZipBomb(ArchiveEntryView entry) =>
        entry.CompressedLength > 0
        && entry.UncompressedLength / entry.CompressedLength > MaxCompressionRatio;

    private static byte[] ReadEntry(ZipArchiveEntry entry, long limit)
    {
        try
        {
            int size = (int)Math.Min(entry.Length, limit);
            var buffer = new byte[size];

            using var stream = entry.Open();
            int read = stream.ReadAtLeast(buffer, size, throwOnEndOfStream: false);

            if (read < size)
                Array.Resize(ref buffer, read);

            return buffer;
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or NotSupportedException)
        {
            // An entry that will not decompress (encrypted, or malformed) is skipped;
            // one bad entry must not lose the findings from the rest.
            return [];
        }
    }

    /// <summary>True when extracting this entry would escape the destination folder.</summary>
    public static bool HasTraversalPath(string entryName)
    {
        var normalized = entryName.Replace('\\', '/');

        return normalized.StartsWith('/')
               || normalized.StartsWith("../", StringComparison.Ordinal)
               || normalized.Contains("/../", StringComparison.Ordinal)
               || normalized.EndsWith("/..", StringComparison.Ordinal)
               || normalized == ".."
               || (normalized.Length >= 2 && normalized[1] == ':');
    }

    public static bool IsNestedArchive(string entryName)
    {
        var extension = Path.GetExtension(entryName).ToLowerInvariant();
        return extension is ".zip" or ".7z" or ".rar" or ".gz" or ".tar" or ".cab" or ".iso";
    }

    public static bool IsExecutableName(string entryName)
    {
        var extension = Path.GetExtension(entryName).ToLowerInvariant();
        return extension is ".exe" or ".dll" or ".scr" or ".com" or ".pif" or ".bat" or ".cmd"
            or ".js" or ".vbs" or ".ps1" or ".hta" or ".lnk" or ".msi";
    }
}
