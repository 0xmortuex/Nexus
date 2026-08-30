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

    /// <summary>Analyses one entry's bytes; the caller supplies the real engines.</summary>
    public delegate IReadOnlyList<SecuritySignal> EntryAnalyser(byte[] content, string entryName);

    public static bool LooksLikeZip(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= 4
        && bytes[0] == 0x50 && bytes[1] == 0x4B
        && (bytes[2] == 0x03 || bytes[2] == 0x05 || bytes[2] == 0x07);

    public static IReadOnlyList<SecuritySignal> Inspect(Stream archiveStream, EntryAnalyser analyseEntry)
    {
        try
        {
            using var archive = new ZipArchive(archiveStream, ZipArchiveMode.Read, leaveOpen: true);
            return InspectEntries(archive, analyseEntry);
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

    private static IReadOnlyList<SecuritySignal> InspectEntries(ZipArchive archive, EntryAnalyser analyseEntry)
    {
        var signals = new List<SecuritySignal>();
        long totalRead = 0;
        int examined = 0;
        var executableNames = new List<string>();
        bool truncated = false;

        foreach (var entry in archive.Entries)
        {
            if (examined >= MaxEntries || totalRead >= MaxTotalUncompressedBytes)
            {
                truncated = true;
                break;
            }

            if (entry.Length == 0)
                continue;

            if (HasTraversalPath(entry.FullName))
            {
                signals.Add(new SecuritySignal(
                    SignalSource.StaticRules, SignalWeight.Strong, "archive-path-traversal",
                    $"An entry in this archive ({entry.FullName}) is named so that extracting it would " +
                    "write outside the folder you extract into. Archive tools do not do this by accident."));
                continue;
            }

            if (IsZipBomb(entry))
            {
                signals.Add(new SecuritySignal(
                    SignalSource.StaticRules, SignalWeight.Moderate, "archive-zip-bomb",
                    $"An entry in this archive expands {entry.Length / Math.Max(1, entry.CompressedLength)}× " +
                    "its stored size. That pattern is used to exhaust disk or memory."));
                continue;
            }

            if (IsNestedArchive(entry.FullName))
            {
                signals.Add(new SecuritySignal(
                    SignalSource.StaticRules, SignalWeight.Weak, "archive-nested",
                    $"This archive contains another archive ({entry.FullName}). Nexus does not open " +
                    "archives inside archives, so its contents were not examined."));
                continue;
            }

            var content = ReadEntry(entry, MaxEntryBytes);
            if (content.Length == 0)
                continue;

            totalRead += content.Length;
            examined++;

            if (IsExecutableName(entry.FullName))
                executableNames.Add(entry.FullName);

            foreach (var signal in analyseEntry(content, entry.FullName))
                signals.Add(Requalify(signal, entry.FullName));
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
            Code = "archive-" + signal.Code,
            Explanation = $"Inside the archive, {entryName}: " +
                          char.ToLowerInvariant(signal.Explanation[0]) + signal.Explanation[1..],
        };

    private static bool IsZipBomb(ZipArchiveEntry entry) =>
        entry.CompressedLength > 0
        && entry.Length / entry.CompressedLength > MaxCompressionRatio;

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
