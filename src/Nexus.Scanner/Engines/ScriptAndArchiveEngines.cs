using System.IO.Compression;
using Nexus.Core.Security;
using Nexus.Core.Security.StaticAnalysis;

namespace Nexus.Scanner.Engines;

/// <summary>
/// Reads script files and reports the shapes that mean "this is trying not to be
/// read". Always available: it is text analysis with no external data.
/// </summary>
public sealed class ScriptStaticEngine : IStaticEngine
{
    public string Name => "script analysis";

    public SignalSource SignalSource => SignalSource.StaticRules;

    public bool IsAvailable => true;

    public IReadOnlyList<SecuritySignal> Analyse(ReadOnlySpan<byte> bytes, string path)
    {
        var kind = ScriptAnalyzer.KindFromExtension(path);
        if (kind == ScriptKind.Unknown)
            return [];

        return ScriptAnalyzer.Analyse(ScriptAnalyzer.DecodeText(bytes), kind);
    }
}

/// <summary>
/// Looks inside ZIP archives, because that is how most malware arrives — a scanner
/// that stops at the container reports "unknown" on the very files it most needs an
/// opinion about.
///
/// Every limit here exists because an archive is attacker-controlled and a naive
/// unpacker is a denial-of-service primitive. A 42 KB zip can expand to petabytes;
/// a nested archive can recurse forever; a zip can name an entry
/// <c>..\..\Windows\System32\x.dll</c>. So: entries are capped, uncompressed output
/// is capped, the compression ratio is capped, nothing is ever written to disk, and
/// nested archives are reported rather than opened.
/// </summary>
public sealed class ArchiveStaticEngine : IStaticEngine
{
    /// <summary>Entries examined before giving up. An archive with more than this is
    /// a bundle, not a payload.</summary>
    public const int MaxEntries = 256;

    /// <summary>Total bytes expanded across the whole archive.</summary>
    public const long MaxTotalUncompressedBytes = 64L * 1024 * 1024;

    /// <summary>Bytes read from any single entry.</summary>
    public const long MaxEntryBytes = 16L * 1024 * 1024;

    /// <summary>An entry claiming to expand more than this many times is a zip bomb.</summary>
    public const long MaxCompressionRatio = 200;

    private readonly PeStaticEngine _pe = new();
    private readonly ScriptStaticEngine _scripts = new();

    public string Name => "archive contents";

    public SignalSource SignalSource => SignalSource.StaticRules;

    public bool IsAvailable => true;

    public IReadOnlyList<SecuritySignal> Analyse(ReadOnlySpan<byte> bytes, string path)
    {
        if (!LooksLikeZip(bytes))
            return [];

        // The span cannot cross into the lambda-free streaming code below, so copy
        // once into a stream. The caller has already capped the file size.
        using var stream = new MemoryStream(bytes.ToArray(), writable: false);

        try
        {
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            return Inspect(archive);
        }
        catch (InvalidDataException)
        {
            return
            [
                new SecuritySignal(SignalSource.StaticRules, SignalWeight.Weak, "archive-corrupt",
                    "This looks like an archive but could not be opened. That happens with damaged " +
                    "downloads, and also with archives deliberately malformed to defeat scanners."),
            ];
        }
    }

    private IReadOnlyList<SecuritySignal> Inspect(ZipArchive archive)
    {
        var signals = new List<SecuritySignal>();
        long totalRead = 0;
        int examined = 0;
        var executableNames = new List<string>();

        foreach (var entry in archive.Entries)
        {
            if (examined >= MaxEntries || totalRead >= MaxTotalUncompressedBytes)
                break;

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

            if (entry.CompressedLength > 0 && entry.Length / entry.CompressedLength > MaxCompressionRatio)
            {
                signals.Add(new SecuritySignal(
                    SignalSource.StaticRules, SignalWeight.Moderate, "archive-zip-bomb",
                    $"An entry in this archive expands {entry.Length / entry.CompressedLength}× its stored " +
                    "size. That pattern is used to exhaust disk or memory."));
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

            foreach (var signal in _pe.Analyse(content, entry.FullName))
                signals.Add(Requalify(signal, entry.FullName));

            foreach (var signal in _scripts.Analyse(content, entry.FullName))
                signals.Add(Requalify(signal, entry.FullName));
        }

        if (executableNames.Count > 0)
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules, SignalWeight.Informational, "archive-contains-executable",
                $"This archive contains {executableNames.Count} program file(s): " +
                string.Join(", ", executableNames.Take(5))));
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

    private static bool LooksLikeZip(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= 4
        && bytes[0] == 0x50 && bytes[1] == 0x4B
        && (bytes[2] == 0x03 || bytes[2] == 0x05 || bytes[2] == 0x07);

    private static bool HasTraversalPath(string entryName)
    {
        var normalized = entryName.Replace('\\', '/');

        return normalized.StartsWith('/')
               || normalized.Contains("../", StringComparison.Ordinal)
               || (normalized.Length >= 2 && normalized[1] == ':');
    }

    private static bool IsNestedArchive(string entryName)
    {
        var extension = Path.GetExtension(entryName).ToLowerInvariant();
        return extension is ".zip" or ".7z" or ".rar" or ".gz" or ".tar" or ".cab" or ".iso";
    }

    private static bool IsExecutableName(string entryName)
    {
        var extension = Path.GetExtension(entryName).ToLowerInvariant();
        return extension is ".exe" or ".dll" or ".scr" or ".com" or ".pif" or ".bat" or ".cmd"
            or ".js" or ".vbs" or ".ps1" or ".hta" or ".lnk" or ".msi";
    }
}
