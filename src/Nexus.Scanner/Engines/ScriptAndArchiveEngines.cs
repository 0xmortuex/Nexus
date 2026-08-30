using SharpCompress.Archives;
using SharpCompress.Readers;
using SharpCompress.Common;
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
/// The limits, the traversal check and the entry walk all live in
/// <see cref="ArchiveInspector"/> in Core, where they are unit-tested: they are
/// security controls against an attacker-controlled file, and an untested limit is
/// a limit nobody has checked. This class only supplies the engines that look at
/// each entry's contents.
/// </summary>
public sealed class ArchiveStaticEngine : IStaticEngine
{
    private readonly PeStaticEngine _pe = new();
    private readonly ScriptStaticEngine _scripts = new();

    public string Name => "archive contents";

    public SignalSource SignalSource => SignalSource.StaticRules;

    public bool IsAvailable => true;

    public IReadOnlyList<SecuritySignal> Analyse(ReadOnlySpan<byte> bytes, string path)
    {
        var format = ArchiveInspector.DetectFormat(bytes);

        if (format == ArchiveInspector.ArchiveFormat.None)
            return [];

        using var stream = new MemoryStream(bytes.ToArray(), writable: false);

        // ZIP keeps the framework's own reader. It is the format that arrives most
        // often, the existing path is well covered by tests, and routing it through a
        // third-party parser would gain nothing.
        if (format == ArchiveInspector.ArchiveFormat.Zip)
            return ArchiveInspector.Inspect(stream, AnalyseEntry);

        return InspectWithSharpCompress(stream, format);
    }

    /// <summary>
    /// 7z, RAR, tar and the single-file compressors.
    ///
    /// Malware moved into these formats for one reason: scanners that only understood
    /// ZIP reported "unknown" and got out of the way.
    ///
    /// Two reading strategies, because no single one covers everything. 7z and RAR
    /// need random access to their central directory. A .tar.gz is a compressed
    /// stream wrapping another archive, which the random-access API refuses outright
    /// ("cannot determine compressed stream type"), so those go through the
    /// forward-only reader instead. Whichever succeeds, the entries end up in the
    /// same <see cref="ArchiveInspector.InspectEntries"/> as ZIP, so the entry cap,
    /// expansion cap, traversal check and zip-bomb ratio apply identically. The limits
    /// are not reimplemented per format; that is how one copy ends up missing a check.
    ///
    /// This runs in the scanner worker, which is the point of the worker: a parser bug
    /// in a third-party archive library becomes a crashed helper process rather than a
    /// compromised elevated one.
    /// </summary>
    private IReadOnlyList<SecuritySignal> InspectWithSharpCompress(
        MemoryStream stream, ArchiveInspector.ArchiveFormat format)
    {
        try
        {
            return InspectRandomAccess(stream);
        }
        catch (CryptographicException)
        {
            return [Encrypted(format)];
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Fall through to the streaming reader. A .tar.gz always lands here.
        }

        try
        {
            stream.Position = 0;
            return InspectStreaming(stream);
        }
        catch (CryptographicException)
        {
            return [Encrypted(format)];
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Every archive here is attacker-controlled and the reader is third-party
            // code, so the catch is deliberately broad: a malformed archive must
            // produce a finding, never an unhandled exception that takes the worker
            // down mid-scan. What it must not do is pass silently.
            return
            [
                new SecuritySignal(SignalSource.StaticRules, SignalWeight.Weak, "archive-corrupt",
                    $"This is a {Describe(format)} archive that could not be read ({ex.GetType().Name}). " +
                    "That happens with damaged downloads and with archives deliberately malformed to " +
                    "defeat scanners. Its contents were not examined."),
            ];
        }
    }

    /// <summary>7z and RAR: the whole entry list is available up front.</summary>
    private IReadOnlyList<SecuritySignal> InspectRandomAccess(Stream stream)
    {
        using var archive = ArchiveFactory.OpenArchive(stream, new ReaderOptions());

        // Enumerated eagerly on purpose: a 7z with encrypted headers opens fine and
        // throws here, which is what turns it into an "encrypted" finding rather than
        // a "corrupt" one.
        var files = archive.Entries.Where(entry => !entry.IsDirectory).ToArray();

        var entries = files.Select(entry => new ArchiveInspector.ArchiveEntryView(
            NameOf(entry.Key),
            entry.Size,
            entry.CompressedSize,
            limit => ReadEntry(entry, limit)));

        var signals = new List<SecuritySignal>(ArchiveInspector.InspectEntries(entries, AnalyseEntry));

        int encrypted = files.Count(entry => entry.IsEncrypted);
        if (encrypted > 0)
            signals.Add(EncryptedEntries(encrypted, files.Length));

        return signals;
    }

    /// <summary>
    /// tar, gzip, bzip2, xz: forward-only, one pass, no going back.
    ///
    /// The entry sequence is lazy and must stay that way. InspectEntries reads each
    /// entry before advancing to the next, which is the only order this reader
    /// permits; materialising the sequence first would read every entry against a
    /// stream that has already moved past it.
    /// </summary>
    private IReadOnlyList<SecuritySignal> InspectStreaming(Stream stream)
    {
        using var reader = ReaderFactory.OpenReader(stream, new ReaderOptions());

        int encrypted = 0;
        int total = 0;

        var signals = new List<SecuritySignal>(
            ArchiveInspector.InspectEntries(StreamEntries(reader, () => total++, () => encrypted++), AnalyseEntry));

        if (encrypted > 0)
            signals.Add(EncryptedEntries(encrypted, total));

        return signals;
    }

    private static IEnumerable<ArchiveInspector.ArchiveEntryView> StreamEntries(
        IReader reader, Action countFile, Action countEncrypted)
    {
        while (reader.MoveToNextEntry())
        {
            var entry = reader.Entry;

            if (entry.IsDirectory)
                continue;

            countFile();

            if (entry.IsEncrypted)
                countEncrypted();

            yield return new ArchiveInspector.ArchiveEntryView(
                NameOf(entry.Key),
                entry.Size,
                entry.CompressedSize,
                limit => ReadStreamedEntry(reader, limit));
        }
    }

    /// <summary>
    /// A password-protected archive is not a corrupt one, and the difference matters.
    /// Encrypting an attachment so the scanner cannot read it, and putting the
    /// password in the message beside it, is the oldest working delivery method there
    /// is. Nexus cannot open it, and that must not read as a clean result.
    /// </summary>
    private static SecuritySignal Encrypted(ArchiveInspector.ArchiveFormat format) =>
        new(SignalSource.StaticRules, SignalWeight.Moderate, "archive-encrypted",
            $"This {Describe(format)} archive is password-protected, including its list of contents, " +
            "so Nexus could not see what is inside it. Nothing here has been cleared — it has not " +
            "been looked at. Sending a protected archive together with its password is a common way " +
            "to get something past a scanner, and also how plenty of people legitimately send documents.");

    private static SecuritySignal EncryptedEntries(int encrypted, int total) =>
        new(SignalSource.StaticRules, SignalWeight.Moderate, "archive-encrypted",
            $"{encrypted} of the {total} file(s) in this archive are password-protected, so Nexus " +
            "could not read them. They have not been cleared — they have not been looked at.");

    private static string Describe(ArchiveInspector.ArchiveFormat format) => format switch
    {
        ArchiveInspector.ArchiveFormat.SevenZip => "7-Zip",
        ArchiveInspector.ArchiveFormat.Rar => "RAR",
        ArchiveInspector.ArchiveFormat.Tar => "tar",
        ArchiveInspector.ArchiveFormat.GZip => "gzip",
        ArchiveInspector.ArchiveFormat.BZip2 => "bzip2",
        ArchiveInspector.ArchiveFormat.Xz => "xz",
        _ => "compressed",
    };

    private static string NameOf(string? key) =>
        key is { Length: > 0 } name ? name : "(unnamed entry)";

    private static byte[] ReadEntry(IArchiveEntry entry, long limit)
    {
        try
        {
            using var entryStream = entry.OpenEntryStream();
            return ReadUpTo(entryStream, entry.Size, limit);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // An entry that will not decompress is skipped; one bad entry must not
            // lose the findings from the rest.
            return [];
        }
    }

    private static byte[] ReadStreamedEntry(IReader reader, long limit)
    {
        try
        {
            using var entryStream = reader.OpenEntryStream();
            return ReadUpTo(entryStream, reader.Entry.Size, limit);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return [];
        }
    }

    /// <summary>
    /// Read at most <paramref name="limit"/> bytes.
    ///
    /// The declared size is not trusted as an allocation instruction: it comes out of
    /// the archive header, which the attacker wrote. It only ever narrows the limit,
    /// never widens it.
    /// </summary>
    private static byte[] ReadUpTo(Stream stream, long declaredSize, long limit)
    {
        int size = (int)Math.Min(declaredSize > 0 ? declaredSize : limit, limit);
        if (size <= 0)
            return [];

        var buffer = new byte[size];
        int read = stream.ReadAtLeast(buffer, size, throwOnEndOfStream: false);

        if (read < size)
            Array.Resize(ref buffer, read);

        return buffer;
    }

    private IReadOnlyList<SecuritySignal> AnalyseEntry(byte[] content, string entryName)
    {
        var signals = new List<SecuritySignal>();
        signals.AddRange(_pe.Analyse(content, entryName));
        signals.AddRange(_scripts.Analyse(content, entryName));
        return signals;
    }
}
