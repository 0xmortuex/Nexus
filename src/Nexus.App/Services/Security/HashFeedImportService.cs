using System.IO;
using System.IO.Compression;
using System.Net.Http;
using Nexus.Core.Logging;
using Nexus.Core.Persistence;
using Nexus.Core.Security;

namespace Nexus.App.Services.Security;

/// <summary>Outcome of importing a hash feed.</summary>
public sealed record HashFeedResult(bool Succeeded, int HashCount, string Message);

/// <summary>
/// Imports a known-bad hash list, from a file on disk or a URL the user gives.
///
/// This is the only outbound network request anywhere in Sentinel, and the
/// distinction matters enough to be explicit: it downloads a <b>public list of
/// malware hashes</b>. It does not send anything about the user's files anywhere.
/// That is precisely the line the rest of the module refuses to cross — reputation
/// is local, and the online per-file lookup interface still has no implementation
/// wired in — and downloading a published list is on the safe side of it. It also
/// only ever happens when someone presses the button.
///
/// The URL is supplied rather than hard-coded. Pinning one vendor's endpoint into
/// the binary means a silent, unfixable break the day they restructure it or start
/// requiring a key, and it forecloses using any other feed. abuse.ch's MalwareBazaar
/// export is the documented default because it is open, needs no key, is CC0, and
/// its format is already exactly what Sentinel reads.
/// </summary>
public sealed class HashFeedImportService
{
    /// <summary>abuse.ch MalwareBazaar, recent samples. Open, no key, CC0.</summary>
    public const string DefaultFeedUrl = "https://bazaar.abuse.ch/export/txt/sha256/recent/";

    /// <summary>The full historical export, as a ZIP. Much larger.</summary>
    public const string FullFeedUrl = "https://bazaar.abuse.ch/export/txt/sha256/full/";

    /// <summary>A wrong or hostile URL must not be able to fill the disk.</summary>
    public const long MaxDownloadBytes = 256L * 1024 * 1024;

    public static readonly TimeSpan Timeout = TimeSpan.FromMinutes(5);

    private readonly ActivityLog _log;
    private readonly NexusPaths _paths;

    public HashFeedImportService(ActivityLog log, NexusPaths paths)
    {
        _log = log;
        _paths = paths;
    }

    public bool FeedImported => File.Exists(_paths.ImportedKnownBadFile);

    /// <summary>
    /// Import from a local path or an http(s) URL. Everything is validated before the
    /// existing list is replaced, so a truncated download or a page of HTML cannot
    /// quietly wipe a working feed.
    /// </summary>
    public async Task<HashFeedResult> ImportAsync(string source, CancellationToken cancellationToken = default)
    {
        source = source.Trim();
        if (source.Length == 0)
            return new HashFeedResult(false, 0, "Give a file path or an http(s) address to import from.");

        try
        {
            var lines = Uri.TryCreate(source, UriKind.Absolute, out var uri)
                        && uri.Scheme is "http" or "https"
                ? await DownloadAsync(uri, cancellationToken).ConfigureAwait(false)
                : ReadLocal(source);

            var hashes = HashListFile.Parse(lines);

            // A feed that yields nothing is a wrong URL, an error page, or a changed
            // format — never a legitimately empty malware list. Refuse rather than
            // replacing a working list with nothing.
            if (hashes.Count == 0)
            {
                return new HashFeedResult(false, 0,
                    "Nothing in that source looked like a SHA-256 hash list, so the existing list was " +
                    "left alone. Check the address, or download the file yourself and import it.");
            }

            Save(hashes, source);

            return new HashFeedResult(true, hashes.Count,
                $"Imported {hashes.Count:N0} known-bad hashes. They take effect the next time Nexus starts.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or UnauthorizedAccessException
                                       or InvalidDataException or UriFormatException)
        {
            _log.Warn("Sentinel", $"Could not import a hash feed from {source}: {ex.Message}");
            return new HashFeedResult(false, 0, $"Could not import that: {ex.Message}");
        }
    }

    private async Task<IEnumerable<string>> DownloadAsync(Uri uri, CancellationToken cancellationToken)
    {
        _log.Info("Sentinel",
            $"Downloading a public malware hash list from {uri.Host}. Nothing about your files is sent.");

        using var client = new HttpClient { Timeout = Timeout };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Nexus-Sentinel/1.0");

        using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        if (response.Content.Headers.ContentLength is { } declared && declared > MaxDownloadBytes)
            throw new IOException($"the feed is {declared / (1024 * 1024)} MB, which is larger than Nexus will download");

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);

        // Buffer with a hard cap, because a server can lie about (or omit) its length.
        using var buffer = new MemoryStream();
        await CopyCappedAsync(stream, buffer, MaxDownloadBytes, cancellationToken).ConfigureAwait(false);
        buffer.Position = 0;

        return LooksLikeZip(buffer) ? ReadZip(buffer) : ReadText(buffer);
    }

    private static async Task CopyCappedAsync(
        Stream source, Stream destination, long cap, CancellationToken cancellationToken)
    {
        var chunk = new byte[81920];
        long total = 0;

        while (true)
        {
            int read = await source.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
            if (read == 0)
                return;

            total += read;
            if (total > cap)
                throw new IOException("the feed is larger than Nexus will download");

            await destination.WriteAsync(chunk.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }
    }

    private static IEnumerable<string> ReadLocal(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"there is no file at {path}");

        if (new FileInfo(path).Length > MaxDownloadBytes)
            throw new IOException("that file is larger than Nexus will read");

        using var stream = File.OpenRead(path);
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        buffer.Position = 0;

        return LooksLikeZip(buffer) ? ReadZip(buffer) : ReadText(buffer);
    }

    private static bool LooksLikeZip(MemoryStream stream)
    {
        if (stream.Length < 4)
            return false;

        var bytes = stream.GetBuffer();
        bool isZip = bytes[0] == 0x50 && bytes[1] == 0x4B;
        stream.Position = 0;
        return isZip;
    }

    /// <summary>The full MalwareBazaar export is a ZIP holding one text file.</summary>
    private static List<string> ReadZip(MemoryStream stream)
    {
        var lines = new List<string>();

        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);

        foreach (var entry in archive.Entries)
        {
            using var entryStream = entry.Open();
            using var reader = new StreamReader(entryStream);

            while (reader.ReadLine() is { } line)
                lines.Add(line);
        }

        return lines;
    }

    private static List<string> ReadText(MemoryStream stream)
    {
        var lines = new List<string>();

        stream.Position = 0;
        using var reader = new StreamReader(stream, leaveOpen: true);

        while (reader.ReadLine() is { } line)
            lines.Add(line);

        return lines;
    }

    private void Save(IReadOnlySet<string> hashes, string source)
    {
        Directory.CreateDirectory(_paths.SecurityDirectory);

        // Streamed: the full MalwareBazaar export is over a million hashes, and
        // building that as one string before writing it is a pointless ~74 MB spike.
        using (var writer = new StreamWriter(_paths.ImportedKnownBadFile, append: false))
        {
            HashListFile.WriteTo(
                writer, hashes, $"Known-bad hashes imported from {source}", DateTimeOffset.Now);
        }

        _log.Info("Sentinel", $"Imported {hashes.Count:N0} known-bad hashes from {source}.");
    }
}
