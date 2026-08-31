using System.IO;
using System.Security.Cryptography;
using Nexus.Core.Logging;
using Nexus.Core.Security;

namespace Nexus.App.Services.Security;

/// <summary>
/// Turns a path into a <see cref="ScanTarget"/> with a content hash.
///
/// Hashing is the one thing Sentinel does to every file it looks at, so it is also
/// the one thing that must never stall the machine: reads are sequential-scan hinted,
/// oversized files are skipped rather than streamed for minutes, and a locked file
/// produces a hashless target instead of an exception.
/// </summary>
public sealed class FileIdentityService
{
    /// <summary>Files above this size are identified by path alone. A 4 GB game
    /// archive is not what Sentinel is looking for, and hashing it would cost
    /// minutes of disk bandwidth during a background scan.</summary>
    public const long MaxHashableBytes = 512L * 1024 * 1024;

    private const int BufferSize = 1024 * 1024;

    private readonly ActivityLog _log;

    public FileIdentityService(ActivityLog log)
    {
        _log = log;
    }

    /// <param name="withHash">
    /// False to skip the SHA-256 entirely.
    ///
    /// Hashing means reading the whole file, and on a real cross-section of a disk
    /// that is 18ms of the 43ms a file costs — the single largest avoidable expense in
    /// a scan. It is worth paying only when something will actually look the hash up:
    /// a reputation list, or files the user has vouched for. With neither present,
    /// every byte read was being thrown away.
    /// </param>
    public ScanTarget Identify(
        string path, CancellationToken cancellationToken = default, bool withHash = true)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
                return ScanTarget.ForFile(path);

            if (!withHash || info.Length > MaxHashableBytes)
                return ScanTarget.ForFile(path, sha256: null, sizeBytes: info.Length);

            var hash = ComputeSha256(path, cancellationToken);
            return ScanTarget.ForFile(path, hash, info.Length);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // A file held open by another process is ordinary, not an error worth
            // shouting about; the caller gets a hashless target and carries on.
            return ScanTarget.ForFile(path);
        }
    }

    public string? ComputeSha256(string path, CancellationToken cancellationToken = default)
    {
        try
        {
            using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                BufferSize, FileOptions.SequentialScan);

            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(stream);
            cancellationToken.ThrowIfCancellationRequested();

            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
        catch (Exception ex)
        {
            _log.Warn("Sentinel", $"Could not hash {Path.GetFileName(path)}: {ex.Message}");
            return null;
        }
    }
}
