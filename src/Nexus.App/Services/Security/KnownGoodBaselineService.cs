using System.IO;
using Nexus.App.Interop.Security;
using Nexus.Core.Logging;
using Nexus.Core.Persistence;
using Nexus.Core.Security;

namespace Nexus.App.Services.Security;

/// <summary>How a baseline build went.</summary>
public sealed record BaselineResult(int HashCount, int Examined, string Message);

/// <summary>
/// Builds a known-good hash list from this machine's own validly-signed binaries.
///
/// Sentinel needs a known-good set to be able to say "clean" at all — without one,
/// reputation never counts as an engine consulted, and every file on the machine
/// comes back "unknown" no matter how ordinary it is. The obvious source is NIST's
/// NSRL, and it is impractical: the full set is tens of gigabytes, far too much to
/// ship with a 63 MB application.
///
/// Building it locally is better on every axis that matters here. It costs nothing
/// to distribute, carries no licensing question, is a couple of megabytes, and is
/// tailored to this machine's actual patch level rather than to whatever a reference
/// set was built from.
///
/// The safety of doing this rests on one rule, and it is not negotiable: a file is
/// only recorded if its Authenticode signature is <b>valid</b> and chains to a root
/// this machine already trusts. That is what stops a compromised machine baking its
/// own malware into its allowlist — an attacker who could satisfy that check could
/// already sign code Windows accepts, at which point the baseline is not the weak
/// link.
/// </summary>
public sealed class KnownGoodBaselineService
{
    /// <summary>Files bigger than this are skipped: hashing a multi-gigabyte payload
    /// to record that it is signed is not worth the disk bandwidth.</summary>
    private const long MaxFileBytes = 128L * 1024 * 1024;

    private readonly ActivityLog _log;
    private readonly NexusPaths _paths;
    private readonly AuthenticodeVerifier _signatures;
    private readonly FileIdentityService _identity;

    public KnownGoodBaselineService(
        ActivityLog log,
        NexusPaths paths,
        AuthenticodeVerifier signatures,
        FileIdentityService identity)
    {
        _log = log;
        _paths = paths;
        _signatures = signatures;
        _identity = identity;
    }

    /// <summary>The system directories worth taking a baseline of.</summary>
    public static IReadOnlyList<string> BaselineFolders()
    {
        Environment.SpecialFolder[] folders =
        [
            Environment.SpecialFolder.System,
            Environment.SpecialFolder.SystemX86,
            Environment.SpecialFolder.ProgramFiles,
            Environment.SpecialFolder.ProgramFilesX86,
        ];

        return folders
            .Select(Environment.GetFolderPath)
            .Where(path => path.Length > 0 && Directory.Exists(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public bool BaselineExists => File.Exists(_paths.GeneratedKnownGoodFile);

    /// <summary>
    /// Walk the system directories and record every validly-signed binary.
    ///
    /// Reports progress rather than blocking silently: this reads tens of thousands
    /// of files and a UI that appears frozen for two minutes is one people kill.
    /// </summary>
    public async Task<BaselineResult> BuildAsync(
        IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int examined = 0;

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
        };

        foreach (var folder in BaselineFolders())
        {
            cancellationToken.ThrowIfCancellationRequested();
            progress?.Report($"Reading {folder}…");

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(folder, "*", options);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _log.Info("Sentinel", $"Skipped {folder} while building the baseline: {ex.Message}");
                continue;
            }

            foreach (var file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (!IsWorthBaselining(file))
                    continue;

                examined++;

                if (examined % 500 == 0)
                {
                    progress?.Report($"Checked {examined:N0} files, recorded {hashes.Count:N0}…");

                    // Yield so this never monopolises the disk or the UI thread's
                    // dispatcher queue.
                    await Task.Delay(1, cancellationToken).ConfigureAwait(false);
                }

                // The rule the safety of this whole feature rests on.
                if (_signatures.Verify(file).State != SignatureState.Valid)
                    continue;

                var hash = _identity.ComputeSha256(file, cancellationToken);
                if (hash is { Length: > 0 })
                    hashes.Add(hash);
            }
        }

        return Save(hashes, examined);
    }

    private BaselineResult Save(IReadOnlySet<string> hashes, int examined)
    {
        try
        {
            Directory.CreateDirectory(_paths.SecurityDirectory);

            using var writer = new StreamWriter(_paths.GeneratedKnownGoodFile, append: false);
            HashListFile.WriteTo(
                writer,
                hashes,
                $"Built from this machine's validly-signed binaries in {string.Join(", ", BaselineFolders())}",
                DateTimeOffset.Now);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.Warn("Sentinel", $"Could not save the known-good baseline: {ex.Message}");
            return new BaselineResult(0, examined, $"Could not save the baseline: {ex.Message}");
        }

        _log.Info("Sentinel",
            $"Known-good baseline built: {hashes.Count:N0} validly-signed files out of {examined:N0} examined. " +
            "Nexus can now recognise these as known-good instead of reporting them as unknown.");

        return new BaselineResult(hashes.Count, examined,
            $"Recorded {hashes.Count:N0} validly-signed files out of {examined:N0} examined. " +
            "Restart Nexus, or these will be used from the next start.");
    }

    /// <summary>Only executable content: a baseline of every icon and help file would
    /// be enormous and would exonerate nothing that ever runs.</summary>
    private static bool IsWorthBaselining(string path)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();
        if (extension is not (".exe" or ".dll" or ".sys" or ".ocx" or ".cpl" or ".drv" or ".scr"))
            return false;

        try
        {
            return new FileInfo(path).Length <= MaxFileBytes;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
