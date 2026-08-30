using System.Collections.Concurrent;
using System.IO;
using Nexus.Core.Logging;

namespace Nexus.App.Services.Security;

/// <summary>
/// Watches the Downloads folder and scans new programs as they land.
///
/// This is where the advisory model is at its most useful. Catching something at
/// the moment it arrives — before it is double-clicked — costs the user nothing and
/// is the one point where a warning genuinely changes what happens next. A scan the
/// user has to remember to run is a scan that happens after the fact.
///
/// Two details make the difference between this working and it being useless:
///
/// - <b>Browsers download to a temporary name</b> (<c>.crdownload</c>,
///   <c>.part</c>, <c>.tmp</c>) and rename on completion. Watching only for created
///   files would scan a zero-byte placeholder and conclude nothing; the rename is
///   the event that matters.
/// - <b>A file is not readable the instant it appears.</b> The writer still holds
///   it, so the scan is delayed and retried rather than run immediately and failed.
/// </summary>
public sealed class DownloadWatcherService : IDisposable
{
    /// <summary>How long to wait before the first attempt, letting the writer finish
    /// and the antivirus that actually blocks things have its turn first.</summary>
    private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(2);

    /// <summary>Attempts before giving up on a file that stays locked.</summary>
    private const int MaxAttempts = 5;

    private static readonly TimeSpan RetryDelay = TimeSpan.FromSeconds(3);

    /// <summary>Extensions worth scanning on arrival.</summary>
    private static readonly HashSet<string> InterestingExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".msi", ".msp", ".scr", ".com", ".pif", ".cpl",
        ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
        ".jar", ".lnk", ".zip", ".iso", ".img",
    };

    /// <summary>Partial-download names to ignore; the rename that follows is the
    /// event worth acting on.</summary>
    private static readonly HashSet<string> PartialExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload",
    };

    /// <summary>How often to re-check whether the game has finished.</summary>
    private static readonly TimeSpan GameModePoll = TimeSpan.FromSeconds(30);

    private readonly ActivityLog _log;
    private readonly Func<string, CancellationToken, Task> _scan;
    private readonly Func<bool> _isGameModeActive;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly ConcurrentDictionary<string, byte> _inFlight = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource _shutdown = new();

    private bool _running;

    public DownloadWatcherService(
        ActivityLog log, Func<string, CancellationToken, Task> scan, Func<bool> isGameModeActive)
    {
        _log = log;
        _scan = scan;
        _isGameModeActive = isGameModeActive;
    }

    public bool IsRunning => _running;

    public static IReadOnlyList<string> DefaultFolders()
    {
        var folders = new List<string>();

        // There is no SpecialFolder for Downloads, so derive it from the profile.
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (profile.Length > 0)
        {
            var downloads = Path.Combine(profile, "Downloads");
            if (Directory.Exists(downloads))
                folders.Add(downloads);
        }

        return folders;
    }

    public void Start()
    {
        if (_running)
            return;

        // A cancelled token source stays cancelled, so a stopped watcher needs a fresh
        // one or every queued scan would abort the moment it resumed.
        if (_shutdown.IsCancellationRequested)
        {
            _shutdown.Dispose();
            _shutdown = new CancellationTokenSource();
        }

        foreach (var folder in DefaultFolders())
        {
            try
            {
                var watcher = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size,
                    InternalBufferSize = 32 * 1024,
                };

                watcher.Created += (_, e) => Consider(e.FullPath);
                watcher.Renamed += (_, e) => Consider(e.FullPath);

                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
            {
                _log.Warn("Sentinel", $"Could not watch {folder} for downloads: {ex.Message}");
            }
        }

        _running = _watchers.Count > 0;

        if (_running)
            _log.Info("Sentinel", "New downloads will be checked as they arrive.");
    }

    private void Consider(string path)
    {
        var extension = Path.GetExtension(path);

        if (PartialExtensions.Contains(extension))
            return; // the rename on completion is the event worth acting on

        if (!InterestingExtensions.Contains(extension))
            return;

        // A single download raises several events; only queue the file once.
        if (!_inFlight.TryAdd(path, 0))
            return;

        _ = ScanWhenReadyAsync(path);
    }

    private async Task ScanWhenReadyAsync(string path)
    {
        try
        {
            await Task.Delay(InitialDelay, _shutdown.Token).ConfigureAwait(false);

            for (int attempt = 0; attempt < MaxAttempts; attempt++)
            {
                _shutdown.Token.ThrowIfCancellationRequested();

                if (!File.Exists(path))
                    return; // moved or cancelled before it settled

                if (IsReadable(path))
                {
                    // Deferred, not skipped. Reading a fresh download means spawning
                    // the worker and pulling the file off disk, which is exactly the
                    // competition Nexus's other half exists to prevent — and someone
                    // downloading a game update while playing is not a rare case. The
                    // check is not time-critical to the second, so it waits.
                    await WaitWhileGamingAsync(path).ConfigureAwait(false);

                    await _scan(path, _shutdown.Token).ConfigureAwait(false);
                    return;
                }

                await Task.Delay(RetryDelay, _shutdown.Token).ConfigureAwait(false);
            }

            _log.Info("Sentinel",
                $"{Path.GetFileName(path)} was still being written after several tries, so it was not " +
                "checked on arrival. You can scan it from the Security tab.");
        }
        catch (OperationCanceledException)
        {
            // Shutting down.
        }
        catch (Exception ex)
        {
            _log.Warn("Sentinel", $"Could not check {Path.GetFileName(path)} on arrival: {ex.Message}");
        }
        finally
        {
            _inFlight.TryRemove(path, out _);
        }
    }

    /// <summary>
    /// Block until no game is running.
    ///
    /// Unbounded on purpose: a session can last hours, and giving up would mean
    /// silently not checking the file. If Nexus shuts down first the scan is lost,
    /// which is acceptable because the scheduled check covers the Downloads folder
    /// anyway — so the file is examined either way, just later.
    /// </summary>
    private async Task WaitWhileGamingAsync(string path)
    {
        if (!_isGameModeActive())
            return;

        _log.Info("Sentinel",
            $"Holding the check on {Path.GetFileName(path)} until you have finished playing.");

        while (_isGameModeActive())
            await Task.Delay(GameModePoll, _shutdown.Token).ConfigureAwait(false);
    }

    /// <summary>True once the writer has let go of the file.</summary>
    private static bool IsReadable(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return stream.Length > 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Stop watching; a later Start() renews the cancellation source.</summary>
    public void Stop() => Dispose();

    public void Dispose()
    {
        _running = false;

        try
        {
            _shutdown.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Already disposed.
        }

        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
            }
            catch (Exception ex) when (ex is ObjectDisposedException or IOException)
            {
                // Already gone.
            }

            watcher.Dispose();
        }

        _watchers.Clear();

        // Deliberately not disposed here: Stop() routes through Dispose(), and a
        // restart needs the field to still be usable long enough to be replaced.
    }
}
