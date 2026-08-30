using System.IO;
using Nexus.Core;
using Nexus.Core.Logging;
using Nexus.Core.Persistence;

namespace Nexus.App.Services.Security;

/// <summary>
/// Runs a periodic quick scan of the places new files actually arrive.
///
/// Deliberately not a "full system scan". Walking every file on a terabyte drive
/// takes hours, hammers the disk, and finds nothing that a scan of Downloads, the
/// temp folders and the startup locations would have missed — because those are
/// where things land. A slow full scan that people cancel is worse than a fast
/// targeted one they let finish.
///
/// Two rules keep it from being a nuisance, which is the only way a background
/// scanner survives on a gaming machine:
/// - It never runs while Game Mode is active. Nexus's other half exists to keep
///   frame times smooth; a security scan that causes stutter would be the same
///   product working against itself.
/// - It is silent unless it finds something. The scan itself is not news.
/// </summary>
public sealed class ScheduledScanService : IDisposable
{
    /// <summary>Delay before the first scan, so startup is never competing with it.</summary>
    public static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(5);

    /// <summary>How often to look again.</summary>
    public static readonly TimeSpan Interval = TimeSpan.FromHours(6);

    /// <summary>Retry interval when a scan is postponed because a game is running.</summary>
    public static readonly TimeSpan PostponedRetry = TimeSpan.FromMinutes(20);

    private readonly ActivityLog _log;
    private readonly SentinelService _sentinel;
    private readonly SettingsService _settings;
    private readonly Func<bool> _isGameModeActive;

    private System.Threading.Timer? _timer;

    // The timer and the "Quick check" button can both try to start a scan. A plain
    // null check in front of an assignment lets both through — press the button as
    // the timer fires and you get two concurrent scans, an orphaned cancellation
    // source, and whichever finishes first clearing the flag for both.
    private readonly SingleFlightGate _gate = new();
    private CancellationTokenSource? _running;
    private bool _disposed;

    public ScheduledScanService(
        ActivityLog log,
        SentinelService sentinel,
        SettingsService settings,
        Func<bool> isGameModeActive)
    {
        _log = log;
        _sentinel = sentinel;
        _settings = settings;
        _isGameModeActive = isGameModeActive;
    }

    public DateTimeOffset? LastScanAt { get; private set; }

    /// <summary>The places worth checking regularly: where downloads, droppers and
    /// startup entries actually live.</summary>
    public static IReadOnlyList<string> QuickScanFolders()
    {
        var folders = new List<string>();

        void Add(string? path)
        {
            if (path is { Length: > 0 } && Directory.Exists(path))
                folders.Add(path);
        }

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (profile.Length > 0)
            Add(Path.Combine(profile, "Downloads"));

        Add(Path.GetTempPath());
        Add(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
        Add(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
        Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));

        return folders.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public void Start()
    {
        if (!_settings.Current.Security.ScheduledQuickScan)
            return;

        _timer = new System.Threading.Timer(_ => Tick(), null, StartupDelay, Interval);
        _log.Info("Sentinel",
            $"A quick check of your download and startup folders will run every {Interval.TotalHours:F0} hours.");
    }

    private void Tick()
    {
        // This runs on a timer thread, where an escaping exception ends the process.
        // The callback itself asks another service whether a game is running, so the
        // failure would not even be this class's own.
        try
        {
            if (_disposed)
                return;

            // Never compete with a game. Nexus's whole optimizer half exists to
            // protect frame times; a scan that causes stutter is the product
            // undermining itself.
            if (_isGameModeActive())
            {
                _timer?.Change(PostponedRetry, Interval);
                return;
            }

            _ = RunAsync();
        }
        catch (Exception ex)
        {
            _log.Warn("Sentinel", $"Skipped a scheduled check: {ex.Message}");
        }
    }

    private async Task RunAsync()
    {
        // A previous scan is still going; skip rather than stacking them up.
        if (!_gate.TryEnter())
            return;

        var cancellation = new CancellationTokenSource();
        _running = cancellation;

        int scanned = 0;
        int notable = 0;

        try
        {
            foreach (var folder in QuickScanFolders())
            {
                await foreach (var verdict in _sentinel
                    .ScanFolderAsync(folder, recursive: true, cancellation.Token)
                    .ConfigureAwait(false))
                {
                    scanned++;
                    if (verdict.WarrantsAlert)
                        notable++;

                    // Yield regularly so a background scan never monopolises the disk.
                    if (scanned % 50 == 0)
                        await Task.Delay(50, cancellation.Token).ConfigureAwait(false);

                    // Abandon the scan the moment a game starts.
                    if (_isGameModeActive())
                    {
                        _log.Info("Sentinel", "Paused the background check because a game started.");
                        return;
                    }
                }
            }

            LastScanAt = DateTimeOffset.Now;

            // Silence on a clean scan is deliberate: "I looked and found nothing" is
            // not news, and logging it every six hours buries the entries that matter.
            if (notable > 0)
            {
                _log.Warn("Sentinel",
                    $"The scheduled check looked at {scanned} files and found {notable} worth a look. " +
                    "Nothing was changed — see the Security tab.");
            }
        }
        catch (OperationCanceledException)
        {
            // Shutting down or postponed.
        }
        catch (Exception ex)
        {
            _log.Warn("Sentinel", $"The scheduled check stopped early: {ex.Message}");
        }
        finally
        {
            _running = null;
            cancellation.Dispose();
            _gate.Exit();
        }
    }

    /// <summary>
    /// Run a quick scan now, for the button in the Security tab. Does nothing if the
    /// scheduled scan is already running — the gate inside RunAsync decides, so the
    /// button and the timer cannot both get in.
    /// </summary>
    public Task RunNowAsync() => RunAsync();

    public void Dispose()
    {
        _disposed = true;

        try
        {
            _running?.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Already finished.
        }

        _timer?.Dispose();
        _timer = null;
    }
}
