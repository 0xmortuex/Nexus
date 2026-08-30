using System.IO;
using Nexus.Core.Logging;

namespace Nexus.App.Services.Security;

/// <summary>
/// Notices a USB drive being plugged in and looks at what is on it.
///
/// This is the other moment, alongside a download landing, where a warning arrives
/// early enough to matter: a stick is plugged in, and something on it is about to be
/// double-clicked. Scanning it afterwards is a report; scanning it now is a warning.
///
/// It polls rather than subscribing to WM_DEVICECHANGE. That message needs a window
/// handle, and Nexus is a tray application that may be running with no window shown
/// at all — a watcher that silently stops working when the window is closed is worse
/// than one that costs a directory listing every few seconds.
///
/// Nothing here blocks the drive or opens anything. The drive stays fully usable
/// while the scan runs, exactly as it would if Nexus were not installed.
/// </summary>
public sealed class RemovableDriveWatcherService : IDisposable
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(3);

    /// <summary>
    /// Give Windows a moment to finish mounting. A drive can report itself ready
    /// before its root directory is actually listable, and enumerating it too early
    /// returns nothing at all — which would look like a clean scan.
    /// </summary>
    private static readonly TimeSpan MountSettleDelay = TimeSpan.FromSeconds(2);

    /// <summary>
    /// A ceiling on one drive, so an external disk someone plugs in cannot turn into
    /// an unbounded scan the user did not ask for. Reaching it is reported rather
    /// than hidden, because a scan that quietly stopped early is a scan that lies.
    /// </summary>
    private const int MaxFilesPerDrive = 20_000;

    private readonly ActivityLog _log;
    private readonly Func<string, int, CancellationToken, Task<int>> _scanDrive;
    private readonly HashSet<string> _known = new(StringComparer.OrdinalIgnoreCase);

    private CancellationTokenSource _shutdown = new();
    private Task? _loop;
    private bool _running;

    /// <param name="scanDrive">Scans a drive root, up to a file limit, and returns how
    /// many findings were worth reporting.</param>
    public RemovableDriveWatcherService(
        ActivityLog log,
        Func<string, int, CancellationToken, Task<int>> scanDrive)
    {
        _log = log;
        _scanDrive = scanDrive;
    }

    public bool IsRunning => _running;

    public void Start()
    {
        if (_running)
            return;

        _shutdown = new CancellationTokenSource();

        // Everything already plugged in at startup counts as known. Scanning the
        // stick that has been in the machine for a week, every time Nexus starts, is
        // noise — the point is to catch the moment something new arrives.
        foreach (var root in RemovableRoots())
            _known.Add(root);

        _running = true;
        _loop = Task.Run(() => WatchAsync(_shutdown.Token));

        _log.Info("Sentinel", "Watching for USB drives being plugged in.");
    }

    public void Stop() => Dispose();

    private async Task WatchAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(PollInterval, cancellationToken).ConfigureAwait(false);

                var current = RemovableRoots();

                // Forget drives that have been removed, so re-inserting one scans again.
                _known.RemoveWhere(root => !current.Contains(root));

                foreach (var root in current)
                {
                    if (!_known.Add(root))
                        continue;

                    await ScanNewDriveAsync(root, cancellationToken).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                // A background loop that throws is a background loop that stops. Any
                // failure here costs one poll, never the watcher.
                _log.Warn("Sentinel", $"USB watch hit a problem and carried on: {ex.Message}");
            }
        }
    }

    private async Task ScanNewDriveAsync(string root, CancellationToken cancellationToken)
    {
        _log.Info("Sentinel", $"A drive was plugged in at {root}. Looking at what is on it — " +
                              "the drive stays usable while this runs.");

        await Task.Delay(MountSettleDelay, cancellationToken).ConfigureAwait(false);

        try
        {
            int notable = await _scanDrive(root, MaxFilesPerDrive, cancellationToken).ConfigureAwait(false);

            _log.Info("Sentinel", notable == 0
                ? $"Nothing on {root} looked worth flagging."
                : $"{notable} thing(s) on {root} are worth a look. Nothing was changed.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.Warn("Sentinel", $"Could not finish looking at {root}: {ex.Message}");
        }
    }

    /// <summary>Removable drive roots that are actually ready to read.</summary>
    private static HashSet<string> RemovableRoots()
    {
        var roots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        DriveInfo[] drives;
        try
        {
            drives = DriveInfo.GetDrives();
        }
        catch (IOException)
        {
            return roots;
        }

        foreach (var drive in drives)
        {
            try
            {
                if (drive.DriveType == DriveType.Removable && drive.IsReady)
                    roots.Add(drive.RootDirectory.FullName);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A card reader with nothing in it, or a drive pulled mid-question.
            }
        }

        return roots;
    }

    public void Dispose()
    {
        if (!_running)
            return;

        _running = false;

        try
        {
            _shutdown.Cancel();
            _loop?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception ex) when (ex is AggregateException or OperationCanceledException or ObjectDisposedException)
        {
            // Shutting down; a watcher that throws on the way out helps nobody.
        }
        finally
        {
            _shutdown.Dispose();
            _loop = null;
            _known.Clear();
        }

        _log.Info("Sentinel", "Stopped watching for USB drives.");
    }
}
