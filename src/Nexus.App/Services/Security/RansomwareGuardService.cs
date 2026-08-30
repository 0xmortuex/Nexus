using System.IO;
using Nexus.Core.Logging;
using Nexus.Core.Security.Ransomware;

namespace Nexus.App.Services.Security;

/// <summary>
/// Plants canary files and watches the user's document folders for the shape of an
/// encryption run.
///
/// The canaries are the sharp part. They are hidden files with names nothing else
/// on the machine knows, sitting in the folders ransomware walks first. No
/// legitimate program opens them, because no legitimate program has any reason to
/// know they exist — so anything that rewrites one is going through your files
/// indiscriminately, and that is worth interrupting you for.
///
/// True to the rest of Sentinel, this reports. It does not suspend the process, kill
/// it, or lock the folder — it cannot do any of those reliably from user mode
/// anyway, and half-blocking an encryption run is worse than telling you about it
/// clearly. What it can do is notice within seconds instead of when you next open a
/// document.
/// </summary>
public sealed class RansomwareGuardService : IDisposable
{
    /// <summary>Deliberately ugly and deliberately first alphabetically, so an
    /// attacker enumerating a folder hits it early and a curious user can tell what
    /// it is.</summary>
    private const string CanaryPrefix = "___nexus-do-not-delete";

    private static readonly string[] CanaryExtensions = [".docx", ".xlsx", ".jpg"];

    private const string CanaryContent =
        "This file was placed by Nexus Security.\r\n\r\n" +
        "It is a tripwire. Nothing on your computer needs to read or change it, so if " +
        "something does, Nexus takes that as a sign that a program is working through " +
        "your files — which is what ransomware does.\r\n\r\n" +
        "You can delete it. Nexus will put it back, and deleting it yourself will " +
        "briefly show up as an alert.\r\n";

    private readonly ActivityLog _log;
    private readonly MassChangeDetector _detector;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly HashSet<string> _canaryPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    private System.Threading.Timer? _replantTimer;
    private bool _running;

    /// <summary>
    /// How often missing tripwires are put back.
    ///
    /// This matters more than it looks: deleting the canaries is the obvious first
    /// move for anything that knows they exist, and a tripwire that stays deleted is
    /// a tripwire that only works once. It also covers the mundane cases — a cleanup
    /// tool, a sync client, or a curious user removing a file they did not recognise.
    /// </summary>
    public static readonly TimeSpan ReplantInterval = TimeSpan.FromMinutes(15);

    /// <summary>Raised when the pattern becomes alarming.</summary>
    public event Action<RansomwareFinding>? Detected;

    public RansomwareGuardService(ActivityLog log, MassChangeDetector detector)
    {
        _log = log;
        _detector = detector;
    }

    public bool IsRunning => _running;

    public int CanaryCount
    {
        get
        {
            lock (_gate)
            {
                return _canaryPaths.Count;
            }
        }
    }

    /// <summary>The folders worth guarding: where a person's irreplaceable files are.</summary>
    public static IReadOnlyList<string> DefaultWatchFolders()
    {
        Environment.SpecialFolder[] folders =
        [
            Environment.SpecialFolder.MyDocuments,
            Environment.SpecialFolder.MyPictures,
            Environment.SpecialFolder.MyVideos,
            Environment.SpecialFolder.MyMusic,
            Environment.SpecialFolder.Desktop,
        ];

        return folders
            .Select(Environment.GetFolderPath)
            .Where(path => path.Length > 0 && Directory.Exists(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public void Start()
    {
        if (_running)
            return;

        var folders = DefaultWatchFolders();
        if (folders.Count == 0)
        {
            _log.Warn("Sentinel", "No document folders found to guard against ransomware.");
            return;
        }

        foreach (var folder in folders)
        {
            PlantCanaries(folder);
            StartWatching(folder);
        }

        _running = _watchers.Count > 0;

        if (_running)
        {
            // Put back anything that goes missing, rather than silently losing the
            // tripwire the first time something deletes it.
            _replantTimer = new System.Threading.Timer(
                _ => ReplantMissingCanaries(), null, ReplantInterval, ReplantInterval);

            _log.Info("Sentinel",
                $"Ransomware watch is on for {_watchers.Count} folder(s), with {CanaryCount} tripwire " +
                "files planted. Nexus will warn you loudly and change nothing by itself.");
        }
    }

    // ---- Canaries ----

    private void PlantCanaries(string folder)
    {
        foreach (var extension in CanaryExtensions)
        {
            var path = Path.Combine(folder, CanaryPrefix + extension);

            try
            {
                if (!File.Exists(path))
                {
                    File.WriteAllText(path, CanaryContent);
                    File.SetAttributes(path, FileAttributes.Hidden);
                }

                lock (_gate)
                {
                    _canaryPaths.Add(path);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A read-only or redirected folder is not an error worth alarming
                // about; the watch still works there, just without a tripwire.
                _log.Info("Sentinel", $"Could not place a tripwire file in {folder}: {ex.Message}");
            }
        }
    }

    /// <summary>Put back any canary that has gone missing, so the tripwire survives
    /// a cleanup tool or a curious user.</summary>
    public void ReplantMissingCanaries()
    {
        string[] paths;
        lock (_gate)
        {
            paths = _canaryPaths.ToArray();
        }

        foreach (var path in paths.Where(p => !File.Exists(p)))
        {
            try
            {
                File.WriteAllText(path, CanaryContent);
                File.SetAttributes(path, FileAttributes.Hidden);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _log.Info("Sentinel", $"Could not restore the tripwire at {path}: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Delete the tripwire files. Called by "Restore all defaults", because these are
    /// real files Nexus put in the user's own folders and leaving them behind would
    /// make that button a lie.
    /// </summary>
    public IReadOnlyList<string> RemoveCanaries()
    {
        string[] paths;
        lock (_gate)
        {
            paths = _canaryPaths.ToArray();
            _canaryPaths.Clear();
        }

        var failures = new List<string>();

        foreach (var path in paths)
        {
            try
            {
                if (File.Exists(path))
                    File.Delete(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                failures.Add($"Tripwire file: could not remove {path} — {ex.Message}");
            }
        }

        // Also sweep for tripwires left by an older run whose paths this instance
        // never learned — a previous install, or a folder that has since moved.
        foreach (var folder in DefaultWatchFolders())
        {
            try
            {
                foreach (var stale in Directory.EnumerateFiles(folder, CanaryPrefix + "*"))
                    File.Delete(stale);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                failures.Add($"Tripwire file: could not clean {folder} — {ex.Message}");
            }
        }

        _log.Info("Restore", $"Removed {paths.Length} ransomware tripwire file(s).");
        return failures;
    }

    // ---- Watching ----

    private void StartWatching(string folder)
    {
        try
        {
            var watcher = new FileSystemWatcher(folder)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,

                // The default 8 KB buffer overflows readily during exactly the burst
                // this service exists to catch, and an overflow means dropped events.
                InternalBufferSize = 64 * 1024,
            };

            watcher.Changed += (_, e) => Handle(e.FullPath, FileChangeKind.Modified);
            watcher.Created += (_, e) => Handle(e.FullPath, FileChangeKind.Created);
            watcher.Deleted += (_, e) => Handle(e.FullPath, FileChangeKind.Deleted);
            watcher.Renamed += (_, e) => Handle(e.FullPath, FileChangeKind.Renamed, e.OldFullPath);
            watcher.Error += (_, e) => OnWatcherError(folder, e.GetException());

            watcher.EnableRaisingEvents = true;
            _watchers.Add(watcher);
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
        {
            _log.Warn("Sentinel", $"Could not watch {folder}: {ex.Message}");
        }
    }

    private void Handle(string path, FileChangeKind kind, string? oldPath = null)
    {
        try
        {
            bool isCanary = IsCanary(path) || (oldPath is not null && IsCanary(oldPath));

            var finding = _detector.Observe(new FileChangeEvent
            {
                Path = path,
                Kind = kind,
                At = DateTimeOffset.Now,
                OldPath = oldPath,
                IsCanary = isCanary,
            });

            if (finding is not null)
                Report(finding);
        }
        catch (Exception ex)
        {
            // This runs on the watcher's thread; letting anything escape would take
            // the watcher down and silently end the protection.
            _log.Error("Sentinel", $"Ransomware watch error: {ex.Message}");
        }
    }

    private bool IsCanary(string path)
    {
        lock (_gate)
        {
            if (_canaryPaths.Contains(path))
                return true;
        }

        // Also catch a canary that has been renamed away, which is what an encryption
        // run does to it.
        return Path.GetFileName(path).StartsWith(CanaryPrefix, StringComparison.OrdinalIgnoreCase);
    }

    private void Report(RansomwareFinding finding)
    {
        var reasons = string.Join(" ", finding.Signals.Select(s => s.Explanation));

        _log.Error("Sentinel",
            $"Possible ransomware activity. {reasons} " +
            $"{finding.FilesAffected} file(s) affected so far, for example: " +
            $"{string.Join(", ", finding.ExamplePaths)}. " +
            "Nexus has changed nothing — if this is not something you started, disconnect the machine " +
            "from the network and stop the program responsible.");

        Detected?.Invoke(finding);
    }

    private void OnWatcherError(string folder, Exception exception)
    {
        // Almost always a buffer overflow: events arrived faster than they could be
        // read, which is itself weakly interesting given what this service watches for.
        _log.Warn("Sentinel",
            $"The ransomware watch on {folder} dropped events ({exception.Message}). " +
            "That happens when a very large number of files change at once.");
    }

    public void Dispose()
    {
        _running = false;
        _replantTimer?.Dispose();
        _replantTimer = null;

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
    }
}
