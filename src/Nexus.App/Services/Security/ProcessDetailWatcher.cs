using System.Management;
using Nexus.Core.Logging;
using Nexus.Core.Security.Behavior;

namespace Nexus.App.Services.Security;

/// <summary>
/// Feeds the behavioural engine with process launches, including the two fields the
/// optimizer's watcher does not carry: the full command line and the parent.
///
/// Uses a WMI instance-creation event over Win32_Process rather than
/// Win32_ProcessStartTrace, because the trace class reports only a name and a PID —
/// and a behavioural rule that cannot see the command line cannot tell
/// "certutil -hashfile" from "certutil -urlcache -f http://…".
///
/// Two honest limitations, both consequences of staying in user mode:
/// - <b>It polls.</b> WMI delivers these events on a one-second window, so a process
///   that starts and exits inside that window can be missed entirely.
/// - <b>It observes after the fact.</b> By the time an event arrives the process is
///   already running. This is a reporting pipeline, not an interception one, and
///   nothing built on it could block an execution even if it wanted to.
/// </summary>
public sealed class ProcessDetailWatcher : IDisposable
{
    private readonly ActivityLog _log;
    private readonly BehaviorEngine _engine;
    private ManagementEventWatcher? _startWatcher;
    private ManagementEventWatcher? _stopWatcher;
    private bool _running;

    /// <summary>Raised for launches the behavioural engine considers notable.</summary>
    public event Action<BehaviorFinding>? FindingRaised;

    public ProcessDetailWatcher(ActivityLog log, BehaviorEngine engine)
    {
        _log = log;
        _engine = engine;
    }

    public bool IsRunning => _running;

    public void Start()
    {
        if (_running)
            return;

        try
        {
            _startWatcher = new ManagementEventWatcher(new EventQuery(
                "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"));
            _startWatcher.EventArrived += OnProcessStarted;
            _startWatcher.Start();

            _stopWatcher = new ManagementEventWatcher(new EventQuery(
                "SELECT * FROM __InstanceDeletionEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'"));
            _stopWatcher.EventArrived += OnProcessStopped;
            _stopWatcher.Start();

            _running = true;
            _log.Info("Sentinel", "Watching process launches for suspicious behaviour.");
        }
        catch (ManagementException ex)
        {
            _log.Warn("Sentinel",
                $"Could not start behaviour monitoring: {ex.Message}. " +
                "File scanning and the startup audit still work.");
            Dispose();
        }
    }

    private void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            if (e.NewEvent["TargetInstance"] is not ManagementBaseObject instance)
                return;

            var imagePath = instance["ExecutablePath"] as string
                            ?? instance["Name"] as string
                            ?? "";
            if (imagePath.Length == 0)
                return;

            int pid = ToInt(instance["ProcessId"]);
            int parentPid = ToInt(instance["ParentProcessId"]);

            var evt = new ProcessStartEvent
            {
                Pid = pid,
                ParentPid = parentPid,
                ImagePath = imagePath,
                CommandLine = instance["CommandLine"] as string ?? "",
                ParentImagePath = ResolveParentImage(parentPid),
                At = DateTimeOffset.Now,
            };

            var finding = _engine.Observe(evt);
            if (finding is null)
                return;

            // Add the launch chain. "powershell.exe did something odd" is a fact;
            // "WINWORD.EXE started cmd.exe which started powershell.exe" is an
            // explanation, and the engine already tracks the ancestry precisely so
            // that this works even when the parent has already exited — which, for a
            // dropper, it usually has.
            var ancestry = _engine.AncestryOf(evt.Pid);
            if (ancestry.Count > 1)
            {
                var chain = string.Join(" → ", ancestry.Reverse());
                finding = finding with
                {
                    Signals =
                    [
                        .. finding.Signals,
                        new Nexus.Core.Security.SecuritySignal(
                            Nexus.Core.Security.SignalSource.Behavior,
                            Nexus.Core.Security.SignalWeight.Informational,
                            "beh-launch-chain",
                            $"It was started like this: {chain}."),
                    ],
                };
            }

            FindingRaised?.Invoke(finding);
        }
        catch (Exception ex)
        {
            // Broad on purpose, matching WmiProcessWatcher. This runs on a WMI
            // callback thread, so anything that escapes here takes the whole process
            // down — and it is not just this method's own failures at risk: raising
            // the event runs every subscriber, up through the verdict engine and into
            // the view-models. A malformed instance is routine under load; a bug in a
            // subscriber should cost one event, not the application.
            _log.Warn("Sentinel", $"Dropped a process event: {ex.Message}");
        }
    }

    private void OnProcessStopped(object sender, EventArrivedEventArgs e)
    {
        try
        {
            if (e.NewEvent["TargetInstance"] is not ManagementBaseObject instance)
                return;

            _engine.Forget(ToInt(instance["ProcessId"]));
        }
        catch (Exception)
        {
            // See above: never let anything escape onto the WMI callback thread.
            // Failing to forget one PID costs a slot in a bounded map, nothing more.
        }
    }

    /// <summary>
    /// Best-effort parent image lookup. The parent has very often already exited by
    /// the time we ask — which is itself the interesting case, and why the engine
    /// keeps its own ancestry map rather than relying on this.
    /// </summary>
    private static string ResolveParentImage(int parentPid)
    {
        if (parentPid <= 0)
            return "";

        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(parentPid);
            return process.MainModule?.FileName ?? process.ProcessName;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException
                                       or System.ComponentModel.Win32Exception)
        {
            return "";
        }
    }

    private static int ToInt(object? value) =>
        value is null ? 0 : Convert.ToInt32(value);

    public void Dispose()
    {
        _running = false;

        foreach (var watcher in new[] { _startWatcher, _stopWatcher })
        {
            if (watcher is null)
                continue;

            try
            {
                watcher.Stop();
            }
            catch (ManagementException)
            {
                // Already stopped or WMI is gone.
            }

            watcher.Dispose();
        }

        _startWatcher = null;
        _stopWatcher = null;
    }
}
