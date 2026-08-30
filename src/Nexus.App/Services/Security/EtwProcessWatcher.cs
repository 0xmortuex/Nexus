using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Nexus.Core.Logging;
using Nexus.Core.Security.Behavior;

namespace Nexus.App.Services.Security;

/// <summary>
/// Feeds the behavioural engine from an ETW kernel session instead of WMI.
///
/// This exists for one reason: WMI delivers process-creation events on a one-second
/// polling window, so anything that starts and exits inside that window is missed
/// entirely. That is not a rare edge case — it is the normal shape of the thing worth
/// catching. A dropper that spawns <c>cmd /c powershell -enc …</c> and exits is
/// measured in milliseconds, and the WMI watcher would never see it.
///
/// ETW delivers the event as the kernel creates the process, with the command line
/// and the parent, and misses nothing.
///
/// What it still cannot do is <b>intercept</b>. The event arrives as the process
/// starts, not before, so this remains a reporting pipeline. Blocking an execution
/// needs a kernel driver, and that gate is documented in the parity matrix.
///
/// <para>
/// Requires administrator rights, which Nexus has. When the session cannot be started
/// — not elevated, ETW disabled by policy, or another tool holding the session — this
/// reports failure and <see cref="SentinelService"/> falls back to the WMI watcher.
/// A degraded watcher is worth having; a silently absent one is not.
/// </para>
/// </summary>
public sealed class EtwProcessWatcher : IDisposable
{
    /// <summary>
    /// A distinctive session name. ETW sessions outlive the process that created them,
    /// so a crash leaves the session running and the name is how the next start finds
    /// and clears it.
    /// </summary>
    private const string SessionName = "NexusSentinelProcessWatch";

    private readonly ActivityLog _log;
    private readonly BehaviorEngine _engine;

    private TraceEventSession? _session;
    private Thread? _pump;
    private volatile bool _running;

    /// <summary>Raised for launches the behavioural engine considers notable.</summary>
    public event Action<BehaviorFinding>? FindingRaised;

    public EtwProcessWatcher(ActivityLog log, BehaviorEngine engine)
    {
        _log = log;
        _engine = engine;
    }

    public bool IsRunning => _running;

    /// <summary>
    /// Try to start the session.
    /// </summary>
    /// <returns>
    /// False when ETW is unavailable, so the caller can fall back rather than leaving
    /// behaviour monitoring silently switched off. Never throws.
    /// </returns>
    public bool TryStart()
    {
        if (_running)
            return true;

        try
        {
            // Clear a session left behind by a previous crash. Without this, a hard
            // kill permanently costs the feature until the machine is rebooted.
            StopStaleSession();

            _session = new TraceEventSession(SessionName)
            {
                // The events are useless if they arrive after the process is gone, and
                // a backlog helps nobody. Stop on dispose rather than persisting.
                StopOnDispose = true,
            };

            _session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);
            _session.Source.Kernel.ProcessStart += OnProcessStart;

            // Source.Process() blocks until the session stops, so it needs its own
            // thread. Background, so a stuck ETW pump can never hold up shutdown.
            _pump = new Thread(Pump)
            {
                IsBackground = true,
                Name = "Nexus ETW process watch",
            };

            _running = true;
            _pump.Start();

            _log.Info("Sentinel",
                "Behaviour monitoring is using ETW, so short-lived processes are seen too.");

            return true;
        }
        catch (Exception ex)
        {
            // Deliberately broad. Every failure here is a reason to fall back, and a
            // security feature that throws on startup because ETW is unavailable is
            // worse than one that quietly runs in its degraded mode and says so.
            _log.Info("Sentinel",
                $"Could not start the ETW process watch ({ex.GetType().Name}: {ex.Message}). " +
                "Falling back to the WMI watcher, which misses very short-lived processes.");

            Cleanup();
            return false;
        }
    }

    private void Pump()
    {
        try
        {
            _session?.Source.Process();
        }
        catch (Exception ex)
        {
            // The pump thread is not the UI thread and not a thread-pool thread; an
            // escaping exception here ends the process.
            if (_running)
                _log.Warn("Sentinel", $"The ETW process watch stopped: {ex.Message}");
        }
        finally
        {
            _running = false;
        }
    }

    private void OnProcessStart(ProcessTraceData data)
    {
        try
        {
            // Nexus's own helpers are excluded inside BehaviorEngine, which is told
            // Nexus's process name at construction; nothing extra is needed here.
            var evt = new ProcessStartEvent
            {
                Pid = data.ProcessID,
                ParentPid = data.ParentID,
                ImagePath = data.ImageFileName ?? "",
                CommandLine = data.CommandLine ?? "",
                ParentImagePath = "",
                At = data.TimeStamp,
            };

            if (_engine.Observe(evt) is { } finding)
                FindingRaised?.Invoke(finding);
        }
        catch (Exception ex)
        {
            // One malformed event must never take down the session. Command lines are
            // attacker-controlled, and this callback runs on the ETW pump thread where
            // an escape would end the process.
            _log.Info("Sentinel", $"Skipped a process event: {ex.Message}");
        }
    }

    /// <summary>
    /// Stop a session this class left behind previously.
    ///
    /// ETW sessions are a machine resource, not a process one. They survive the
    /// process that created them, so without this a crashed Nexus would hold the name
    /// until reboot and every later start would fail.
    /// </summary>
    private void StopStaleSession()
    {
        try
        {
            TraceEventSession.GetActiveSession(SessionName)?.Stop(noThrow: true);
        }
        catch (Exception ex)
        {
            _log.Info("Sentinel", $"Could not clear a previous ETW session: {ex.Message}");
        }
    }

    public void Stop() => Dispose();

    public void Dispose()
    {
        if (_session is null)
            return;

        _running = false;

        try
        {
            // Stopping the session ends Source.Process(), which lets the pump exit.
            _session.Stop(noThrow: true);
            _pump?.Join(TimeSpan.FromSeconds(2));
        }
        catch (Exception ex)
        {
            _log.Info("Sentinel", $"The ETW session did not stop cleanly: {ex.Message}");
        }
        finally
        {
            Cleanup();
            _log.Info("Sentinel", "Stopped the ETW process watch.");
        }
    }

    private void Cleanup()
    {
        try
        {
            _session?.Dispose();
        }
        catch (Exception ex) when (ex is ObjectDisposedException or InvalidOperationException)
        {
            // Already gone.
        }

        _session = null;
        _pump = null;
        _running = false;
    }
}
