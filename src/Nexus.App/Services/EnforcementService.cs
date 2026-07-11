using System.Diagnostics;
using Nexus.App.Interop;
using Nexus.Core;
using Nexus.Core.Enforcement;
using Nexus.Core.Logging;
using Nexus.Core.Models;
using Nexus.Core.Persistence;

namespace Nexus.App.Services;

/// <summary>
/// Hosts the instance-limit, disallowed-process, and watchdog engines. Reuses the
/// watcher for launch-time enforcement and the ProBalance snapshot stream for the
/// watchdog so the system is only sampled once per second in total.
/// </summary>
public sealed class EnforcementService : IDisposable
{
    private readonly IProcessWatcher _watcher;
    private readonly ProBalanceService _snapshots;
    private readonly ProcessApi _api;
    private readonly ActivityLog _log;
    private readonly SettingsService _settings;
    private readonly WatchdogEngine _watchdog = new();
    private readonly Dictionary<int, RunningInstance> _running = new();
    private readonly object _gate = new();

    public EnforcementService(
        IProcessWatcher watcher,
        ProBalanceService snapshots,
        ProcessApi api,
        ActivityLog log,
        SettingsService settings)
    {
        _watcher = watcher;
        _snapshots = snapshots;
        _api = api;
        _log = log;
        _settings = settings;
    }

    public void Start()
    {
        lock (_gate)
        {
            foreach (var process in Process.GetProcesses())
            {
                using (process)
                {
                    DateTimeOffset started;
                    try
                    {
                        started = process.StartTime;
                    }
                    catch (Exception)
                    {
                        started = DateTimeOffset.Now; // access denied → treat as just started
                    }
                    _running[process.Id] = new RunningInstance(process.Id, process.ProcessName + ".exe", started);
                }
            }
        }

        _watcher.ProcessStarted += OnProcessStarted;
        _watcher.ProcessStopped += OnProcessStopped;
        _snapshots.SnapshotTaken += OnSnapshot;
    }

    private void OnProcessStarted(ProcessEvent e)
    {
        var instance = new RunningInstance(e.Pid, e.ExeName, DateTimeOffset.Now);
        lock (_gate)
        {
            _running[e.Pid] = instance;
        }

        var options = _settings.Current.Enforcement;
        var normalized = ProcessRule.Normalize(e.ExeName);

        // Disallowed list: terminate on sight.
        if (options.DisallowedProcesses.Any(d => ProcessRule.Normalize(d) == normalized))
        {
            if (TryKill(e.Pid, e.ExeName))
                _log.Info("Enforcement", $"Terminated disallowed process {e.ExeName} (PID {e.Pid}).");
            return;
        }

        // Instance limits: kill newest beyond N.
        var limit = options.InstanceLimits.FirstOrDefault(l => l.Enabled && l.NormalizedName == normalized);
        if (limit is not null)
        {
            IReadOnlyList<int> toKill;
            lock (_gate)
            {
                toKill = InstanceLimitEngine.SelectPidsToKill(_running.Values, limit);
            }
            foreach (var pid in toKill)
            {
                if (TryKill(pid, e.ExeName))
                    _log.Info("Enforcement",
                        $"Closed extra instance of {e.ExeName} (PID {pid}); limit is {limit.MaxInstances}.");
            }
        }
    }

    private void OnProcessStopped(ProcessEvent e)
    {
        lock (_gate)
        {
            _running.Remove(e.Pid);
        }
    }

    private void OnSnapshot(SystemSnapshot snapshot)
    {
        var rules = _settings.Current.Enforcement.WatchdogRules;
        if (rules.Count == 0)
            return;

        foreach (var trigger in _watchdog.Tick(snapshot, rules, snapshot.Timestamp))
            ApplyWatchdogAction(trigger);
    }

    private void ApplyWatchdogAction(WatchdogTrigger trigger)
    {
        switch (trigger.Rule.Action)
        {
            case WatchdogActionKind.LowerPriority:
                if (_api.TrySetPriority(trigger.Pid, trigger.ExeName, ProcessPriority.BelowNormal, out var error))
                    _log.Info("Watchdog", $"Lowered {trigger.ExeName} (PID {trigger.Pid}) to BelowNormal: {trigger.Reason}.");
                else
                    _log.Warn("Watchdog", $"Could not lower {trigger.ExeName}: {error}");
                break;

            case WatchdogActionKind.TrimWorkingSet:
                if (_api.TryTrimWorkingSet(trigger.Pid, trigger.ExeName, out error))
                    _log.Info("Watchdog", $"Trimmed working set of {trigger.ExeName} (PID {trigger.Pid}): {trigger.Reason}.");
                else
                    _log.Warn("Watchdog", $"Could not trim {trigger.ExeName}: {error}");
                break;

            case WatchdogActionKind.Kill:
                if (TryKill(trigger.Pid, trigger.ExeName))
                    _log.Info("Watchdog", $"Killed {trigger.ExeName} (PID {trigger.Pid}): {trigger.Reason}.");
                break;

            case WatchdogActionKind.Restart:
                Restart(trigger);
                break;
        }
    }

    private void Restart(WatchdogTrigger trigger)
    {
        if (ProcessSafety.IsProtected(trigger.ExeName))
        {
            _log.Warn("Watchdog", $"Refused to restart protected process {trigger.ExeName}.");
            return;
        }

        try
        {
            string? path;
            using (var process = Process.GetProcessById(trigger.Pid))
            {
                path = process.MainModule?.FileName;
                process.Kill();
                process.WaitForExit(5000);
            }

            if (path is null)
            {
                _log.Warn("Watchdog",
                    $"Killed {trigger.ExeName} (PID {trigger.Pid}) but could not read its path to restart it.");
                return;
            }

            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
            _log.Info("Watchdog",
                $"Restarted {trigger.ExeName}: {trigger.Reason}. Command-line arguments are not preserved.");
        }
        catch (Exception ex)
        {
            _log.Error("Watchdog", $"Restart of {trigger.ExeName} (PID {trigger.Pid}) failed: {ex.Message}");
        }
    }

    private bool TryKill(int pid, string exeName)
    {
        if (ProcessSafety.IsProtected(exeName))
        {
            _log.Warn("Enforcement", $"Refused to terminate protected process {exeName}.");
            return false;
        }
        if (pid == Environment.ProcessId)
            return false;

        try
        {
            using var process = Process.GetProcessById(pid);
            process.Kill();
            return true;
        }
        catch (Exception ex)
        {
            _log.Warn("Enforcement", $"Could not terminate {exeName} (PID {pid}): {ex.Message}");
            return false;
        }
    }

    public void Dispose()
    {
        _watcher.ProcessStarted -= OnProcessStarted;
        _watcher.ProcessStopped -= OnProcessStopped;
        _snapshots.SnapshotTaken -= OnSnapshot;
    }
}
