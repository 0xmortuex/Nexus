using System.Diagnostics;
using Nexus.App.Services;
using Nexus.Core;
using Nexus.Core.Logging;
using Nexus.Core.Models;
using Nexus.Core.Rules;

namespace Nexus.App.Services;

/// <summary>
/// Handles the lifecycle-shaped rule flags that RuleApplicationService (a pure
/// "apply settings at start" service) can't: keep-awake-while-running holds,
/// auto-restart on exit (crash-loop guarded), and CPU-limiter job cleanup.
/// </summary>
public sealed class RuleLifecycleService : IDisposable
{
    private const int MaxRestartsPerWindow = 3;
    private static readonly TimeSpan RestartWindow = TimeSpan.FromMinutes(5);

    private readonly IProcessWatcher _watcher;
    private readonly RulesRepository _rules;
    private readonly KeepAwakeService _keepAwake;
    private readonly CpuLimiterService _limiter;
    private readonly KillTracker _kills;
    private readonly ActivityLog _log;
    private readonly object _gate = new();

    private readonly HashSet<int> _awakeHolds = [];
    private readonly Dictionary<int, string> _restartPaths = new();
    private readonly Dictionary<string, List<DateTimeOffset>> _restartHistory = new(StringComparer.Ordinal);

    public RuleLifecycleService(
        IProcessWatcher watcher,
        RulesRepository rules,
        KeepAwakeService keepAwake,
        CpuLimiterService limiter,
        KillTracker kills,
        ActivityLog log)
    {
        _watcher = watcher;
        _rules = rules;
        _keepAwake = keepAwake;
        _limiter = limiter;
        _kills = kills;
        _log = log;
    }

    public void Start()
    {
        _watcher.ProcessStarted += OnStarted;
        _watcher.ProcessStopped += OnStopped;

        // Pick up already-running processes for keep-awake / restart tracking.
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                OnStarted(new ProcessEvent(process.Id, process.ProcessName + ".exe"));
            }
        }
    }

    private void OnStarted(ProcessEvent e)
    {
        var rule = _rules.Find(e.ExeName);
        if (rule is not { Enabled: true })
            return;

        lock (_gate)
        {
            if (rule.KeepAwakeWhileRunning && _awakeHolds.Add(e.Pid))
                _keepAwake.AddHold(e.ExeName);

            if (rule.RestartIfExited && !_restartPaths.ContainsKey(e.Pid))
            {
                try
                {
                    using var process = Process.GetProcessById(e.Pid);
                    if (process.MainModule?.FileName is { } path)
                        _restartPaths[e.Pid] = path;
                }
                catch (Exception)
                {
                    // Access denied / exited — restart won't be possible for this instance.
                }
            }
        }
    }

    private void OnStopped(ProcessEvent e)
    {
        string? restartPath = null;

        lock (_gate)
        {
            if (_awakeHolds.Remove(e.Pid))
                _keepAwake.ReleaseHold(e.ExeName);

            _limiter.OnProcessExited(e.Pid);

            if (_restartPaths.Remove(e.Pid, out var path))
            {
                var rule = _rules.Find(e.ExeName);
                if (rule is { Enabled: true, RestartIfExited: true }
                    && !_kills.WasKilledByNexus(e.Pid)
                    && !ProcessSafety.IsProtected(e.ExeName)
                    && AllowRestartLocked(rule.NormalizedName))
                {
                    restartPath = path;
                }
            }
        }

        if (restartPath is null)
            return;

        try
        {
            Process.Start(new ProcessStartInfo(restartPath) { UseShellExecute = true });
            _log.Info("Rules", $"{e.ExeName} exited and its rule says keep it running — relaunched it.");
        }
        catch (Exception ex)
        {
            _log.Warn("Rules", $"Could not relaunch {e.ExeName}: {ex.Message}");
        }
    }

    private bool AllowRestartLocked(string normalizedName)
    {
        var now = DateTimeOffset.Now;
        if (!_restartHistory.TryGetValue(normalizedName, out var history))
            _restartHistory[normalizedName] = history = [];

        history.RemoveAll(t => now - t > RestartWindow);
        if (history.Count >= MaxRestartsPerWindow)
        {
            _log.Warn("Rules",
                $"{normalizedName} exited again but was already relaunched {MaxRestartsPerWindow} times in {RestartWindow.TotalMinutes:F0} minutes — backing off (crash loop?).");
            return false;
        }

        history.Add(now);
        return true;
    }

    public void Dispose()
    {
        _watcher.ProcessStarted -= OnStarted;
        _watcher.ProcessStopped -= OnStopped;
    }
}
