using Nexus.App.Interop;
using Nexus.Core;
using Nexus.Core.Logging;
using Nexus.Core.Models;
using Nexus.Core.Persistence;

namespace Nexus.App.Services;

/// <summary>
/// Process Lasso-style foreground boosting: while enabled, the app you're working
/// in is raised to AboveNormal and restored to its original priority the moment it
/// goes to the background. Only Normal-priority processes are boosted — anything
/// the user or a rule already set stays untouched.
/// </summary>
public sealed class ForegroundBoostService : IDisposable
{
    private readonly ForegroundMonitor _foreground;
    private readonly ProcessApi _api;
    private readonly ActivityLog _log;
    private readonly SettingsService _settings;
    private readonly GameModeService _gameMode;
    private readonly object _gate = new();

    private int _boostedPid = -1;
    private string _boostedExe = "";

    public ForegroundBoostService(
        ForegroundMonitor foreground,
        ProcessApi api,
        ActivityLog log,
        SettingsService settings,
        GameModeService gameMode)
    {
        _foreground = foreground;
        _api = api;
        _log = log;
        _settings = settings;
        _gameMode = gameMode;
    }

    public void Start() => _foreground.Sampled += OnSampled;

    private void OnSampled(ForegroundSample? sample)
    {
        lock (_gate)
        {
            bool enabled = _settings.Current.ForegroundBoost && !_gameMode.IsActive;
            int currentPid = sample?.Pid ?? -1;

            if (_boostedPid > 0 && (_boostedPid != currentPid || !enabled))
                Unboost();

            if (!enabled || sample is null || currentPid == _boostedPid
                || currentPid == Environment.ProcessId)
                return;

            var exe = sample.Window.ExeName;
            if (ProcessSafety.IsRestraintExempt(exe))
                return;

            // Boost only processes currently at Normal so explicit settings survive.
            if (!_api.TryGetPriority(currentPid, out var priority, out _) || priority != ProcessPriority.Normal)
                return;

            if (_api.TrySetPriority(currentPid, exe, ProcessPriority.AboveNormal, out _))
            {
                _boostedPid = currentPid;
                _boostedExe = exe;
                _log.Info("ForegroundBoost", $"Boosted foreground app {exe} (PID {currentPid}) to AboveNormal.");
            }
        }
    }

    private void Unboost()
    {
        if (_api.TrySetPriority(_boostedPid, _boostedExe, ProcessPriority.Normal, out _))
            _log.Info("ForegroundBoost", $"Restored {_boostedExe} (PID {_boostedPid}) to Normal.");
        _boostedPid = -1;
        _boostedExe = "";
    }

    public void Dispose()
    {
        _foreground.Sampled -= OnSampled;
        lock (_gate)
        {
            if (_boostedPid > 0)
                Unboost();
        }
    }
}
