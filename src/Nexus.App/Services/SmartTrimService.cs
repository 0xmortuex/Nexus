using Nexus.App.Interop;
using Nexus.Core.Enforcement;
using Nexus.Core.Logging;
using Nexus.Core.Models;
using Nexus.Core.Persistence;

namespace Nexus.App.Services;

/// <summary>
/// Periodically trims the working sets of background processes holding more RAM
/// than the configured threshold. The foreground app and exempt/system processes
/// are never touched; a per-process cooldown avoids trim thrash.
/// </summary>
public sealed class SmartTrimService : IDisposable
{
    private readonly ProBalanceService _snapshots;
    private readonly ProcessApi _api;
    private readonly ActivityLog _log;
    private readonly SettingsService _settings;
    private readonly SmartTrimEngine _engine = new();

    public SmartTrimService(ProBalanceService snapshots, ProcessApi api, ActivityLog log, SettingsService settings)
    {
        _snapshots = snapshots;
        _api = api;
        _log = log;
        _settings = settings;
    }

    public void Start() => _snapshots.SnapshotTaken += OnSnapshot;

    private void OnSnapshot(SystemSnapshot snapshot)
    {
        var targets = _engine.Tick(snapshot, ForegroundInfo.GetForegroundPid(),
            _settings.Current.SmartTrim, snapshot.Timestamp);

        long freedApprox = 0;
        int trimmed = 0;
        foreach (var target in targets)
        {
            if (_api.TryTrimWorkingSet(target.Pid, target.ExeName, out _))
            {
                trimmed++;
                freedApprox += target.WorkingSetBytes;
                _log.Info("SmartTrim",
                    $"Trimmed {target.ExeName} (PID {target.Pid}), was holding {target.WorkingSetBytes / (1024 * 1024)} MB.");
            }
        }

        if (trimmed > 1)
            _log.Info("SmartTrim", $"Trim pass complete: {trimmed} processes, ~{freedApprox / (1024 * 1024)} MB working set released.");
    }

    public void Dispose() => _snapshots.SnapshotTaken -= OnSnapshot;
}
