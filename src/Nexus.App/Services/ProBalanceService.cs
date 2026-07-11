using Nexus.App.Interop;
using Nexus.Core.Logging;
using Nexus.Core.Models;
using Nexus.Core.Persistence;
using Nexus.Core.ProBalance;

namespace Nexus.App.Services;

/// <summary>
/// Thin host for the ProBalance engine: samples the system once a second, feeds the
/// engine, applies its actions (saving each victim's original priority so restores
/// are exact), and logs every event in plain language.
/// </summary>
public sealed class ProBalanceService : IDisposable
{
    private readonly SystemSampler _sampler;
    private readonly ProcessApi _api;
    private readonly ActivityLog _log;
    private readonly SettingsService _settings;
    private readonly ProBalanceEngine _engine;
    private readonly Dictionary<int, ProcessPriority> _originalPriorities = new();
    private readonly object _gate = new();
    private System.Threading.Timer? _timer;

    /// <summary>Most recent snapshot, for the dashboard.</summary>
    public SystemSnapshot? LastSnapshot { get; private set; }

    public event Action<SystemSnapshot>? SnapshotTaken;

    public bool Enabled => _settings.Current.ProBalance.Enabled;

    public IReadOnlyCollection<int> RestrainedPids
    {
        get
        {
            lock (_gate)
            {
                return _engine.RestrainedPids.ToArray();
            }
        }
    }

    public ProBalanceService(SystemSampler sampler, ProcessApi api, ActivityLog log, SettingsService settings)
    {
        _sampler = sampler;
        _api = api;
        _log = log;
        _settings = settings;
        _engine = new ProBalanceEngine(settings.Current.ProBalance);
        settings.Changed += s =>
        {
            lock (_gate)
            {
                _engine.Options = s.ProBalance;
            }
        };
    }

    public void Start()
    {
        _timer = new System.Threading.Timer(_ => Tick(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        _log.Info("ProBalance", "Dynamic restraint started.");
    }

    public void SetEnabled(bool enabled)
    {
        _settings.Update(s => s with { ProBalance = s.ProBalance with { Enabled = enabled } });
        _log.Info("ProBalance", enabled ? "Dynamic restraint enabled." : "Dynamic restraint disabled.");
    }

    private void Tick()
    {
        try
        {
            var snapshot = _sampler.Sample();
            LastSnapshot = snapshot;

            IReadOnlyList<ProBalanceAction> actions;
            lock (_gate)
            {
                actions = _engine.Tick(snapshot, ForegroundInfo.GetForegroundPid(), snapshot.Timestamp);
            }

            foreach (var action in actions)
                ApplyAction(action);

            SnapshotTaken?.Invoke(snapshot);
        }
        catch (Exception ex)
        {
            _log.Error("ProBalance", $"Sampling pass failed: {ex.Message}");
        }
    }

    private void ApplyAction(ProBalanceAction action)
    {
        switch (action)
        {
            case RestrainAction restrain:
            {
                if (_api.TryGetPriority(restrain.Pid, out var original, out _))
                {
                    lock (_gate)
                    {
                        _originalPriorities[restrain.Pid] = original;
                    }
                }

                if (_api.TrySetPriority(restrain.Pid, restrain.ExeName, ProcessPriority.BelowNormal, out var error))
                    _log.Info("ProBalance",
                        $"Restrained {restrain.ExeName} (PID {restrain.Pid}) to BelowNormal: {restrain.Reason}.");
                else
                    _log.Warn("ProBalance",
                        $"Could not restrain {restrain.ExeName} (PID {restrain.Pid}): {error}");
                break;
            }
            case RestoreAction restore:
            {
                ProcessPriority original;
                lock (_gate)
                {
                    if (!_originalPriorities.Remove(restore.Pid, out original))
                        original = ProcessPriority.Normal;
                }

                if (restore.ProcessExited)
                {
                    _log.Info("ProBalance", $"{restore.ExeName} (PID {restore.Pid}) exited while restrained.");
                    break;
                }

                if (_api.TrySetPriority(restore.Pid, restore.ExeName, original, out var error))
                    _log.Info("ProBalance",
                        $"Restored {restore.ExeName} (PID {restore.Pid}) to {original}: {restore.Reason}.");
                else
                    _log.Warn("ProBalance",
                        $"Could not restore {restore.ExeName} (PID {restore.Pid}): {error}");
                break;
            }
        }
    }

    public void Dispose()
    {
        _timer?.Dispose();

        // Best effort: leave no process restrained behind on clean shutdown.
        foreach (var pid in RestrainedPids)
        {
            ProcessPriority original;
            lock (_gate)
            {
                if (!_originalPriorities.Remove(pid, out original))
                    original = ProcessPriority.Normal;
            }
            _api.TrySetPriority(pid, "shutdown-restore", original, out _);
        }
    }
}
