using Nexus.Core.Logging;

namespace Nexus.App.Services;

/// <summary>
/// Prefers the event-driven WMI watcher and hot-swaps to polling if WMI is
/// unavailable at startup or dies later. Consumers only ever see this wrapper.
/// </summary>
public sealed class FailoverProcessWatcher : IProcessWatcher
{
    private readonly ActivityLog _log;
    private readonly object _gate = new();
    private IProcessWatcher? _inner;
    private bool _disposed;

    public event Action<ProcessEvent>? ProcessStarted;
    public event Action<ProcessEvent>? ProcessStopped;

    public string Mechanism => _inner?.Mechanism ?? "none";

    public FailoverProcessWatcher(ActivityLog log)
    {
        _log = log;
    }

    public void Start()
    {
        lock (_gate)
        {
            try
            {
                var wmi = new WmiProcessWatcher();
                wmi.Failed += OnWmiFailed;
                Attach(wmi);
                wmi.Start();
                _log.Info("Watcher", "Watching process starts via WMI event trace.");
            }
            catch (Exception ex)
            {
                _log.Warn("Watcher", $"WMI process watcher unavailable ({ex.Message}); using 1.5 s polling instead.");
                StartPollingLocked();
            }
        }
    }

    private void OnWmiFailed(Exception ex)
    {
        lock (_gate)
        {
            if (_disposed || _inner is PollingProcessWatcher)
                return;
            _log.Warn("Watcher", $"WMI process watcher failed ({ex.Message}); switching to 1.5 s polling.");
            _inner?.Dispose();
            StartPollingLocked();
        }
    }

    private void StartPollingLocked()
    {
        var polling = new PollingProcessWatcher();
        Attach(polling);
        polling.Start();
    }

    private void Attach(IProcessWatcher watcher)
    {
        watcher.ProcessStarted += e => ProcessStarted?.Invoke(e);
        watcher.ProcessStopped += e => ProcessStopped?.Invoke(e);
        _inner = watcher;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            _inner?.Dispose();
        }
    }
}
