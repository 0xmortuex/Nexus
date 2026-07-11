using System.Management;

namespace Nexus.App.Services;

/// <summary>
/// Event-driven watcher over Win32_ProcessStartTrace / Win32_ProcessStopTrace
/// (kernel ETW trace via WMI; requires admin, which the app manifest guarantees).
/// Raises Failed if the WMI subsystem dies so the factory can fall back to polling.
/// </summary>
public sealed class WmiProcessWatcher : IProcessWatcher
{
    private ManagementEventWatcher? _startWatcher;
    private ManagementEventWatcher? _stopWatcher;

    public event Action<ProcessEvent>? ProcessStarted;
    public event Action<ProcessEvent>? ProcessStopped;
    public event Action<Exception>? Failed;

    public string Mechanism => "WMI";

    public void Start()
    {
        _startWatcher = new ManagementEventWatcher(new EventQuery("SELECT * FROM Win32_ProcessStartTrace"));
        _stopWatcher = new ManagementEventWatcher(new EventQuery("SELECT * FROM Win32_ProcessStopTrace"));

        _startWatcher.EventArrived += (_, e) => Dispatch(e, ProcessStarted);
        _stopWatcher.EventArrived += (_, e) => Dispatch(e, ProcessStopped);
        _startWatcher.Stopped += (_, _) => Failed?.Invoke(new InvalidOperationException("WMI start-trace watcher stopped"));

        _startWatcher.Start();
        _stopWatcher.Start();
    }

    private void Dispatch(EventArrivedEventArgs e, Action<ProcessEvent>? handler)
    {
        try
        {
            var name = e.NewEvent["ProcessName"] as string ?? "";
            var pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
            if (name.Length > 0)
                handler?.Invoke(new ProcessEvent(pid, name));
        }
        catch (Exception ex)
        {
            Failed?.Invoke(ex);
        }
    }

    public void Dispose()
    {
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
                // Already stopped or WMI gone; nothing to clean up.
            }
            watcher.Dispose();
        }
    }
}
