using System.Diagnostics;

namespace Nexus.App.Services;

/// <summary>
/// Fallback watcher: diffs the PID set every 1.5 s. Slower to react than WMI but
/// has no dependencies that can break.
/// </summary>
public sealed class PollingProcessWatcher : IProcessWatcher
{
    private readonly TimeSpan _interval;
    private System.Threading.Timer? _timer;
    private Dictionary<int, string> _known = new();
    private int _scanning;

    public event Action<ProcessEvent>? ProcessStarted;
    public event Action<ProcessEvent>? ProcessStopped;

    public string Mechanism => "polling";

    public PollingProcessWatcher(TimeSpan? interval = null)
    {
        _interval = interval ?? TimeSpan.FromSeconds(1.5);
    }

    public void Start()
    {
        _known = Scan();
        _timer = new System.Threading.Timer(_ => Tick(), null, _interval, _interval);
    }

    private void Tick()
    {
        if (Interlocked.Exchange(ref _scanning, 1) == 1)
            return; // previous scan still running

        try
        {
            var current = Scan();

            foreach (var (pid, name) in current)
            {
                if (!_known.ContainsKey(pid))
                    ProcessStarted?.Invoke(new ProcessEvent(pid, name));
            }

            foreach (var (pid, name) in _known)
            {
                if (!current.ContainsKey(pid))
                    ProcessStopped?.Invoke(new ProcessEvent(pid, name));
            }

            _known = current;
        }
        catch (Exception)
        {
            // A failed scan just means we catch up on the next tick.
        }
        finally
        {
            Volatile.Write(ref _scanning, 0);
        }
    }

    private static Dictionary<int, string> Scan()
    {
        var result = new Dictionary<int, string>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                result[process.Id] = process.ProcessName + ".exe";
            }
        }
        return result;
    }

    public void Dispose() => _timer?.Dispose();
}
