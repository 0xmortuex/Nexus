using Nexus.App.Interop;
using Nexus.Core.Logging;

namespace Nexus.App.Services;

/// <summary>
/// Keep Awake toggle over SetThreadExecutionState. The execution-state flag is
/// per-thread and dies with its thread, so this service owns one long-lived
/// background thread and marshals every state change onto it.
/// </summary>
public sealed class KeepAwakeService : IDisposable
{
    private readonly ActivityLog _log;
    private readonly Thread _thread;
    private readonly SemaphoreSlim _wake = new(0);
    private volatile bool _manual;
    private int _holds;
    private volatile bool _desired;
    private volatile bool _shutdown;

    /// <summary>The user-facing manual toggle state.</summary>
    public bool Enabled => _manual;

    public event Action<bool>? EnabledChanged;

    public KeepAwakeService(ActivityLog log)
    {
        _log = log;
        _thread = new Thread(Run) { IsBackground = true, Name = "Nexus.KeepAwake" };
        _thread.Start();
    }

    public void SetEnabled(bool enabled)
    {
        if (_manual == enabled)
            return;
        _manual = enabled;
        Recompute();
        _log.Info("KeepAwake", enabled
            ? "Keep Awake on — the PC and display will not sleep."
            : "Keep Awake off — normal power timeouts apply.");
        EnabledChanged?.Invoke(enabled);
    }

    /// <summary>Per-process holds (rules with "keep PC awake while running").
    /// The system stays awake while the manual toggle OR any hold is active.</summary>
    public void AddHold(string reason)
    {
        Interlocked.Increment(ref _holds);
        Recompute();
        _log.Info("KeepAwake", $"Keeping the PC awake while {reason} is running.");
    }

    public void ReleaseHold(string reason)
    {
        if (Interlocked.Decrement(ref _holds) < 0)
            Interlocked.Exchange(ref _holds, 0);
        Recompute();
        _log.Info("KeepAwake", $"Released the keep-awake hold for {reason}.");
    }

    private void Recompute()
    {
        bool desired = _manual || Volatile.Read(ref _holds) > 0;
        if (_desired == desired)
            return;
        _desired = desired;
        _wake.Release();
    }

    private void Run()
    {
        bool applied = false;
        while (!_shutdown)
        {
            // Re-assert hourly even without changes; some drivers reset the state.
            _wake.Wait(TimeSpan.FromHours(1));
            if (_shutdown)
                break;

            try
            {
                if (_desired)
                {
                    var result = NativeMethods.SetThreadExecutionState(
                        NativeMethods.ES_CONTINUOUS | NativeMethods.ES_SYSTEM_REQUIRED | NativeMethods.ES_DISPLAY_REQUIRED);
                    if (result == 0)
                        _log.Warn("KeepAwake", "SetThreadExecutionState failed; the system may still sleep.");
                    applied = true;
                }
                else if (applied)
                {
                    NativeMethods.SetThreadExecutionState(NativeMethods.ES_CONTINUOUS);
                    applied = false;
                }
            }
            catch (Exception ex)
            {
                _log.Error("KeepAwake", $"Keep Awake toggle failed: {ex.Message}");
            }
        }

        if (applied)
        {
            try
            {
                NativeMethods.SetThreadExecutionState(NativeMethods.ES_CONTINUOUS);
            }
            catch (Exception)
            {
                // Process exit clears the state anyway.
            }
        }
    }

    public void Dispose()
    {
        _shutdown = true;
        _wake.Release();
        _thread.Join(TimeSpan.FromSeconds(2));
    }
}
