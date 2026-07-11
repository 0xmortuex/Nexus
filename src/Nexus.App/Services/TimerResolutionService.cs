using Nexus.App.Interop;
using Nexus.Core.Logging;
using Nexus.Core.Persistence;

namespace Nexus.App.Services;

/// <summary>
/// Requests the finest system timer resolution (typically 0.5 ms) and holds it.
/// Since Windows 10 2004 timer resolution is per-process, so a long-lived process
/// like Nexus must keep the request alive to stop the system falling back to the
/// 15.6 ms default; the request is re-asserted on a timer as a belt-and-braces.
/// Honest note (shown in the UI): on current Windows this mainly helps apps that
/// call timeBeginPeriod poorly; it is not a guaranteed FPS win.
/// </summary>
public sealed class TimerResolutionService : IDisposable
{
    private readonly ActivityLog _log;
    private readonly SettingsService _settings;
    private System.Threading.Timer? _reassert;
    private bool _held;

    public TimerResolutionService(ActivityLog log, SettingsService settings)
    {
        _log = log;
        _settings = settings;
    }

    public bool Enabled => _settings.Current.HighTimerResolution;

    /// <summary>Current actual resolution in milliseconds, or null if unknown.</summary>
    public double? CurrentMs
    {
        get
        {
            try
            {
                if (NativeMethods.NtQueryTimerResolution(out _, out _, out var current) == 0)
                    return current / 10_000.0;
            }
            catch (Exception)
            {
            }
            return null;
        }
    }

    public void Start()
    {
        if (Enabled)
            Apply();
    }

    public void SetEnabled(bool enabled)
    {
        _settings.Update(s => s with { HighTimerResolution = enabled });
        if (enabled)
            Apply();
        else
            Release();
    }

    private void Apply()
    {
        try
        {
            // Ask for the maximum (finest) resolution the platform supports.
            if (NativeMethods.NtQueryTimerResolution(out _, out var maximum, out _) != 0)
                maximum = 5000; // 0.5 ms fallback
            if (NativeMethods.NtSetTimerResolution(maximum, true, out var current) == 0)
            {
                _held = true;
                _reassert ??= new System.Threading.Timer(_ => Reassert(), null,
                    TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
                _log.Info("Timer", $"Requested high timer resolution; system is now at {current / 10_000.0:F2} ms.");
            }
            else
            {
                _log.Warn("Timer", "NtSetTimerResolution was refused; leaving the system default.");
            }
        }
        catch (Exception ex)
        {
            _log.Error("Timer", $"Could not set timer resolution: {ex.Message}");
        }
    }

    private void Reassert()
    {
        if (_held && NativeMethods.NtQueryTimerResolution(out _, out var maximum, out _) == 0)
            NativeMethods.NtSetTimerResolution(maximum, true, out _);
    }

    private void Release()
    {
        _reassert?.Dispose();
        _reassert = null;
        if (!_held)
            return;
        try
        {
            if (NativeMethods.NtQueryTimerResolution(out var minimum, out _, out _) == 0)
                NativeMethods.NtSetTimerResolution(minimum, false, out _);
            _held = false;
            _log.Info("Timer", "Released the high timer resolution request.");
        }
        catch (Exception ex)
        {
            _log.Warn("Timer", $"Could not release timer resolution: {ex.Message}");
        }
    }

    public void Dispose() => Release();
}
