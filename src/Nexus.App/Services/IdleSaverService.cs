using Nexus.App.Interop;
using Nexus.Core.Enforcement;
using Nexus.Core.Logging;
using Nexus.Core.Persistence;

namespace Nexus.App.Services;

/// <summary>
/// Switches to the Power Saver plan after N minutes without keyboard/mouse input
/// (GetLastInputInfo) and restores the previous plan the moment input returns.
/// Suppressed while Game Mode is active.
/// </summary>
public sealed class IdleSaverService : IDisposable
{
    private readonly PowerPlanService _power;
    private readonly ActivityLog _log;
    private readonly SettingsService _settings;
    private readonly IdleSaverEngine _engine = new();
    private System.Threading.Timer? _timer;

    /// <summary>Set true while a game/Performance Mode session runs (wired in Stage 4).</summary>
    public Func<bool> IsSuppressed { get; set; } = static () => false;

    public IdleSaverService(PowerPlanService power, ActivityLog log, SettingsService settings)
    {
        _power = power;
        _log = log;
        _settings = settings;
    }

    public void Start()
    {
        _timer = new System.Threading.Timer(_ => Tick(), null,
            TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(15));
    }

    private void Tick()
    {
        try
        {
            var transition = _engine.Tick(GetIdleTime(), _settings.Current.IdleSaver, IsSuppressed());
            switch (transition)
            {
                case IdleTransition.EnterPowerSaver:
                    if (_power.ActivatePowerSaver())
                        _log.Info("IdleSaver",
                            $"No input for {_settings.Current.IdleSaver.IdleMinutes} minutes — switched to Power Saver.");
                    break;
                case IdleTransition.RestorePreviousPlan:
                    if (_power.RestorePreviousPlan())
                        _log.Info("IdleSaver", "Input detected — restored the previous power plan.");
                    break;
            }
        }
        catch (Exception ex)
        {
            _log.Error("IdleSaver", $"Idle check failed: {ex.Message}");
        }
    }

    private static TimeSpan GetIdleTime()
    {
        var info = new NativeMethods.LASTINPUTINFO
        {
            Size = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.LASTINPUTINFO>(),
        };
        if (!NativeMethods.GetLastInputInfo(ref info))
            return TimeSpan.Zero;

        // Unsigned math survives the 49.7-day tick wraparound.
        uint elapsed = (uint)Environment.TickCount - info.Time;
        return TimeSpan.FromMilliseconds(elapsed);
    }

    public void Dispose() => _timer?.Dispose();
}
