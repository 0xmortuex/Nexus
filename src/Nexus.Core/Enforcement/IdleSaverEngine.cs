namespace Nexus.Core.Enforcement;

public sealed record IdleSaverOptions
{
    public bool Enabled { get; set; }
    public int IdleMinutes { get; set; } = 10;
}

public enum IdleTransition
{
    /// <summary>User has been idle long enough — switch to the Power Saver plan.</summary>
    EnterPowerSaver,
    /// <summary>Input returned (or the feature was disabled/suppressed) — restore the previous plan.</summary>
    RestorePreviousPlan,
}

/// <summary>Pure state machine for IdleSaver. The host feeds it the current idle
/// duration; it answers with at most one transition.</summary>
public sealed class IdleSaverEngine
{
    public bool InPowerSaver { get; private set; }

    /// <param name="suppressed">True while a game is running or Performance Mode is
    /// forced — IdleSaver must never fight those.</param>
    public IdleTransition? Tick(TimeSpan idleTime, IdleSaverOptions options, bool suppressed)
    {
        if (InPowerSaver)
        {
            if (!options.Enabled || suppressed || idleTime.TotalMinutes < options.IdleMinutes)
            {
                InPowerSaver = false;
                return IdleTransition.RestorePreviousPlan;
            }
            return null;
        }

        if (options.Enabled && !suppressed && idleTime.TotalMinutes >= options.IdleMinutes)
        {
            InPowerSaver = true;
            return IdleTransition.EnterPowerSaver;
        }

        return null;
    }
}
