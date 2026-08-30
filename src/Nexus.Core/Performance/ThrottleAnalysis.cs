namespace Nexus.Core.Performance;

/// <summary>One core's power state, as reported by the OS.</summary>
/// <param name="MaxMhz">The processor's rated maximum.</param>
/// <param name="CurrentMhz">What it is running at right now.</param>
/// <param name="MhzLimit">The ceiling currently being enforced. Below
/// <paramref name="MaxMhz"/> means something is holding the processor down.</param>
public sealed record CoreFrequency(int Number, int MaxMhz, int CurrentMhz, int MhzLimit);

public enum ThrottleCause
{
    None,

    /// <summary>The active power plan caps the maximum processor state.</summary>
    PowerPlan,

    /// <summary>The firmware is enforcing a ceiling below the rated maximum —
    /// thermal, power-delivery, or a vendor policy.</summary>
    FirmwareOrThermal,
}

/// <summary>What the frequency readings mean, in terms a user can act on.</summary>
public sealed record ThrottleFinding
{
    public required ThrottleCause Cause { get; init; }
    public required string Summary { get; init; }

    /// <summary>Enforced ceiling as a percentage of the rated maximum.</summary>
    public required int CeilingPercent { get; init; }

    /// <summary>Current speed as a percentage of the rated maximum.</summary>
    public required int CurrentPercent { get; init; }

    public required int MaxMhz { get; init; }
    public required int CeilingMhz { get; init; }
    public required int CurrentMhz { get; init; }

    /// <summary>True when Nexus can plausibly do something about it.</summary>
    public required bool ActionableInSoftware { get; init; }
}

/// <summary>
/// Works out whether the processor is being held below its rated speed, and — more
/// usefully — whether that is something software can fix.
///
/// This exists because the most common "my games stutter" cause is not a registry
/// tweak away. A laptop sitting at 40% of its rated clock because it is hot, or a
/// desktop capped by a power plan nobody remembers setting, will not be fixed by
/// anything in the Tweaks tab. Telling the user that plainly is worth more than
/// another toggle, and it is the difference between an optimizer and a placebo.
///
/// The distinction that matters:
/// - A ceiling Windows is enforcing (power plan) — Nexus can change that.
/// - A ceiling the firmware is enforcing (heat, power delivery, vendor policy) —
///   Nexus cannot, and should say so rather than implying otherwise.
/// </summary>
public static class ThrottleAnalysis
{
    /// <summary>A ceiling within this much of the maximum is just measurement slack
    /// and boost behaviour, not a throttle.</summary>
    public const int CeilingTolerancePercent = 5;

    /// <summary>Below this, the machine is meaningfully slower than it should be.</summary>
    public const int SignificantThrottlePercent = 85;

    /// <summary>
    /// Analyse the reported core frequencies.
    /// </summary>
    /// <param name="cores">One entry per logical processor.</param>
    /// <param name="powerPlanMaxPercent">The active power plan's maximum processor
    /// state, if known. When this matches the observed ceiling, the power plan is the
    /// cause and the fix is in software.</param>
    public static ThrottleFinding? Analyse(
        IReadOnlyList<CoreFrequency> cores, int? powerPlanMaxPercent = null)
    {
        if (cores.Count == 0)
            return null;

        // The rated maximum is a property of the part, so take the highest reported;
        // hybrid CPUs report different maxima for P- and E-cores.
        int maxMhz = cores.Max(c => c.MaxMhz);
        if (maxMhz <= 0)
            return null;

        // The binding ceiling is the lowest one being enforced on any core that has
        // one, because that is the core that will hold back a pinned game thread.
        int ceilingMhz = cores.Where(c => c.MhzLimit > 0).Select(c => c.MhzLimit).DefaultIfEmpty(maxMhz).Min();
        int currentMhz = cores.Max(c => c.CurrentMhz);

        int ceilingPercent = (int)Math.Round(ceilingMhz * 100.0 / maxMhz);
        int currentPercent = (int)Math.Round(currentMhz * 100.0 / maxMhz);

        if (ceilingPercent >= 100 - CeilingTolerancePercent)
            return null; // nothing is holding it down

        bool causedByPowerPlan = powerPlanMaxPercent is { } planned
                                 && Math.Abs(planned - ceilingPercent) <= CeilingTolerancePercent;

        var cause = causedByPowerPlan ? ThrottleCause.PowerPlan : ThrottleCause.FirmwareOrThermal;

        return new ThrottleFinding
        {
            Cause = cause,
            CeilingPercent = ceilingPercent,
            CurrentPercent = currentPercent,
            MaxMhz = maxMhz,
            CeilingMhz = ceilingMhz,
            CurrentMhz = currentMhz,
            ActionableInSoftware = causedByPowerPlan,
            Summary = Describe(cause, ceilingPercent, maxMhz, ceilingMhz),
        };
    }

    private static string Describe(ThrottleCause cause, int ceilingPercent, int maxMhz, int ceilingMhz)
    {
        string severity = ceilingPercent < SignificantThrottlePercent
            ? "well below"
            : "slightly below";

        return cause switch
        {
            ThrottleCause.PowerPlan =>
                $"Your power plan caps the processor at {ceilingPercent}% " +
                $"({ceilingMhz} MHz of {maxMhz} MHz), which is {severity} what the chip can do. " +
                "This one is fixable: switch to the Nexus performance plan, or raise the maximum " +
                "processor state in Windows power options.",

            ThrottleCause.FirmwareOrThermal =>
                $"The processor is being held at {ceilingPercent}% " +
                $"({ceilingMhz} MHz of {maxMhz} MHz) by the firmware, not by Windows. That usually " +
                "means heat, a power-delivery limit, or a vendor setting. No software tweak will " +
                "raise it — check cooling, the power adapter, and the BIOS before blaming Windows.",

            _ => "The processor is running at its rated speed.",
        };
    }
}
