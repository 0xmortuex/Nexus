namespace Nexus.Core.Suggestions;

public enum SuggestionKind
{
    /// <summary>Apply a tweak from the catalog (TargetId = tweak id).</summary>
    ApplyTweak,
    /// <summary>Disable a service from the debloat list (TargetId = service name).</summary>
    DisableService,
    /// <summary>Disable a scheduled task (TargetId = task path).</summary>
    DisableTask,
    /// <summary>Enable a Nexus feature (TargetId = feature key, e.g. "probalance").</summary>
    EnableFeature,
    /// <summary>Informational only — no Apply button.</summary>
    Hint,
}

public sealed record Suggestion(
    string Id,
    string Title,
    /// <summary>Why this is suggested, referencing the observed state — no hype.</summary>
    string Reason,
    SuggestionKind Kind,
    string TargetId);

/// <summary>Everything the engine needs to know about the machine's CURRENT state.
/// Collected by the App layer from the registry/services/settings; kept as a plain
/// record so the decision logic is unit-testable off-Windows.</summary>
public sealed record SystemFacts
{
    public bool GameDvrCaptureEnabled { get; init; }
    public bool MouseAccelerationEnabled { get; init; }
    public bool WindowsGameModeEnabled { get; init; }
    public bool StickyKeysShortcutEnabled { get; init; }
    public bool DiagTrackEnabled { get; init; }
    public bool CompatAppraiserTaskEnabled { get; init; }
    public bool ProBalanceEnabled { get; init; }
    public bool GameModeEnabled { get; init; }
    public bool IsHybridCpu { get; init; }
    public int GameProfileCount { get; init; }
    public bool NexusPerformancePlanExists { get; init; }

    // ---- Observed hardware state, from the measurement layer ----

    /// <summary>The processor is being held below its rated speed by the power plan.
    /// Unlike everything else here, this is a measurement rather than a setting, and
    /// it usually matters more than any tweak on the list.</summary>
    public bool ThrottledByPowerPlan { get; init; }

    /// <summary>The processor is being held down by the firmware — heat, power
    /// delivery, or a vendor policy. Nothing in this app can raise it.</summary>
    public bool ThrottledByFirmware { get; init; }

    /// <summary>The enforced ceiling as a percentage of rated speed, when throttled.</summary>
    public int ThrottleCeilingPercent { get; init; } = 100;

    // ---- Observed security state ----

    /// <summary>Microsoft Defender's real-time protection is switched off.</summary>
    public bool DefenderRealTimeOff { get; init; }

    /// <summary>Defender has an exclusion broad enough to be a hole.</summary>
    public bool DefenderHasBroadExclusion { get; init; }
}

/// <summary>
/// Hone-style "suggested optimizations", the honest version: each suggestion is
/// derived from observed system state, states its reason, and routes to a change
/// that is already reversible elsewhere in the app (tweaks back up + undo,
/// services disable-only). Nothing here auto-applies.
/// </summary>
public static class SuggestionEngine
{
    public static IReadOnlyList<Suggestion> Evaluate(SystemFacts facts)
    {
        var suggestions = new List<Suggestion>();

        // Hardware limits come first. A machine capped at 40% of its rated clock will
        // not be fixed by anything further down this list, and burying that under six
        // registry tweaks would be the same dishonesty as promising FPS.
        if (facts.ThrottledByPowerPlan)
            suggestions.Add(new Suggestion(
                "sug-throttle-power-plan",
                "Your power plan is capping the processor",
                $"The CPU is limited to {facts.ThrottleCeilingPercent}% of its rated speed by the active " +
                "power plan. No tweak below will matter as much as lifting this, and it is a settings " +
                "change rather than a hardware limit.",
                SuggestionKind.EnableFeature, "perfplan"));

        if (facts.ThrottledByFirmware)
            suggestions.Add(new Suggestion(
                "sug-throttle-firmware",
                "Something outside Windows is capping the processor",
                $"The CPU is being held at {facts.ThrottleCeilingPercent}% of its rated speed by the " +
                "firmware — usually heat, power delivery, or a vendor setting. Nexus cannot raise it, and " +
                "no optimizer can: check cooling, the power adapter, and the BIOS.",
                SuggestionKind.Hint, ""));

        // Security next, for the same reason: a machine with its protection switched
        // off has a bigger problem than an un-tweaked registry.
        if (facts.DefenderRealTimeOff)
            suggestions.Add(new Suggestion(
                "sug-defender-off",
                "Turn Microsoft Defender's real-time protection back on",
                "Real-time protection is off. Nexus only reports on what it finds — Defender is what " +
                "actually stops things — so nothing on this machine is currently being blocked.",
                SuggestionKind.Hint, ""));

        if (facts.DefenderHasBroadExclusion)
            suggestions.Add(new Suggestion(
                "sug-defender-exclusion",
                "Review Microsoft Defender's exclusions",
                "Defender has been told to ignore a whole drive or user folder. That turns protection " +
                "off for everything inside it, and adding one is a standard step for malware that wants " +
                "to stay. Check the Security tab for the details.",
                SuggestionKind.Hint, ""));

        if (facts.GameDvrCaptureEnabled)
            suggestions.Add(new Suggestion(
                "sug-gamedvr",
                "Turn off GameDVR background capture",
                "Background clip recording is currently enabled; it costs GPU/CPU while you play even if you never save clips.",
                SuggestionKind.ApplyTweak, "gamedvr-off"));

        if (facts.MouseAccelerationEnabled)
            suggestions.Add(new Suggestion(
                "sug-mouse-accel",
                "Disable mouse acceleration",
                "\"Enhance pointer precision\" is on, so the same hand movement travels different distances depending on speed — bad for aim consistency.",
                SuggestionKind.ApplyTweak, "mouse-accel-off"));

        if (!facts.WindowsGameModeEnabled)
            suggestions.Add(new Suggestion(
                "sug-win-game-mode",
                "Turn Windows Game Mode on",
                "Windows' built-in Game Mode is off; on modern builds it is neutral-to-mildly-positive and lets Windows defer background work during play.",
                SuggestionKind.ApplyTweak, "windows-game-mode-on"));

        if (facts.StickyKeysShortcutEnabled)
            suggestions.Add(new Suggestion(
                "sug-sticky-keys",
                "Disable the Sticky Keys shortcut",
                "Tapping Shift five times mid-game currently pops the Sticky Keys prompt over your game.",
                SuggestionKind.ApplyTweak, "sticky-keys-off"));

        if (facts.DiagTrackEnabled)
            suggestions.Add(new Suggestion(
                "sug-diagtrack",
                "Disable the telemetry service (DiagTrack)",
                "The Connected User Experiences and Telemetry service is running; disabling stops periodic data collection and uploads. Fully reversible.",
                SuggestionKind.DisableService, "DiagTrack"));

        if (facts.CompatAppraiserTaskEnabled)
            suggestions.Add(new Suggestion(
                "sug-appraiser",
                "Disable the Compatibility Appraiser task",
                "This scheduled telemetry scan is a known cause of periodic disk/CPU spikes. Fully reversible.",
                SuggestionKind.DisableTask,
                @"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"));

        if (!facts.ProBalanceEnabled)
            suggestions.Add(new Suggestion(
                "sug-probalance",
                "Turn ProBalance on",
                "Dynamic restraint is off, so a runaway background process can currently starve your foreground app under load.",
                SuggestionKind.EnableFeature, "probalance"));

        if (!facts.GameModeEnabled)
            suggestions.Add(new Suggestion(
                "sug-game-mode",
                "Turn Nexus Game Mode on",
                "Game Mode is off, so games are not auto-boosted (priority, core pinning, power plan) when they launch.",
                SuggestionKind.EnableFeature, "gamemode"));

        if (facts.IsHybridCpu && facts.GameProfileCount == 0)
            suggestions.Add(new Suggestion(
                "sug-hybrid-games",
                "Add your games to the game list",
                "This CPU has P-cores and E-cores. Adding your games lets Nexus pin them to P-cores automatically — the highest-value action on hybrid CPUs.",
                SuggestionKind.Hint, ""));

        if (!facts.NexusPerformancePlanExists)
            suggestions.Add(new Suggestion(
                "sug-perf-plan",
                "Create the performance power plan",
                "No Nexus Performance plan exists yet; Game Mode will create it on first use, or create it now from the tray so the first game launch doesn't wait on powercfg.",
                SuggestionKind.EnableFeature, "perfplan"));

        return suggestions;
    }
}
