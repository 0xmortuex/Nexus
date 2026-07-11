namespace Nexus.Core.Advisor;

/// <summary>Honest average impact of an optimization for its stated purpose.
/// This is an editorial judgement, not a benchmark — the point is to stop users
/// applying situational tweaks expecting miracles.</summary>
public enum Effectiveness
{
    /// <summary>Helps only in specific setups; often zero effect. (1 bar)</summary>
    Situational = 1,
    /// <summary>Small but real, or quality-of-life. (2 bars)</summary>
    Minor = 2,
    /// <summary>Noticeable on most systems for its purpose. (3 bars)</summary>
    Moderate = 3,
    /// <summary>Consistently worthwhile; low downside. (4 bars)</summary>
    Strong = 4,
}

/// <summary>What an optimization actually affects — separate from raw "performance".</summary>
public enum ImpactArea
{
    InputLatency,
    FrameConsistency,
    AverageFps,
    Responsiveness,
    Memory,
    NetworkLatency,
    Privacy,
    DiskSpace,
    PowerAndHeat,
}

/// <summary>
/// The honest information layer behind every meter and rating: for each setting
/// (tweak OR feature) its effectiveness, what it affects, and its real pros/cons.
/// Keyed by the same id the tweak catalog / settings use.
/// </summary>
public sealed record OptimizationInfo(
    string Id,
    string Name,
    ImpactArea Impact,
    Effectiveness Effectiveness,
    IReadOnlyList<string> Pros,
    IReadOnlyList<string> Cons);

public static class OptimizationCatalog
{
    private static readonly Dictionary<string, OptimizationInfo> ById;

    public static IReadOnlyCollection<OptimizationInfo> All => ById.Values;

    public static OptimizationInfo? Find(string id) => ById.GetValueOrDefault(id);

    /// <summary>Effectiveness for an id, defaulting to Minor when unknown.</summary>
    public static Effectiveness EffectivenessOf(string id)
        => ById.TryGetValue(id, out var info) ? info.Effectiveness : Effectiveness.Minor;

    private static OptimizationInfo I(string id, string name, ImpactArea impact, Effectiveness eff,
        string[] pros, string[] cons) => new(id, name, impact, eff, pros, cons);

    static OptimizationCatalog()
    {
        var list = new[]
        {
            // ---------- Features ----------
            I("probalance", "ProBalance dynamic restraint", ImpactArea.Responsiveness, Effectiveness.Strong,
                ["Keeps the foreground app smooth when a background process spikes the CPU",
                 "Fully automatic, reverses itself, low overhead"],
                ["No effect when the CPU isn't under load",
                 "A mis-tuned background app can be briefly slowed"]),
            I("gamemode", "Nexus Game Mode", ImpactArea.FrameConsistency, Effectiveness.Strong,
                ["One switch applies priority, core pinning and power plan when a game launches",
                 "Full revert on exit or crash"],
                ["Auto-detection can misfire on borderless non-games (fixable via the ignore list)"]),
            I("foregroundboost", "Foreground boosting", ImpactArea.Responsiveness, Effectiveness.Minor,
                ["The app you're actively using gets a small scheduler edge"],
                ["Marginal on a fast CPU", "Only affects Normal-priority apps"]),
            I("cpulimiter", "CPU limiter (hard cap)", ImpactArea.PowerAndHeat, Effectiveness.Moderate,
                ["Caps a runaway or background app's CPU to control heat/fan noise",
                 "Kernel-enforced, no suspend/resume risk"],
                ["Slows the capped app by design", "Not a performance gain for the capped process"]),
            I("timerres", "High timer resolution (0.5 ms)", ImpactArea.InputLatency, Effectiveness.Situational,
                ["Can help apps that sleep on coarse timers"],
                ["Since Win10 2004 it's per-process, so system-wide benefit is small",
                 "Slightly higher power draw"]),
            I("standby", "Standby-list purge", ImpactArea.FrameConsistency, Effectiveness.Situational,
                ["Frees cached RAM before a game needs a big allocation, avoiding a stall"],
                ["Windows reuses standby pages on demand anyway", "Over-purging causes extra disk reads"]),
            I("smarttrim", "SmartTrim working-set trimming", ImpactArea.Memory, Effectiveness.Minor,
                ["Reclaims RAM from idle background apps"],
                ["Trimmed pages fault back in on next use — don't trim active apps"]),
            I("idlesaver", "IdleSaver", ImpactArea.PowerAndHeat, Effectiveness.Minor,
                ["Drops to Power Saver when you step away; saves energy/heat"],
                ["No performance benefit; purely a power feature"]),
            I("keepawake", "Keep Awake", ImpactArea.Responsiveness, Effectiveness.Minor,
                ["Stops sleep/display-off during downloads, installs or media"],
                ["Wastes power if left on", "Not a performance feature"]),
            I("dns", "Low-latency DNS", ImpactArea.NetworkLatency, Effectiveness.Minor,
                ["Faster name lookups; the benchmark shows real numbers for your line"],
                ["Does not change in-game ping or bandwidth", "Gain is milliseconds, once per lookup"]),
            I("performanceplan", "Performance power plan", ImpactArea.FrameConsistency, Effectiveness.Moderate,
                ["Disables core parking and holds clocks high, cutting spiky micro-stutter"],
                ["Higher idle power and heat", "Little benefit on desktops already at High Performance"]),

            // ---------- Tweaks ----------
            I("priosep-gaming-short", "Win32PrioritySeparation 0x26 (gaming)", ImpactArea.FrameConsistency, Effectiveness.Minor,
                ["Short foreground-boosted quanta can smooth frame pacing"],
                ["Can reduce background throughput", "Effect is subtle and system-dependent"]),
            I("priosep-throughput", "Win32PrioritySeparation 0x2A (throughput)", ImpactArea.AverageFps, Effectiveness.Minor,
                ["Longer quanta, fewer context switches — marginally higher average FPS"],
                ["Very slightly higher input latency"]),
            I("priosep-balanced", "Win32PrioritySeparation default", ImpactArea.Responsiveness, Effectiveness.Situational,
                ["Restores stock behaviour for A/B testing"], ["Not an optimization itself"]),
            I("priosep-long-fixed", "Win32PrioritySeparation 0x18 (long fixed)", ImpactArea.AverageFps, Effectiveness.Situational,
                ["Server-style long quanta for batch throughput"], ["Worse input responsiveness; niche"]),
            I("gamedvr-off", "GameDVR / Game Bar capture off", ImpactArea.FrameConsistency, Effectiveness.Moderate,
                ["Stops a background recorder that steals GPU/CPU during play"],
                ["No effect if capture was already idle", "Loses one-tap clip recording"]),
            I("hags-on", "Hardware GPU scheduling ON", ImpactArea.InputLatency, Effectiveness.Situational,
                ["Can lower latency on modern GPUs/drivers"],
                ["On some drivers it adds stutter instead", "Reboot required — test both ways"]),
            I("hags-off", "Hardware GPU scheduling OFF", ImpactArea.FrameConsistency, Effectiveness.Situational,
                ["Fixes stutter caused by HAGS on some setups"], ["May raise latency on others; test"]),
            I("mouse-accel-off", "Mouse acceleration off", ImpactArea.InputLatency, Effectiveness.Strong,
                ["Same hand movement = same cursor distance every time — real aim consistency"],
                ["Muscle memory adjustment if you were used to acceleration", "Zero FPS change"]),
            I("nagle-off", "Nagle's algorithm off", ImpactArea.NetworkLatency, Effectiveness.Situational,
                ["Sends small packets immediately instead of coalescing them"],
                ["Most modern games already set TCP_NODELAY or use UDP — often no effect"]),
            I("network-throttling-off", "Network throttling index off", ImpactArea.NetworkLatency, Effectiveness.Situational,
                ["Removes the multimedia packet cap; helps heavy streaming while gaming"],
                ["Negligible for normal play"]),
            I("mmcss-gaming", "MMCSS Games profile tuning", ImpactArea.FrameConsistency, Effectiveness.Minor,
                ["Raises the scheduler class for game threads"], ["Subtle at best on modern Windows"]),
            I("mmcss-responsiveness-max", "MMCSS SystemResponsiveness 0", ImpactArea.AverageFps, Effectiveness.Minor,
                ["Gives the foreground all CPU instead of reserving 20% for background"],
                ["Can starve recording/chat/streaming running alongside the game"]),
            I("gpu-preemption-off", "GPU preemption off", ImpactArea.FrameConsistency, Effectiveness.Situational,
                ["Stops the GPU switching away from a render job for background graphics"],
                ["Can cause hangs on some drivers", "Reboot required"]),
            I("prefetch-superfetch-off", "Prefetch / SuperFetch off", ImpactArea.Responsiveness, Effectiveness.Situational,
                ["Removes predictive background disk I/O on fast NVMe"],
                ["HELPS on mechanical HDDs — do not apply there", "Slightly slower cold app starts"]),
            I("core-parking-unhide", "Unhide core-parking slider", ImpactArea.FrameConsistency, Effectiveness.Minor,
                ["Lets you set min-cores to 100% manually"],
                ["Just reveals a control; the Performance plan already disables parking"]),
            I("windows-game-mode-on", "Windows Game Mode on", ImpactArea.FrameConsistency, Effectiveness.Minor,
                ["Lets Windows defer background work during play"], ["Neutral-to-small on most builds"]),
            I("fse-optimizations-off", "Fullscreen optimizations off", ImpactArea.InputLatency, Effectiveness.Situational,
                ["Forces classic exclusive fullscreen for games that honor it"],
                ["Modern optimized path is often equal or better — test per game", "Can break alt-tab"]),
            I("power-throttling-off", "Global power throttling off", ImpactArea.AverageFps, Effectiveness.Minor,
                ["Stops Windows EcoQoS-throttling foreground work"], ["Costs battery on laptops"]),
            I("sticky-keys-off", "Sticky Keys shortcut off", ImpactArea.Responsiveness, Effectiveness.Minor,
                ["No more Sticky Keys popup interrupting a game on repeated Shift"], ["None to speak of"]),
            I("visual-effects-performance", "Visual effects: performance", ImpactArea.Responsiveness, Effectiveness.Minor,
                ["Snappier desktop on weak iGPUs/old machines"], ["Imperceptible on gaming hardware; less pretty"]),
            I("transparency-off", "Transparency off", ImpactArea.Responsiveness, Effectiveness.Situational,
                ["Removes acrylic/blur compositing cost"], ["Tiny; mostly a preference"]),
            I("animations-off", "Window animations off", ImpactArea.Responsiveness, Effectiveness.Minor,
                ["Desktop feels instant — no animation waits"], ["No effect on in-game FPS"]),
            I("hibernation-off", "Hibernation off", ImpactArea.DiskSpace, Effectiveness.Minor,
                ["Frees several GB of hiberfil.sys; disables Fast Startup quirks"],
                ["Lose hibernate + Fast Startup", "No runtime performance change"]),
        };

        ById = list.ToDictionary(i => i.Id, StringComparer.Ordinal);
    }
}
