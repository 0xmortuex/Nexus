using Nexus.Core.Models;

namespace Nexus.Core.Enforcement;

public enum WatchdogActionKind
{
    LowerPriority,
    TrimWorkingSet,
    Restart,
    Kill,
}

/// <summary>Per-exe resource watchdog: if the process exceeds a CPU% or RAM threshold
/// (OR, when both set) for the configured duration, fire the chosen action.</summary>
public sealed record WatchdogRule
{
    public required string ExeName { get; set; }
    public bool Enabled { get; set; } = true;
    public double? CpuAbovePct { get; set; }
    public long? WorkingSetAboveBytes { get; set; }
    public int ForSeconds { get; set; } = 10;
    public WatchdogActionKind Action { get; set; } = WatchdogActionKind.LowerPriority;
    /// <summary>After firing, leave the process alone this long before re-arming.</summary>
    public int CooldownSeconds { get; set; } = 60;

    public string NormalizedName => ProcessRule.Normalize(ExeName);
}

public sealed record WatchdogTrigger(int Pid, string ExeName, WatchdogRule Rule, string Reason);

/// <summary>Pure state machine: tracks how long each matching process has been over
/// its rule's thresholds and emits a trigger once per breach (with cooldown).</summary>
public sealed class WatchdogEngine
{
    private readonly Dictionary<(string Rule, int Pid), DateTimeOffset> _overSince = new();
    private readonly Dictionary<(string Rule, int Pid), DateTimeOffset> _cooldownUntil = new();

    public IReadOnlyList<WatchdogTrigger> Tick(
        SystemSnapshot snapshot, IReadOnlyList<WatchdogRule> rules, DateTimeOffset now)
    {
        var triggers = new List<WatchdogTrigger>();
        var liveKeys = new HashSet<(string, int)>();

        foreach (var rule in rules)
        {
            if (!rule.Enabled || (rule.CpuAbovePct is null && rule.WorkingSetAboveBytes is null))
                continue;

            var ruleName = rule.NormalizedName;
            foreach (var proc in snapshot.Processes)
            {
                if (!string.Equals(ProcessRule.Normalize(proc.ExeName), ruleName, StringComparison.Ordinal))
                    continue;

                var key = (ruleName, proc.Pid);
                liveKeys.Add(key);

                bool cpuOver = rule.CpuAbovePct is { } cpu && proc.CpuPct > cpu;
                bool ramOver = rule.WorkingSetAboveBytes is { } ram && proc.WorkingSetBytes > ram;

                if (!cpuOver && !ramOver)
                {
                    _overSince.Remove(key);
                    continue;
                }

                if (_cooldownUntil.TryGetValue(key, out var until))
                {
                    if (now < until)
                        continue;
                    _cooldownUntil.Remove(key);
                }

                if (!_overSince.TryGetValue(key, out var since))
                    _overSince[key] = since = now;

                if ((now - since).TotalSeconds >= rule.ForSeconds)
                {
                    _overSince.Remove(key);
                    _cooldownUntil[key] = now.AddSeconds(rule.CooldownSeconds);

                    var reason = cpuOver
                        ? $"CPU {proc.CpuPct:F0}% above {rule.CpuAbovePct:F0}% for {rule.ForSeconds}s"
                        : $"RAM {proc.WorkingSetBytes / (1024 * 1024)} MB above {rule.WorkingSetAboveBytes / (1024 * 1024)} MB for {rule.ForSeconds}s";
                    triggers.Add(new WatchdogTrigger(proc.Pid, proc.ExeName, rule, reason));
                }
            }
        }

        // Forget state for processes that exited.
        foreach (var key in _overSince.Keys.Where(k => !liveKeys.Contains(k)).ToArray())
            _overSince.Remove(key);
        foreach (var key in _cooldownUntil.Keys.Where(k => !liveKeys.Contains(k)).ToArray())
            _cooldownUntil.Remove(key);

        return triggers;
    }
}
