using Nexus.Core.Enforcement;
using Nexus.Core.GameMode;
using Nexus.Core.ProBalance;

namespace Nexus.Core.Models;

public sealed record EnforcementOptions
{
    public IReadOnlyList<WatchdogRule> WatchdogRules { get; init; } = [];
    public IReadOnlyList<InstanceLimit> InstanceLimits { get; init; } = [];
    /// <summary>Exe names terminated the instant they launch. Confirmed by the user
    /// when added in the UI; the service enforces without further prompts.</summary>
    public IReadOnlyList<string> DisallowedProcesses { get; init; } = [];
    /// <summary>Exe names whose running instances get their cores split evenly
    /// between them (Instance Balancer).</summary>
    public IReadOnlyList<string> BalancedProcesses { get; init; } = [];
}

public sealed record PowerOptions
{
    /// <summary>GUID of the Nexus Performance plan once created (cloned from Ultimate
    /// Performance with core parking disabled). Null until first activation.</summary>
    public string? PerformancePlanGuid { get; init; }
    /// <summary>Plan that was active before Nexus switched plans, for restore.</summary>
    public string? PreviousPlanGuid { get; init; }
}

public sealed record MemoryOptions
{
    /// <summary>Purge the standby list automatically when available memory drops
    /// below the threshold (ISLC-style). Off by default — Windows normally reuses
    /// standby pages on demand just fine.</summary>
    public bool AutoPurgeStandby { get; init; }
    public int FreeMemoryThresholdMb { get; init; } = 1024;
}

/// <summary>Root settings document (settings.json). Extended stage by stage.</summary>
public sealed record AppSettings
{
    public ProBalanceOptions ProBalance { get; init; } = new();
    public EnforcementOptions Enforcement { get; init; } = new();
    public IdleSaverOptions IdleSaver { get; init; } = new();
    public SmartTrimOptions SmartTrim { get; init; } = new();
    public PowerOptions Power { get; init; } = new();
    public GameModeOptions GameMode { get; init; } = new();
    public MemoryOptions Memory { get; init; } = new();
    /// <summary>Raise the foreground app to AboveNormal while it has focus.</summary>
    public bool ForegroundBoost { get; init; }
    /// <summary>Hold the finest system timer resolution (NtSetTimerResolution).</summary>
    public bool HighTimerResolution { get; init; }
}
