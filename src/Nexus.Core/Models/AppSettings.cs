using Nexus.Core.Enforcement;
using Nexus.Core.ProBalance;

namespace Nexus.Core.Models;

public sealed record EnforcementOptions
{
    public IReadOnlyList<WatchdogRule> WatchdogRules { get; init; } = [];
    public IReadOnlyList<InstanceLimit> InstanceLimits { get; init; } = [];
    /// <summary>Exe names terminated the instant they launch. Confirmed by the user
    /// when added in the UI; the service enforces without further prompts.</summary>
    public IReadOnlyList<string> DisallowedProcesses { get; init; } = [];
}

public sealed record PowerOptions
{
    /// <summary>GUID of the Nexus Performance plan once created (cloned from Ultimate
    /// Performance with core parking disabled). Null until first activation.</summary>
    public string? PerformancePlanGuid { get; init; }
    /// <summary>Plan that was active before Nexus switched plans, for restore.</summary>
    public string? PreviousPlanGuid { get; init; }
}

/// <summary>Root settings document (settings.json). Extended stage by stage.</summary>
public sealed record AppSettings
{
    public ProBalanceOptions ProBalance { get; init; } = new();
    public EnforcementOptions Enforcement { get; init; } = new();
    public IdleSaverOptions IdleSaver { get; init; } = new();
    public SmartTrimOptions SmartTrim { get; init; } = new();
    public PowerOptions Power { get; init; } = new();
}
