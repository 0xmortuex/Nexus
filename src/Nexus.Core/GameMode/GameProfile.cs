using Nexus.Core.Models;

namespace Nexus.Core.GameMode;

/// <summary>Per-game overrides, persisted in games.json. A default profile is used
/// for auto-detected games that have no saved profile yet.</summary>
public sealed record GameProfile
{
    public required string ExeName { get; set; }
    public bool Enabled { get; set; } = true;

    public ProcessPriority Priority { get; set; } = ProcessPriority.High;

    /// <summary>P-cores on hybrid CPUs; on homogeneous CPUs PCoresOnly resolves to
    /// all cores, so PhysicalCoresOnly is the interesting alternative there.</summary>
    public CpuAffinityMode Pinning { get; set; } = CpuAffinityMode.PCoresOnly;

    /// <summary>Soft CPU sets (default) vs hard affinity mask. Hard pinning can trip
    /// some anti-cheat integrity checks; CPU sets are safer.</summary>
    public bool UseCpuSets { get; set; } = true;

    /// <summary>Demote background CPU hogs to BelowNormal + efficiency mode.</summary>
    public bool DemoteBackgroundHogs { get; set; } = true;

    public bool UsePerformancePowerPlan { get; set; } = true;

    /// <summary>Stop wuauserv while playing; resumed on exit/crash recovery.</summary>
    public bool PauseWindowsUpdate { get; set; }

    public string NormalizedName => ProcessRule.Normalize(ExeName);
}

public sealed record GameModeOptions
{
    public bool Enabled { get; set; } = true;
    /// <summary>Detect fullscreen/borderless games automatically (vs user list only).</summary>
    public bool AutoDetect { get; set; } = true;
    /// <summary>Background process CPU% above which it is demoted during a game.</summary>
    public double HogCpuThresholdPct { get; set; } = 10;
    /// <summary>Exes the detector must never treat as games.</summary>
    public IReadOnlyList<string> IgnoredProcesses { get; set; } = [];
}
