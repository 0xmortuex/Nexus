namespace Nexus.Core.Models;

/// <summary>Priority classes mirroring the Win32 priority class constants.</summary>
public enum ProcessPriority
{
    Idle,
    BelowNormal,
    Normal,
    AboveNormal,
    High,
    RealTime,
}

/// <summary>IO priority hints accepted by NtSetInformationProcess(ProcessIoPriority).
/// Values above Normal require special privileges and are intentionally not exposed.</summary>
public enum IoPriorityLevel
{
    VeryLow = 0,
    Low = 1,
    Normal = 2,
}

/// <summary>Memory (page) priority accepted by SetProcessInformation(ProcessMemoryPriority).</summary>
public enum MemoryPriorityLevel
{
    VeryLow = 1,
    Low = 2,
    Medium = 3,
    BelowNormal = 4,
    Normal = 5,
}

/// <summary>How a rule constrains which CPUs a process may run on.</summary>
public enum CpuAffinityMode
{
    None,
    /// <summary>Performance cores only (hybrid CPUs; on homogeneous CPUs this is all cores).</summary>
    PCoresOnly,
    /// <summary>Efficiency cores only (no-op on homogeneous CPUs).</summary>
    ECoresOnly,
    /// <summary>One logical processor per physical core (avoids SMT sibling contention).</summary>
    PhysicalCoresOnly,
    /// <summary>User-supplied affinity mask.</summary>
    CustomMask,
}

/// <summary>
/// A persistent per-executable rule. Applied every time a process with a matching
/// image name starts. Null members mean "leave that setting alone".
/// </summary>
public sealed record ProcessRule
{
    /// <summary>Image name including extension, e.g. "game.exe". Compared case-insensitively.</summary>
    public required string ExeName { get; set; }

    public bool Enabled { get; set; } = true;

    public ProcessPriority? Priority { get; set; }

    public CpuAffinityMode AffinityMode { get; set; } = CpuAffinityMode.None;

    /// <summary>Only used when <see cref="AffinityMode"/> is CustomMask.</summary>
    public ulong? CustomAffinityMask { get; set; }

    /// <summary>
    /// When true, core restrictions are applied as CPU sets (a soft preference the
    /// scheduler may override for system work); when false, as a hard affinity mask.
    /// </summary>
    public bool UseCpuSets { get; set; } = true;

    public IoPriorityLevel? IoPriority { get; set; }

    public MemoryPriorityLevel? MemoryPriority { get; set; }

    /// <summary>true = enable EcoQoS (efficiency mode), false = force off, null = OS default.</summary>
    public bool? EfficiencyMode { get; set; }

    /// <summary>Trim the working set once when the rule is applied.</summary>
    public bool TrimWorkingSetOnStart { get; set; }

    /// <summary>Hard CPU cap (1–99 % of total CPU) enforced by a Job Object.</summary>
    public int? CpuLimitPct { get; set; }

    /// <summary>Block system/display sleep while any instance of this exe runs.</summary>
    public bool KeepAwakeWhileRunning { get; set; }

    /// <summary>Relaunch the exe if it exits (crash-loop guarded; skipped when Nexus
    /// itself terminated it via disallowed/instance-limit/watchdog rules).</summary>
    public bool RestartIfExited { get; set; }

    public string NormalizedName => Normalize(ExeName);

    public static string Normalize(string exeName)
    {
        var name = exeName.Trim();
        if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            name += ".exe";
        return name.ToLowerInvariant();
    }
}
