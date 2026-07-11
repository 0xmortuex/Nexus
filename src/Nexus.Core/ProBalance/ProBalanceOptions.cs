namespace Nexus.Core.ProBalance;

/// <summary>Tunables for dynamic restraint. Persisted in settings.json.</summary>
public sealed record ProBalanceOptions
{
    public bool Enabled { get; init; } = true;

    /// <summary>Total CPU load (%) that must be sustained before restraint starts.</summary>
    public double SystemLoadEnterPct { get; init; } = 85;

    /// <summary>Total CPU load (%) below which the system counts as calm again.
    /// Kept well under the enter threshold so restraint doesn't flap.</summary>
    public double SystemLoadExitPct { get; init; } = 70;

    /// <summary>How long the load must stay above the enter threshold before acting (ms).</summary>
    public int SustainMs { get; init; } = 2000;

    /// <summary>How long the load must stay below the exit threshold before restoring (ms).</summary>
    public int ReleaseMs { get; init; } = 3000;

    /// <summary>Minimum time a process stays restrained even if load drops instantly (ms).
    /// Becoming the foreground app overrides this.</summary>
    public int MinRestraintMs { get; init; } = 5000;

    /// <summary>Per-process CPU share (%) above which a background process counts as a hog.</summary>
    public double ProcessCpuThresholdPct { get; init; } = 25;

    /// <summary>How long a process must stay above the per-process threshold (ms).</summary>
    public int ProcessSustainMs { get; init; } = 1000;

    /// <summary>Cap on simultaneously restrained processes.</summary>
    public int MaxRestrainedProcesses { get; init; } = 5;

    /// <summary>User-added exe names that must never be restrained.</summary>
    public IReadOnlyList<string> UserExclusions { get; init; } = [];
}
