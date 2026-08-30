using Nexus.Core.Enforcement;
using Nexus.Core.GameMode;
using Nexus.Core.ProBalance;

namespace Nexus.Core.Models;

public sealed record EnforcementOptions
{
    private IReadOnlyList<WatchdogRule> _watchdogrules = [];
    public IReadOnlyList<WatchdogRule> WatchdogRules
    {
        get => _watchdogrules;
        set => _watchdogrules = value ?? [];
    }

    private IReadOnlyList<InstanceLimit> _instancelimits = [];
    public IReadOnlyList<InstanceLimit> InstanceLimits
    {
        get => _instancelimits;
        set => _instancelimits = value ?? [];
    }

    /// <summary>Exe names terminated the instant they launch. Confirmed by the user
    /// when added in the UI; the service enforces without further prompts.</summary>
    private IReadOnlyList<string> _disallowedprocesses = [];
    public IReadOnlyList<string> DisallowedProcesses
    {
        get => _disallowedprocesses;
        set => _disallowedprocesses = value ?? [];
    }

    /// <summary>Exe names whose running instances get their cores split evenly
    /// between them (Instance Balancer).</summary>
    private IReadOnlyList<string> _balancedprocesses = [];
    public IReadOnlyList<string> BalancedProcesses
    {
        get => _balancedprocesses;
        set => _balancedprocesses = value ?? [];
    }

}

public sealed record PowerOptions
{
    /// <summary>GUID of the Nexus Performance plan once created (cloned from Ultimate
    /// Performance with core parking disabled). Null until first activation.</summary>
    public string? PerformancePlanGuid { get; set; }
    /// <summary>Plan that was active before Nexus switched plans, for restore.</summary>
    public string? PreviousPlanGuid { get; set; }
}

public sealed record MemoryOptions
{
    /// <summary>Purge the standby list automatically when available memory drops
    /// below the threshold (ISLC-style). Off by default — Windows normally reuses
    /// standby pages on demand just fine.</summary>
    public bool AutoPurgeStandby { get; set; }
    public int FreeMemoryThresholdMb { get; set; } = 1024;
}

/// <summary>
/// What the security module is allowed to do.
///
/// Everything here is on by default and everything here can be turned off, because
/// two of these features are not passive: the ransomware watch writes real files into
/// the user's own folders, and behaviour monitoring runs a WMI query once a second.
/// A tool that puts files on your disk and watches your filesystem has to let you
/// say no, and a switch that only appears after you have already been opted in is
/// not really a switch.
/// </summary>
public sealed record SecurityOptions
{
    /// <summary>Watch process launches for suspicious command lines and masquerading.
    /// Costs a WMI event subscription polled once a second.</summary>
    public bool BehaviourMonitoring { get; set; } = true;

    /// <summary>Plant tripwire files and watch document folders for mass changes.
    /// This writes hidden files into Documents, Pictures, Videos, Music and Desktop.</summary>
    public bool RansomwareWatch { get; set; } = true;

    /// <summary>Scan new programs that appear in the Downloads folder.</summary>
    public bool ScanDownloads { get; set; } = true;

    /// <summary>Check Microsoft Defender's health at startup.</summary>
    public bool CheckDefenderHealth { get; set; } = true;

    /// <summary>Periodically re-check the folders where new files arrive. Never runs
    /// while a game is active.</summary>
    public bool ScheduledQuickScan { get; set; } = true;
}

/// <summary>Root settings document (settings.json). Extended stage by stage.</summary>
public sealed record AppSettings
{
    private SecurityOptions _security = new();
    public SecurityOptions Security
    {
        get => _security;
        set => _security = value ?? new();
    }


    private ProBalanceOptions _probalance = new();
    public ProBalanceOptions ProBalance
    {
        get => _probalance;
        set => _probalance = value ?? new();
    }

    private EnforcementOptions _enforcement = new();
    public EnforcementOptions Enforcement
    {
        get => _enforcement;
        set => _enforcement = value ?? new();
    }

    private IdleSaverOptions _idlesaver = new();
    public IdleSaverOptions IdleSaver
    {
        get => _idlesaver;
        set => _idlesaver = value ?? new();
    }

    private SmartTrimOptions _smarttrim = new();
    public SmartTrimOptions SmartTrim
    {
        get => _smarttrim;
        set => _smarttrim = value ?? new();
    }

    private PowerOptions _power = new();
    public PowerOptions Power
    {
        get => _power;
        set => _power = value ?? new();
    }

    private GameModeOptions _gamemode = new();
    public GameModeOptions GameMode
    {
        get => _gamemode;
        set => _gamemode = value ?? new();
    }

    private MemoryOptions _memory = new();
    public MemoryOptions Memory
    {
        get => _memory;
        set => _memory = value ?? new();
    }

    /// <summary>Raise the foreground app to AboveNormal while it has focus.</summary>
    public bool ForegroundBoost { get; set; }
    /// <summary>Hold the finest system timer resolution (NtSetTimerResolution).</summary>
    public bool HighTimerResolution { get; set; }
    /// <summary>Set once the first-run setup wizard has been completed or skipped.</summary>
    public bool WizardCompleted { get; set; }
    /// <summary>Advanced (Developer) mode: reveals the Processes list, the Latency &amp;
    /// Hardware tab and the deeper Tweaks sections. Off = the simple, guided app.</summary>
    public bool AdvancedMode { get; set; }
}
