using System.Diagnostics;
using System.ServiceProcess;
using Nexus.App.Interop;
using Nexus.Core;
using Nexus.Core.GameMode;
using Nexus.Core.Logging;
using Nexus.Core.Models;
using Nexus.Core.Persistence;

namespace Nexus.App.Services;

/// <summary>
/// Hone-style Game Mode. Watches the foreground window; when a game appears it
/// boosts the game (priority + core pinning), demotes background hogs
/// (BelowNormal + EcoQoS), switches to the performance power plan, and optionally
/// pauses Windows Update — journaling every change beforehand so both a normal
/// exit and a crash restore the machine exactly.
/// Game Mode ends when the game process exits (not when it merely loses focus).
/// </summary>
public sealed class GameModeService : IDisposable
{
    private readonly ForegroundMonitor _foreground;
    private readonly ProBalanceService _snapshots;
    private readonly GameProfileRepository _profiles;
    private readonly IntendedStateJournal _journal;
    private readonly ProcessApi _api;
    private readonly CpuTopologyProvider _topologyProvider;
    private readonly PowerPlanService _power;
    private readonly ActivityLog _log;
    private readonly SettingsService _settings;
    private readonly object _gate = new();

    private int _activeGamePid = -1;
    private string? _activeGameExe;

    public bool IsActive => _activeGamePid > 0;
    public string? ActiveGame => _activeGameExe;

    public event Action? StateChanged;

    public GameModeService(
        ForegroundMonitor foreground,
        ProBalanceService snapshots,
        GameProfileRepository profiles,
        IntendedStateJournal journal,
        ProcessApi api,
        CpuTopologyProvider topologyProvider,
        PowerPlanService power,
        ActivityLog log,
        SettingsService settings)
    {
        _foreground = foreground;
        _snapshots = snapshots;
        _profiles = profiles;
        _journal = journal;
        _api = api;
        _topologyProvider = topologyProvider;
        _power = power;
        _log = log;
        _settings = settings;
    }

    public void Start() => _foreground.Sampled += OnForegroundSampled;

    private void OnForegroundSampled(ForegroundSample? sample)
    {
        lock (_gate)
        {
            if (IsActive)
            {
                if (!IsProcessAlive(_activeGamePid))
                    ExitGameMode("the game exited");
                return;
            }

            var options = _settings.Current.GameMode;
            if (!options.Enabled || sample is null)
                return;

            var profile = _profiles.Find(sample.Window.ExeName);
            bool isListedGame = profile is not null;
            bool detected = isListedGame
                ? profile!.Enabled
                : options.AutoDetect && GameDetector.LooksLikeGame(
                    sample.Window, sample.MonitorRect,
                    _profiles.GameExeNames(), options.IgnoredProcesses);

            if (detected)
                EnterGameMode(sample.Pid, sample.Window.ExeName, profile ?? _profiles.FindOrDefault(sample.Window.ExeName));
        }
    }

    /// <summary>Manually start game mode for the current foreground process.</summary>
    public bool ForceForForeground()
    {
        var pid = ForegroundInfo.GetForegroundPid();
        if (pid is null)
            return false;
        try
        {
            using var process = Process.GetProcessById(pid.Value);
            var exe = process.ProcessName + ".exe";
            lock (_gate)
            {
                if (IsActive)
                    return false;
                EnterGameMode(pid.Value, exe, _profiles.FindOrDefault(exe));
            }
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    public void EndManually()
    {
        lock (_gate)
        {
            if (IsActive)
                ExitGameMode("ended manually");
        }
    }

    private void EnterGameMode(int pid, string exeName, GameProfile profile)
    {
        if (ProcessSafety.IsProtected(exeName))
            return;

        _activeGamePid = pid;
        _activeGameExe = ProcessRule.Normalize(exeName);
        _journal.SetActiveGame(_activeGameExe);
        _log.Info("GameMode", $"Game detected: {exeName} (PID {pid}). Entering Game Mode.");

        // Save the profile so the game shows up in the UI list from now on.
        if (_profiles.Find(exeName) is null)
            _profiles.Upsert(profile);

        // 1. Power plan (journal first — the journal write precedes every change).
        if (profile.UsePerformancePowerPlan)
        {
            var current = _power.GetActiveSchemeGuid();
            if (current is not null)
                _journal.RecordPreviousPowerPlan(current);
            if (_power.ActivatePerformanceMode())
                _log.Info("GameMode", "Switched to the Nexus Performance power plan.");
        }

        // 2. Boost the game itself.
        BoostGame(pid, exeName, profile);

        // 3. Demote background hogs.
        if (profile.DemoteBackgroundHogs)
            DemoteHogs(pid);

        // 4. Optionally pause Windows Update.
        if (profile.PauseWindowsUpdate)
            PauseWindowsUpdate();

        StateChanged?.Invoke();
    }

    private void BoostGame(int pid, string exeName, GameProfile profile)
    {
        _api.TryGetPriority(pid, out var originalPriority, out _);
        _api.TryGetAffinity(pid, out var originalAffinity, out _);
        _journal.RecordMutation(new ProcessMutationRecord(
            pid, exeName, originalPriority, originalAffinity,
            ClearCpuSets: profile.UseCpuSets, ResetEfficiencyMode: true));

        if (_api.TrySetPriority(pid, exeName, profile.Priority, out var error))
            _log.Info("GameMode", $"Set {exeName} to {profile.Priority} priority.");
        else
            _log.Warn("GameMode", $"Could not set game priority: {error}");

        // Make sure the game is not in efficiency mode.
        _api.TrySetEfficiencyMode(pid, exeName, false, out _);

        var topology = _topologyProvider.Topology;
        var pinning = profile.Pinning;
        if (pinning == CpuAffinityMode.PCoresOnly && !topology.IsHybrid)
            pinning = CpuAffinityMode.PhysicalCoresOnly; // sensible P-core equivalent on homogeneous CPUs

        if (pinning == CpuAffinityMode.None)
            return;

        if (profile.UseCpuSets && topology.CpuSetIdsFor(pinning) is { } ids)
        {
            if (_api.TrySetCpuSets(pid, exeName, ids, out error))
                _log.Info("GameMode", $"Pinned {exeName} to {pinning} via CPU sets ({ids.Count} CPUs).");
            else
                _log.Warn("GameMode", $"Could not apply CPU sets: {error}");
        }
        else if (topology.MaskFor(pinning) is { } mask)
        {
            if (_api.TrySetAffinity(pid, exeName, mask, out error))
                _log.Info("GameMode", $"Pinned {exeName} to {pinning} (mask 0x{mask:X}).");
            else
                _log.Warn("GameMode", $"Could not apply affinity: {error}");
        }
    }

    private void DemoteHogs(int gamePid)
    {
        var snapshot = _snapshots.LastSnapshot;
        if (snapshot is null)
            return;

        double threshold = _settings.Current.GameMode.HogCpuThresholdPct;
        foreach (var proc in snapshot.Processes)
        {
            if (proc.Pid <= 4
                || proc.Pid == gamePid
                || proc.Pid == Environment.ProcessId
                || proc.CpuPct < threshold
                || ProcessSafety.IsRestraintExempt(proc.ExeName))
                continue;

            _api.TryGetPriority(proc.Pid, out var original, out _);
            _journal.RecordMutation(new ProcessMutationRecord(
                proc.Pid, proc.ExeName, original, null,
                ClearCpuSets: false, ResetEfficiencyMode: true));

            bool lowered = _api.TrySetPriority(proc.Pid, proc.ExeName, ProcessPriority.BelowNormal, out _);
            bool eco = _api.TrySetEfficiencyMode(proc.Pid, proc.ExeName, true, out _);
            if (lowered || eco)
                _log.Info("GameMode",
                    $"Demoted background hog {proc.ExeName} (PID {proc.Pid}, {proc.CpuPct:F0}% CPU) to BelowNormal + efficiency mode.");
        }
    }

    private void PauseWindowsUpdate()
    {
        try
        {
            using var service = new ServiceController("wuauserv");
            if (service.Status == ServiceControllerStatus.Running)
            {
                _journal.RecordWindowsUpdatePaused();
                service.Stop();
                _log.Info("GameMode", "Paused the Windows Update service for this session.");
            }
        }
        catch (Exception ex)
        {
            _log.Warn("GameMode", $"Could not pause Windows Update: {ex.Message}");
        }
    }

    private void ExitGameMode(string reason)
    {
        _log.Info("GameMode", $"Leaving Game Mode ({reason}).");
        var state = _journal.Current;

        foreach (var mutation in state.Mutations)
            RevertMutation(mutation, _api, _log);

        if (state.PreviousPowerPlanGuid is not null)
        {
            if (_power.RestorePreviousPlan())
                _log.Info("GameMode", "Restored the previous power plan.");
        }

        if (state.WindowsUpdatePaused)
            ResumeWindowsUpdate(_log);

        _journal.Clear();
        _activeGamePid = -1;
        _activeGameExe = null;
        StateChanged?.Invoke();
    }

    /// <summary>Shared with crash recovery: undo one journaled process mutation.</summary>
    internal static void RevertMutation(ProcessMutationRecord mutation, ProcessApi api, ActivityLog log)
    {
        // The process may be gone; every call below fails soft.
        if (mutation.OriginalPriority is { } priority)
            api.TrySetPriority(mutation.Pid, mutation.ExeName, priority, out _);
        if (mutation.OriginalAffinityMask is { } mask and > 0)
            api.TrySetAffinity(mutation.Pid, mutation.ExeName, mask, out _);
        if (mutation.ClearCpuSets)
            api.TrySetCpuSets(mutation.Pid, mutation.ExeName, null, out _);
        if (mutation.ResetEfficiencyMode)
            api.TrySetEfficiencyMode(mutation.Pid, mutation.ExeName, null, out _);
        log.Info("GameMode", $"Reverted changes to {mutation.ExeName} (PID {mutation.Pid}).");
    }

    internal static void ResumeWindowsUpdate(ActivityLog log)
    {
        try
        {
            using var service = new ServiceController("wuauserv");
            if (service.Status == ServiceControllerStatus.Stopped)
            {
                service.Start();
                log.Info("GameMode", "Resumed the Windows Update service.");
            }
        }
        catch (Exception ex)
        {
            log.Warn("GameMode", $"Could not resume Windows Update: {ex.Message}");
        }
    }

    private static bool IsProcessAlive(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    public void Dispose()
    {
        _foreground.Sampled -= OnForegroundSampled;
        lock (_gate)
        {
            if (IsActive)
                ExitGameMode("Nexus is shutting down");
        }
    }
}
