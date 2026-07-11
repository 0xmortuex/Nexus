using System.Diagnostics;
using Nexus.Core.Logging;
using Nexus.Core.Persistence;
using Nexus.Core.Power;

namespace Nexus.App.Services;

/// <summary>
/// Power plan control via powercfg.exe. Owns the "Nexus Performance" plan (a clone
/// of Ultimate Performance with core parking disabled) and remembers the previously
/// active plan so every switch is reversible. GUIDs only — output labels are localized.
/// </summary>
public sealed class PowerPlanService
{
    private readonly ActivityLog _log;
    private readonly SettingsService _settings;
    private readonly object _gate = new();

    public PowerPlanService(ActivityLog log, SettingsService settings)
    {
        _log = log;
        _settings = settings;
    }

    public bool PerformanceModeActive
    {
        get
        {
            var opts = _settings.Current.Power;
            return opts.PerformancePlanGuid is { } guid && GetActiveSchemeGuid() == guid;
        }
    }

    /// <summary>Switch to the Nexus Performance plan (creating it on first use).</summary>
    public bool ActivatePerformanceMode()
    {
        lock (_gate)
        {
            var guid = EnsurePerformancePlan();
            if (guid is null)
                return false;
            return Activate(guid, rememberPrevious: true);
        }
    }

    /// <summary>Switch to Windows' built-in Power Saver plan (IdleSaver).</summary>
    public bool ActivatePowerSaver()
    {
        lock (_gate)
        {
            return Activate(PowerSchemes.PowerSaver, rememberPrevious: true);
        }
    }

    /// <summary>Return to whatever plan was active before Nexus last switched.</summary>
    public bool RestorePreviousPlan()
    {
        lock (_gate)
        {
            var previous = _settings.Current.Power.PreviousPlanGuid;
            if (previous is null)
                return false;

            if (!RunPowerCfg($"/setactive {previous}", out _))
                return false;

            _settings.Update(s => s with { Power = s.Power with { PreviousPlanGuid = null } });
            _log.Info("Power", $"Restored previous power plan {previous}.");
            return true;
        }
    }

    public string? GetActiveSchemeGuid()
    {
        return RunPowerCfg("/getactivescheme", out var output)
            ? PowerCfgParser.ParseFirstGuid(output)
            : null;
    }

    /// <summary>Create (or find) the Nexus Performance plan. Returns its GUID or null.</summary>
    public string? EnsurePerformancePlan()
    {
        var stored = _settings.Current.Power.PerformancePlanGuid;
        if (stored is not null && RunPowerCfg("/list", out var list)
            && PowerCfgParser.ParseSchemeList(list).Any(s => s.Guid == stored))
        {
            return stored;
        }

        // Clone Ultimate Performance; fall back to High Performance on editions
        // where the Ultimate scheme is unavailable.
        string? guid = null;
        if (RunPowerCfg($"/duplicatescheme {PowerSchemes.UltimatePerformance}", out var dup))
            guid = PowerCfgParser.ParseFirstGuid(dup);
        if (guid is null && RunPowerCfg($"/duplicatescheme {PowerSchemes.HighPerformance}", out dup))
            guid = PowerCfgParser.ParseFirstGuid(dup);
        if (guid is null)
        {
            _log.Error("Power", "Could not create the performance power plan (powercfg /duplicatescheme failed).");
            return null;
        }

        RunPowerCfg($"/changename {guid} \"Nexus Performance\" \"Ultimate Performance clone with core parking disabled. Created by Nexus.\"", out _);

        // Disable core parking: keep 100% of cores unparked, on AC and battery.
        RunPowerCfg($"/setacvalueindex {guid} SUB_PROCESSOR CPMINCORES 100", out _);
        RunPowerCfg($"/setdcvalueindex {guid} SUB_PROCESSOR CPMINCORES 100", out _);
        // Keep the processor at full minimum state so clocks don't dip mid-game.
        RunPowerCfg($"/setacvalueindex {guid} SUB_PROCESSOR PROCTHROTTLEMIN 100", out _);

        _settings.Update(s => s with { Power = s.Power with { PerformancePlanGuid = guid } });
        _log.Info("Power", $"Created power plan \"Nexus Performance\" ({guid}) with core parking disabled.");
        return guid;
    }

    private bool Activate(string guid, bool rememberPrevious)
    {
        var current = GetActiveSchemeGuid();
        if (current == guid)
            return true;

        if (!RunPowerCfg($"/setactive {guid}", out _))
            return false;

        if (rememberPrevious && current is not null
            && _settings.Current.Power.PreviousPlanGuid is null) // don't overwrite across nested switches
        {
            _settings.Update(s => s with { Power = s.Power with { PreviousPlanGuid = current } });
        }

        _log.Info("Power", $"Activated power plan {guid}.");
        return true;
    }

    /// <summary>Delete the Nexus plan and forget stored GUIDs (restore-defaults path).</summary>
    public void DeletePerformancePlan()
    {
        lock (_gate)
        {
            var opts = _settings.Current.Power;
            if (opts.PerformancePlanGuid is { } guid)
            {
                if (GetActiveSchemeGuid() == guid)
                    RunPowerCfg($"/setactive {opts.PreviousPlanGuid ?? PowerSchemes.Balanced}", out _);
                RunPowerCfg($"/delete {guid}", out _);
                _log.Info("Power", "Removed the Nexus Performance power plan.");
            }
            _settings.Update(s => s with { Power = new Core.Models.PowerOptions() });
        }
    }

    private bool RunPowerCfg(string arguments, out string output)
    {
        output = "";
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "powercfg.exe",
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (process is null)
                return false;

            output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(10_000))
            {
                process.Kill();
                _log.Warn("Power", $"powercfg {arguments} timed out.");
                return false;
            }
            if (process.ExitCode != 0)
            {
                _log.Warn("Power", $"powercfg {arguments} exited with code {process.ExitCode}.");
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            _log.Error("Power", $"powercfg {arguments} failed: {ex.Message}");
            return false;
        }
    }
}
