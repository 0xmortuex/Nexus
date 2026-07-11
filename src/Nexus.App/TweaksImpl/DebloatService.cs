using System.Diagnostics;
using Microsoft.Win32;
using Nexus.Core.Logging;
using Nexus.Core.Tweaks;

namespace Nexus.App.TweaksImpl;

public sealed record DebloatServiceEntry(string ServiceName, string DisplayName, string Description, bool Warning = false);
public sealed record DebloatTaskEntry(string TaskPath, string Description);
public sealed record DebloatAppxEntry(string PackageFamily, string DisplayName);

/// <summary>
/// Debloat, the reversible way: services and scheduled tasks are DISABLED, never
/// deleted, with prior state recorded for undo. Appx removal is the one one-way
/// action, so the UI pre-checks nothing and warns explicitly.
/// </summary>
public sealed class DebloatService
{
    private readonly TweakStateStore _state;
    private readonly ActivityLog _log;

    public DebloatService(TweakStateStore state, ActivityLog log)
    {
        _state = state;
        _log = log;
    }

    /// <summary>Curated safe-to-disable services.</summary>
    public static IReadOnlyList<DebloatServiceEntry> Services { get; } =
    [
        new("DiagTrack", "Connected User Experiences and Telemetry",
            "Windows diagnostic data collection. Disabling stops telemetry uploads; no functional loss."),
        new("dmwappushservice", "WAP Push Message Routing",
            "Telemetry-adjacent message routing. Safe to disable on desktops."),
        new("MapsBroker", "Downloaded Maps Manager",
            "Only needed by the Maps app for offline maps."),
        new("RetailDemo", "Retail Demo Service",
            "Store-shelf demo mode. Useless on personal machines."),
        new("WMPNetworkSvc", "Windows Media Player Network Sharing",
            "DLNA media sharing from WMP. Disable unless you stream via WMP."),
        new("Fax", "Fax",
            "The fax service. If you fax, you know."),
        new("SysMain", "SysMain (Superfetch)",
            "Preloads frequently-used apps into RAM. On SSD systems the benefit is small, but disabling can make cold app starts slower. Measure both ways.",
            Warning: true),
    ];

    /// <summary>Curated telemetry/maintenance scheduled tasks (disable-only).</summary>
    public static IReadOnlyList<DebloatTaskEntry> Tasks { get; } =
    [
        new(@"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
            "Compatibility telemetry scan; a known cause of periodic disk/CPU spikes."),
        new(@"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
            "Application telemetry data collection."),
        new(@"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
            "CEIP data upload."),
        new(@"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
            "USB CEIP data collection."),
        new(@"\Microsoft\Windows\Feedback\Siuf\DmClient",
            "Feedback/diagnostics upload client."),
        new(@"\Microsoft\Windows\Windows Error Reporting\QueueReporting",
            "Queued error-report upload."),
    ];

    /// <summary>Curated provisioned apps commonly considered bloat. Removal is per-user
    /// (Remove-AppxPackage) and reversible only through the Microsoft Store.</summary>
    public static IReadOnlyList<DebloatAppxEntry> AppxCandidates { get; } =
    [
        new("Microsoft.BingNews", "Microsoft News"),
        new("Microsoft.BingWeather", "MSN Weather"),
        new("Microsoft.GetHelp", "Get Help"),
        new("Microsoft.Getstarted", "Tips"),
        new("Microsoft.Microsoft3DViewer", "3D Viewer"),
        new("Microsoft.MicrosoftOfficeHub", "Office Hub"),
        new("Microsoft.MicrosoftSolitaireCollection", "Solitaire Collection"),
        new("Microsoft.MixedReality.Portal", "Mixed Reality Portal"),
        new("Microsoft.People", "People"),
        new("Microsoft.SkypeApp", "Skype (UWP)"),
        new("Microsoft.WindowsFeedbackHub", "Feedback Hub"),
        new("Microsoft.ZuneMusic", "Groove Music / Media Player (legacy)"),
        new("Microsoft.ZuneVideo", "Movies & TV"),
        new("MicrosoftTeams", "Teams (consumer)"),
    ];

    // ---- Services (registry Start value: 2 auto, 3 manual, 4 disabled) ----

    public bool IsServiceDisabled(string serviceName)
        => ReadServiceStart(serviceName) == 4;

    public bool DisableService(string serviceName, out string? error)
    {
        error = null;
        var keyPath = $@"SYSTEM\CurrentControlSet\Services\{serviceName}";
        try
        {
            var original = ReadServiceStart(serviceName);
            if (original is null)
            {
                error = "service not found";
                return false;
            }
            if (original == 4)
                return true;

            _state.RecordServiceOriginal(new CapturedValue(
                $@"HKEY_LOCAL_MACHINE\{keyPath}", "Start", "dword", original.Value.ToString(), Existed: true));

            using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: true);
            key!.SetValue("Start", 4, RegistryValueKind.DWord);
            StopService(serviceName);
            _log.Info("Debloat", $"Disabled service {serviceName} (was start type {original}). Undo re-enables it.");
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            _log.Error("Debloat", $"Could not disable service {serviceName}: {ex.Message}");
            return false;
        }
    }

    public bool RestoreService(string serviceName, out string? error)
    {
        error = null;
        var keyPath = $@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{serviceName}";
        var original = _state.Current.ServiceOriginals
            .FirstOrDefault(v => v.KeyPath.Equals(keyPath, StringComparison.OrdinalIgnoreCase));
        if (original?.Value is null)
        {
            error = "no recorded original start type";
            return false;
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{serviceName}", writable: true);
            if (key is null)
            {
                error = "service not found";
                return false;
            }
            key.SetValue("Start", int.Parse(original.Value), RegistryValueKind.DWord);
            _state.RemoveServiceOriginal(keyPath);
            _log.Info("Debloat", $"Restored service {serviceName} to start type {original.Value}.");
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static int? ReadServiceStart(string serviceName)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}");
        return key?.GetValue("Start") as int?;
    }

    private void StopService(string serviceName)
    {
        try
        {
            using var controller = new System.ServiceProcess.ServiceController(serviceName);
            if (controller.Status == System.ServiceProcess.ServiceControllerStatus.Running)
                controller.Stop();
        }
        catch (Exception ex)
        {
            _log.Warn("Debloat", $"Service {serviceName} disabled but could not be stopped now ({ex.Message}); it will not start after reboot.");
        }
    }

    // ---- Scheduled tasks ----

    public bool IsTaskDisabledByNexus(string taskPath)
        => _state.Current.DisabledTasks.Contains(taskPath, StringComparer.OrdinalIgnoreCase);

    public bool DisableTask(string taskPath, out string? error)
    {
        if (RunSchtasks($"/Change /TN \"{taskPath}\" /Disable", out error))
        {
            _state.RecordDisabledTask(taskPath);
            _log.Info("Debloat", $"Disabled scheduled task {taskPath}.");
            return true;
        }
        return false;
    }

    public bool EnableTask(string taskPath, out string? error)
    {
        if (RunSchtasks($"/Change /TN \"{taskPath}\" /Enable", out error))
        {
            _state.RemoveDisabledTask(taskPath);
            _log.Info("Debloat", $"Re-enabled scheduled task {taskPath}.");
            return true;
        }
        return false;
    }

    /// <summary>Re-enable everything Nexus disabled (restore-defaults path).</summary>
    public void RestoreAll()
    {
        foreach (var entry in Services)
        {
            RestoreService(entry.ServiceName, out _);
        }
        foreach (var task in _state.Current.DisabledTasks.ToArray())
        {
            EnableTask(task, out _);
        }
    }

    // ---- Appx ----

    /// <summary>Remove a Store app for the current user via PowerShell. One-way:
    /// reinstall requires the Microsoft Store. The UI warns and pre-checks nothing.</summary>
    public bool RemoveAppx(string packageFamily, out string? error)
    {
        error = null;
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " +
                    $"\"Get-AppxPackage -Name '{packageFamily}' | Remove-AppxPackage\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (process is null)
            {
                error = "could not start PowerShell";
                return false;
            }
            var stderr = process.StandardError.ReadToEnd();
            if (!process.WaitForExit(120_000))
            {
                process.Kill();
                error = "Remove-AppxPackage timed out";
                return false;
            }
            if (process.ExitCode != 0)
            {
                error = stderr.Trim();
                _log.Error("Debloat", $"Removing {packageFamily} failed: {error}");
                return false;
            }
            _log.Info("Debloat", $"Removed app package {packageFamily} for the current user.");
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private bool RunSchtasks(string arguments, out string? error)
    {
        error = null;
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (process is null)
            {
                error = "could not start schtasks";
                return false;
            }
            var stderr = process.StandardError.ReadToEnd();
            process.WaitForExit(15_000);
            if (process.ExitCode != 0)
            {
                error = stderr.Trim().Length > 0 ? stderr.Trim() : $"schtasks exited with {process.ExitCode}";
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }
}
