using System.Diagnostics;
using Nexus.Core.Logging;

namespace Nexus.App.Services;

public sealed record BootTimerSetting(
    string Id,
    string Name,
    string Description,
    string ApplyArgs,
    string UndoArgs);

/// <summary>
/// Boot Configuration Data (BCD) timer settings via bcdedit.exe: HPET usage,
/// dynamic tick, and TSC sync policy. Each has an explicit undo. These take effect
/// on reboot and are the single most "your-mileage-varies" area in the app — the
/// UI says so, and every option can be reverted.
/// </summary>
public sealed class BootTimerService
{
    private readonly ActivityLog _log;

    public BootTimerService(ActivityLog log)
    {
        _log = log;
    }

    public static IReadOnlyList<BootTimerSetting> Settings { get; } =
    [
        new("useplatformclock-off",
            "Let Windows use the CPU TSC instead of forcing HPET",
            "Removes any forced platform-clock (HPET) setting so Windows picks the low-overhead TSC. This is the modern default and the safe choice on most systems. Reboot required.",
            "/deletevalue useplatformclock",
            "/set useplatformclock true"),
        new("dynamictick-off",
            "Disable dynamic tick",
            "Forces a constant timer tick instead of letting it stop to save power. Can reduce wake-from-idle latency; raises idle power draw. Reboot required.",
            "/set disabledynamictick yes",
            "/set disabledynamictick no"),
        new("tsc-sync-enhanced",
            "Enhanced TSC sync across cores",
            "Aggressively synchronizes the Time Stamp Counter across cores; can help temporal consistency on multi-CCD CPUs. Reboot required.",
            "/set tscsyncpolicy Enhanced",
            "/deletevalue tscsyncpolicy"),
    ];

    public bool Apply(string id, out string? error)
    {
        error = null;
        var setting = Settings.FirstOrDefault(s => s.Id == id);
        if (setting is null)
        {
            error = "unknown boot-timer setting";
            return false;
        }
        if (RunBcdedit(setting.ApplyArgs, out error))
        {
            _log.Info("BootTimer", $"Applied \"{setting.Name}\". Takes effect after a reboot.");
            return true;
        }
        return false;
    }

    public bool Undo(string id, out string? error)
    {
        error = null;
        var setting = Settings.FirstOrDefault(s => s.Id == id);
        if (setting is null)
        {
            error = "unknown boot-timer setting";
            return false;
        }
        if (RunBcdedit(setting.UndoArgs, out error))
        {
            _log.Info("BootTimer", $"Reverted \"{setting.Name}\". Takes effect after a reboot.");
            return true;
        }
        return false;
    }

    private bool RunBcdedit(string arguments, out string? error)
    {
        error = null;
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "bcdedit.exe",
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (process is null)
            {
                error = "could not start bcdedit";
                return false;
            }
            var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            process.WaitForExit(15_000);
            if (process.ExitCode != 0)
            {
                error = $"bcdedit {arguments}: {output.Trim()}";
                _log.Warn("BootTimer", error);
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
