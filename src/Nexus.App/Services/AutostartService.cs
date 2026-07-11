using System.Diagnostics;
using Nexus.Core.Logging;

namespace Nexus.App.Services;

/// <summary>
/// Start-with-Windows via a scheduled task with highest run level. A plain Run key
/// cannot elevate, and this app requires administrator — the scheduled task is the
/// standard way to autostart elevated without a UAC prompt at logon.
/// </summary>
public sealed class AutostartService
{
    private const string TaskName = "Nexus Optimizer";
    private readonly ActivityLog _log;

    public AutostartService(ActivityLog log)
    {
        _log = log;
    }

    public bool IsEnabled()
        => RunSchtasks($"/Query /TN \"{TaskName}\"", out _);

    public bool SetEnabled(bool enabled)
    {
        if (enabled)
        {
            // Environment.ProcessPath, NOT Assembly.Location — the latter is empty
            // in single-file publishes.
            var exe = Environment.ProcessPath;
            if (exe is null)
            {
                _log.Error("Autostart", "Could not determine the executable path.");
                return false;
            }

            if (RunSchtasks(
                    $"/Create /F /RL HIGHEST /SC ONLOGON /TN \"{TaskName}\" /TR \"\\\"{exe}\\\"\"",
                    out var error))
            {
                _log.Info("Autostart", "Nexus will start with Windows (scheduled task, highest privileges).");
                return true;
            }
            _log.Error("Autostart", $"Could not create the autostart task: {error}");
            return false;
        }

        if (RunSchtasks($"/Delete /F /TN \"{TaskName}\"", out var deleteError))
        {
            _log.Info("Autostart", "Nexus will no longer start with Windows.");
            return true;
        }
        _log.Warn("Autostart", $"Could not remove the autostart task: {deleteError}");
        return false;
    }

    private static bool RunSchtasks(string arguments, out string? error)
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
                error = stderr.Trim();
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
