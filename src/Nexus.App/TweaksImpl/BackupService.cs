using System.IO;
using System.Diagnostics;
using System.Management;
using Nexus.Core.Logging;
using Nexus.Core.Persistence;

namespace Nexus.App.TweaksImpl;

/// <summary>
/// Pre-tweak safety net. A System Restore point is attempted (best effort — Windows
/// throttles them to one per 24 h and Home editions sometimes disable the service),
/// but the .reg export of every affected key is MANDATORY: if it fails, the tweak
/// is not applied.
/// </summary>
public sealed class BackupService
{
    private readonly NexusPaths _paths;
    private readonly ActivityLog _log;
    private bool _restorePointAttempted;

    public BackupService(NexusPaths paths, ActivityLog log)
    {
        _paths = paths;
        _log = log;
    }

    /// <summary>Returns the backup directory on success, null when the mandatory
    /// registry export failed. Keys that don't exist yet are skipped (nothing to back up).</summary>
    public string? BackupBeforeTweak(string tweakId, IReadOnlyList<string> affectedKeys)
    {
        TryCreateRestorePointOncePerSession();

        var dir = Path.Combine(_paths.RegistryBackupDirectory,
            $"{DateTimeOffset.Now:yyyyMMdd-HHmmss}-{tweakId}");
        try
        {
            Directory.CreateDirectory(dir);

            int index = 0;
            foreach (var key in affectedKeys)
            {
                var file = Path.Combine(dir, $"{index++:D2}.reg");
                if (!ExportKey(key, file))
                    return null; // mandatory backup failed → caller must refuse the tweak
            }

            _log.Info("Tweaks", $"Backed up {affectedKeys.Count} registry key(s) to {dir}.");
            return dir;
        }
        catch (Exception ex)
        {
            _log.Error("Tweaks", $"Registry backup failed: {ex.Message}");
            return null;
        }
    }

    private bool ExportKey(string keyPath, string file)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "reg.exe",
                Arguments = $"export \"{keyPath}\" \"{file}\" /y",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (process is null)
                return false;
            process.WaitForExit(15_000);

            // Exit code 1 with no output file usually means the key doesn't exist yet —
            // there is genuinely nothing to back up, which is fine.
            if (process.ExitCode == 0)
                return true;
            if (!KeyExists(keyPath))
            {
                File.WriteAllText(file + ".absent",
                    $"Key {keyPath} did not exist when this backup was taken.");
                return true;
            }

            _log.Error("Tweaks", $"reg export of {keyPath} failed (exit {process.ExitCode}).");
            return false;
        }
        catch (Exception ex)
        {
            _log.Error("Tweaks", $"reg export of {keyPath} failed: {ex.Message}");
            return false;
        }
    }

    private static bool KeyExists(string keyPath)
    {
        int separator = keyPath.IndexOf('\\');
        if (separator < 0)
            return false;
        var root = keyPath[..separator].ToUpperInvariant() switch
        {
            "HKEY_LOCAL_MACHINE" or "HKLM" => Microsoft.Win32.Registry.LocalMachine,
            "HKEY_CURRENT_USER" or "HKCU" => Microsoft.Win32.Registry.CurrentUser,
            _ => null,
        };
        if (root is null)
            return false;
        using var key = root.OpenSubKey(keyPath[(separator + 1)..]);
        return key is not null;
    }

    private void TryCreateRestorePointOncePerSession()
    {
        if (_restorePointAttempted)
            return;
        _restorePointAttempted = true;

        try
        {
            using var systemRestore = new ManagementClass(
                new ManagementScope(@"\\.\root\default"), new ManagementPath("SystemRestore"), null);
            var parameters = systemRestore.GetMethodParameters("CreateRestorePoint");
            parameters["Description"] = "Nexus tweaks";
            parameters["RestorePointType"] = 0;   // APPLICATION_INSTALL
            parameters["EventType"] = 100;        // BEGIN_SYSTEM_CHANGE
            var result = systemRestore.InvokeMethod("CreateRestorePoint", parameters, null);
            var code = Convert.ToInt32(result["ReturnValue"]);

            if (code == 0)
                _log.Info("Tweaks", "Created System Restore point \"Nexus tweaks\".");
            else
                // 1440 = another point was created within the 24 h throttle window.
                _log.Warn("Tweaks",
                    $"System Restore point not created (code {code}; Windows throttles points to one per 24 h). The .reg backups still protect these tweaks.");
        }
        catch (Exception ex)
        {
            _log.Warn("Tweaks",
                $"System Restore point unavailable ({ex.Message}). Proceeding — the mandatory .reg backups still protect these tweaks.");
        }
    }
}
