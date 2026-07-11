using System.IO;
using System.Diagnostics;
using System.Text.Json;
using Microsoft.Win32;
using Nexus.Core.Logging;

namespace Nexus.App.TweaksImpl;

public enum StartupSource
{
    RegistryRunHklm,
    RegistryRunHkcu,
    StartupFolder,
    ScheduledTask,
}

public sealed record StartupEntry(
    string Id,
    string Name,
    string Command,
    StartupSource Source,
    bool Enabled);

/// <summary>
/// Startup manager: enumerates Run keys (HKLM+HKCU), Startup folders, and
/// logon-triggered scheduled tasks. Enable/disable ONLY — nothing is deleted.
/// Run/StartupFolder entries are toggled via the same StartupApproved registry
/// mechanism Task Manager uses, so the two UIs stay consistent.
/// </summary>
public sealed class StartupManagerService
{
    private const string RunKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string ApprovedRun = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
    private const string ApprovedFolder = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder";

    private readonly ActivityLog _log;

    public StartupManagerService(ActivityLog log)
    {
        _log = log;
    }

    public IReadOnlyList<StartupEntry> Enumerate()
    {
        var entries = new List<StartupEntry>();
        EnumerateRunKey(Registry.LocalMachine, StartupSource.RegistryRunHklm, entries);
        EnumerateRunKey(Registry.CurrentUser, StartupSource.RegistryRunHkcu, entries);
        EnumerateStartupFolder(entries);
        EnumerateLogonTasks(entries);
        return entries;
    }

    public bool SetEnabled(StartupEntry entry, bool enabled, out string? error)
    {
        error = null;
        try
        {
            switch (entry.Source)
            {
                case StartupSource.RegistryRunHklm:
                    SetApprovedFlag(Registry.LocalMachine, ApprovedRun, entry.Name, enabled);
                    break;
                case StartupSource.RegistryRunHkcu:
                    SetApprovedFlag(Registry.CurrentUser, ApprovedRun, entry.Name, enabled);
                    break;
                case StartupSource.StartupFolder:
                    SetApprovedFlag(Registry.CurrentUser, ApprovedFolder, entry.Name, enabled);
                    break;
                case StartupSource.ScheduledTask:
                    return RunSchtasks($"/Change /TN \"{entry.Id}\" /{(enabled ? "Enable" : "Disable")}", out error);
            }

            _log.Info("Startup", $"{(enabled ? "Enabled" : "Disabled")} startup entry \"{entry.Name}\".");
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            _log.Error("Startup", $"Could not toggle \"{entry.Name}\": {ex.Message}");
            return false;
        }
    }

    private void EnumerateRunKey(RegistryKey root, StartupSource source, List<StartupEntry> entries)
    {
        try
        {
            using var key = root.OpenSubKey(RunKey);
            if (key is null)
                return;
            foreach (var name in key.GetValueNames())
            {
                if (string.IsNullOrWhiteSpace(name))
                    continue;
                entries.Add(new StartupEntry(
                    $"{source}:{name}", name,
                    key.GetValue(name)?.ToString() ?? "",
                    source,
                    IsApproved(root, ApprovedRun, name)));
            }
        }
        catch (Exception ex)
        {
            _log.Warn("Startup", $"Could not read {source} Run key: {ex.Message}");
        }
    }

    private void EnumerateStartupFolder(List<StartupEntry> entries)
    {
        foreach (var folder in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        })
        {
            try
            {
                if (!Directory.Exists(folder))
                    continue;
                foreach (var file in Directory.EnumerateFiles(folder)
                             .Where(f => !f.EndsWith("desktop.ini", StringComparison.OrdinalIgnoreCase)))
                {
                    var name = Path.GetFileName(file);
                    entries.Add(new StartupEntry(
                        $"folder:{name}", name, file, StartupSource.StartupFolder,
                        IsApproved(Registry.CurrentUser, ApprovedFolder, name)));
                }
            }
            catch (Exception ex)
            {
                _log.Warn("Startup", $"Could not read startup folder: {ex.Message}");
            }
        }
    }

    /// <summary>Logon-triggered scheduled tasks via PowerShell (locale-independent,
    /// unlike schtasks' localized CSV output).</summary>
    private void EnumerateLogonTasks(List<StartupEntry> entries)
    {
        try
        {
            const string script =
                "Get-ScheduledTask | Where-Object { $_.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' } } | " +
                "Select-Object @{n='Path';e={$_.TaskPath + $_.TaskName}}, @{n='Name';e={$_.TaskName}}, State | ConvertTo-Json -Compress";

            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{script}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (process is null)
                return;
            var output = process.StandardOutput.ReadToEnd();
            if (!process.WaitForExit(30_000) || string.IsNullOrWhiteSpace(output))
                return;

            using var json = JsonDocument.Parse(output);
            var items = json.RootElement.ValueKind == JsonValueKind.Array
                ? json.RootElement.EnumerateArray().ToArray()
                : [json.RootElement];

            foreach (var item in items)
            {
                var path = item.GetProperty("Path").GetString();
                var name = item.GetProperty("Name").GetString();
                if (path is null || name is null)
                    continue;
                // State: 1 = Disabled (Microsoft.PowerShell.Cmdletization enum)
                bool enabled = !item.TryGetProperty("State", out var state) || state.GetInt32() != 1;
                entries.Add(new StartupEntry(path, name, path, StartupSource.ScheduledTask, enabled));
            }
        }
        catch (Exception ex)
        {
            _log.Warn("Startup", $"Could not enumerate logon tasks: {ex.Message}");
        }
    }

    // StartupApproved binary format (as written by Task Manager): 12 bytes,
    // first byte 0x02 = enabled, 0x03 = disabled, rest is a disable timestamp.
    private static bool IsApproved(RegistryKey root, string approvedKey, string name)
    {
        using var key = root.OpenSubKey(approvedKey);
        return key?.GetValue(name) is not byte[] bytes || bytes.Length == 0 || (bytes[0] & 0x03) != 0x03;
    }

    private static void SetApprovedFlag(RegistryKey root, string approvedKey, string name, bool enabled)
    {
        using var key = root.CreateSubKey(approvedKey, writable: true);
        var bytes = new byte[12];
        bytes[0] = enabled ? (byte)0x02 : (byte)0x03;
        if (!enabled)
        {
            var now = BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc());
            Array.Copy(now, 0, bytes, 4, 8);
        }
        key.SetValue(name, bytes, RegistryValueKind.Binary);
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
