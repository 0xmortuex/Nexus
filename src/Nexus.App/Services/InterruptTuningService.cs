using System.Diagnostics;
using System.Text.Json;
using Microsoft.Win32;
using Nexus.Core.Logging;

namespace Nexus.App.Services;

public sealed record InterruptDevice(
    string InstancePath,
    string FriendlyName,
    string Class,
    bool MsiEnabled,
    int? DevicePolicy,
    int? AssignedCore);

/// <summary>
/// Interrupt tuning (DPC-latency reduction from the report): enable Message Signaled
/// Interrupts and set IRQ affinity policy per device, via the documented
/// Enum\...\Device Parameters\Interrupt Management registry keys. Every change is
/// reversible (delete the value = back to driver default) and takes effect on the
/// next device reset / reboot. Restricted to GPU + network + storage controllers,
/// where this actually matters and is safe.
/// </summary>
public sealed class InterruptTuningService
{
    private const int IrqPolicySpecifiedProcessors = 4; // IrqPolicySpecifiedProcessors
    private readonly ActivityLog _log;

    public InterruptTuningService(ActivityLog log)
    {
        _log = log;
    }

    /// <summary>Enumerate tunable devices (Display, Net, SCSI/NVMe) with their current
    /// MSI + affinity-policy state, via PnP + the Interrupt Management registry keys.</summary>
    public IReadOnlyList<InterruptDevice> Enumerate()
    {
        var devices = new List<InterruptDevice>();
        try
        {
            const string script =
                "Get-PnpDevice -PresentOnly | Where-Object { $_.Class -in 'Display','Net','SCSIAdapter','HDC' } | " +
                "Select-Object InstanceId, FriendlyName, Class | ConvertTo-Json -Compress";
            var output = RunPowerShell(script, 30_000);
            if (string.IsNullOrWhiteSpace(output))
                return devices;

            using var json = JsonDocument.Parse(output);
            var items = json.RootElement.ValueKind == JsonValueKind.Array
                ? json.RootElement.EnumerateArray().ToArray()
                : [json.RootElement];

            foreach (var item in items)
            {
                var instanceId = item.GetProperty("InstanceId").GetString();
                if (instanceId is null || !instanceId.StartsWith("PCI", StringComparison.OrdinalIgnoreCase))
                    continue;
                var name = item.TryGetProperty("FriendlyName", out var fn) ? fn.GetString() ?? instanceId : instanceId;
                var cls = item.TryGetProperty("Class", out var c) ? c.GetString() ?? "" : "";
                var (msi, policy, core) = ReadInterruptState(instanceId);
                devices.Add(new InterruptDevice(instanceId, name, cls, msi, policy, core));
            }
        }
        catch (Exception ex)
        {
            _log.Warn("Interrupts", $"Could not enumerate devices: {ex.Message}");
        }
        return devices;
    }

    public bool SetMsi(string instancePath, bool enabled, out string? error)
    {
        error = null;
        try
        {
            var path = $@"SYSTEM\CurrentControlSet\Enum\{instancePath}\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties";
            using var key = Registry.LocalMachine.CreateSubKey(path, writable: true);
            key.SetValue("MSISupported", enabled ? 1 : 0, RegistryValueKind.DWord);
            _log.Info("Interrupts",
                $"{(enabled ? "Enabled" : "Disabled")} Message Signaled Interrupts for {instancePath}. Reboot to apply.");
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            _log.Error("Interrupts", $"Could not set MSI for {instancePath}: {ex.Message}");
            return false;
        }
    }

    /// <summary>Pin this device's interrupts to a single logical processor (group 0),
    /// or pass null to clear back to the driver default.</summary>
    public bool SetIrqAffinity(string instancePath, int? logicalCore, out string? error)
    {
        error = null;
        try
        {
            var path = $@"SYSTEM\CurrentControlSet\Enum\{instancePath}\Device Parameters\Interrupt Management\Affinity Policy";
            using var key = Registry.LocalMachine.CreateSubKey(path, writable: true);
            if (logicalCore is { } core)
            {
                key.SetValue("DevicePolicy", IrqPolicySpecifiedProcessors, RegistryValueKind.DWord);
                // AssignmentSetOverride is a little-endian bitmask (QWORD) of allowed processors.
                key.SetValue("AssignmentSetOverride", BitConverter.GetBytes(1UL << core), RegistryValueKind.Binary);
                _log.Info("Interrupts", $"Pinned {instancePath} interrupts to CPU {core}. Reboot to apply.");
            }
            else
            {
                key.DeleteValue("DevicePolicy", throwOnMissingValue: false);
                key.DeleteValue("AssignmentSetOverride", throwOnMissingValue: false);
                _log.Info("Interrupts", $"Cleared IRQ affinity for {instancePath} (driver default). Reboot to apply.");
            }
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            _log.Error("Interrupts", $"Could not set IRQ affinity for {instancePath}: {ex.Message}");
            return false;
        }
    }

    private static (bool Msi, int? Policy, int? Core) ReadInterruptState(string instancePath)
    {
        bool msi = false;
        using (var msiKey = Registry.LocalMachine.OpenSubKey(
            $@"SYSTEM\CurrentControlSet\Enum\{instancePath}\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"))
        {
            msi = msiKey?.GetValue("MSISupported") as int? == 1;
        }

        int? policy = null, core = null;
        using (var affKey = Registry.LocalMachine.OpenSubKey(
            $@"SYSTEM\CurrentControlSet\Enum\{instancePath}\Device Parameters\Interrupt Management\Affinity Policy"))
        {
            policy = affKey?.GetValue("DevicePolicy") as int?;
            if (affKey?.GetValue("AssignmentSetOverride") is byte[] bytes && bytes.Length is > 0 and <= 8)
            {
                ulong mask = 0;
                for (int i = 0; i < bytes.Length; i++)
                    mask |= (ulong)bytes[i] << (8 * i);
                for (int bit = 0; bit < 64; bit++)
                    if ((mask & (1UL << bit)) != 0) { core = bit; break; }
            }
        }
        return (msi, policy, core);
    }

    private static string RunPowerShell(string script, int timeoutMs)
    {
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
            return "";
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit(timeoutMs);
        return output;
    }
}
