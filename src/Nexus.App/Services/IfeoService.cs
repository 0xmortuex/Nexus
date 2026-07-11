using Microsoft.Win32;
using Nexus.Core;
using Nexus.Core.Logging;
using Nexus.Core.Models;

namespace Nexus.App.Services;

/// <summary>
/// Image File Execution Options "PerfOptions": the kernel reads these keys at the
/// exact moment it creates a process and applies the priority/IO/memory class
/// BEFORE the process's own threads (or an anti-cheat's self-protection) start.
/// This is how a priority can stick on processes that reject a live SetPriorityClass
/// call. It is a fully documented Windows facility, not code injection — Nexus never
/// touches the anti-cheat process itself, only asks the kernel to launch the *game*
/// at the requested class.
///
/// Layout: HKLM\...\Image File Execution Options\<exe>\PerfOptions
///   CpuPriorityClass (dword): 1 Idle, 2 Normal, 3 High, 4 RealTime(->High), 5 Below, 6 Above
///   IoPriority (dword):       0 VeryLow, 1 Low, 2 Normal, 3 High
///   PagePriority (dword):     0..7 (5 = normal)
/// </summary>
public sealed class IfeoService
{
    private const string IfeoRoot = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private readonly ActivityLog _log;

    public IfeoService(ActivityLog log)
    {
        _log = log;
    }

    public bool IsConfigured(string exeName)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"{IfeoRoot}\{Normalize(exeName)}\PerfOptions");
        return key?.GetValue("CpuPriorityClass") is not null;
    }

    /// <summary>Set the launch-time priority (and optional IO/page priority) for an exe.</summary>
    public bool SetLaunchPriority(string exeName, ProcessPriority priority,
        IoPriorityLevel? io, MemoryPriorityLevel? page, out string? error)
    {
        error = null;
        if (ProcessSafety.IsProtected(exeName))
        {
            error = $"{exeName} is on the never-touch list";
            return false;
        }

        try
        {
            using var key = Registry.LocalMachine.CreateSubKey(
                $@"{IfeoRoot}\{Normalize(exeName)}\PerfOptions", writable: true);
            key.SetValue("CpuPriorityClass", ToIfeoPriority(priority), RegistryValueKind.DWord);
            if (io is { } ioLevel)
                key.SetValue("IoPriority", (int)ioLevel, RegistryValueKind.DWord);
            if (page is { } pageLevel)
                key.SetValue("PagePriority", ToPagePriority(pageLevel), RegistryValueKind.DWord);

            _log.Info("IFEO",
                $"{exeName} will now launch at {priority} priority (enforced by the kernel at process creation — survives anti-cheat).");
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            _log.Error("IFEO", $"Could not set launch priority for {exeName}: {ex.Message}");
            return false;
        }
    }

    /// <summary>Remove the PerfOptions subkey (and the exe key if it is now empty).</summary>
    public bool Clear(string exeName, out string? error)
    {
        error = null;
        try
        {
            var exeKey = $@"{IfeoRoot}\{Normalize(exeName)}";
            using (var perf = Registry.LocalMachine.OpenSubKey($@"{exeKey}\PerfOptions", writable: true))
            {
                if (perf is null)
                    return true;
            }
            Registry.LocalMachine.DeleteSubKeyTree($@"{exeKey}\PerfOptions", throwOnMissingSubKey: false);

            // Only remove the exe key itself if Nexus created it and nothing else lives there
            // (a debugger value, for instance, must be preserved).
            using (var exe = Registry.LocalMachine.OpenSubKey(exeKey))
            {
                if (exe is not null && exe.ValueCount == 0 && exe.SubKeyCount == 0)
                    Registry.LocalMachine.DeleteSubKey(exeKey, throwOnMissingSubKey: false);
            }

            _log.Info("IFEO", $"Removed the launch-time priority rule for {exeName}.");
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public IReadOnlyList<string> ConfiguredExes()
    {
        var result = new List<string>();
        using var root = Registry.LocalMachine.OpenSubKey(IfeoRoot);
        if (root is null)
            return result;
        foreach (var name in root.GetSubKeyNames())
        {
            using var perf = root.OpenSubKey($@"{name}\PerfOptions");
            if (perf?.GetValue("CpuPriorityClass") is not null)
                result.Add(name);
        }
        return result;
    }

    private static string Normalize(string exeName)
        => exeName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? exeName : exeName + ".exe";

    private static int ToIfeoPriority(ProcessPriority priority) => priority switch
    {
        ProcessPriority.Idle => 1,
        ProcessPriority.Normal => 2,
        ProcessPriority.High => 3,
        ProcessPriority.RealTime => 3,       // IFEO caps at High; RealTime unavailable this way
        ProcessPriority.BelowNormal => 5,
        ProcessPriority.AboveNormal => 6,
        _ => 2,
    };

    private static int ToPagePriority(MemoryPriorityLevel level) => level switch
    {
        MemoryPriorityLevel.VeryLow => 1,
        MemoryPriorityLevel.Low => 2,
        MemoryPriorityLevel.Medium => 3,
        MemoryPriorityLevel.BelowNormal => 4,
        _ => 5,
    };
}
