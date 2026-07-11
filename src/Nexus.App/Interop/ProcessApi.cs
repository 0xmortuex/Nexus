using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Nexus.Core;
using Nexus.Core.Logging;
using Nexus.Core.Models;

namespace Nexus.App.Interop;

/// <summary>
/// The only gateway for mutating other processes. Every method: refuses protected
/// processes, never throws (returns false + error text), and leaves a log trail
/// for failures at the caller's discretion.
/// </summary>
public sealed class ProcessApi
{
    private readonly ActivityLog _log;

    public ProcessApi(ActivityLog log)
    {
        _log = log;
    }

    public bool TrySetPriority(int pid, string exeName, ProcessPriority priority, out string? error)
    {
        if (Blocked(exeName, out error))
            return false;

        return WithHandle(pid,
            NativeMethods.PROCESS_SET_INFORMATION | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
            handle => NativeMethods.SetPriorityClass(handle, ToPriorityClass(priority)),
            out error);
    }

    public bool TryGetPriority(int pid, out ProcessPriority priority, out string? error)
    {
        var result = ProcessPriority.Normal;
        var ok = WithHandle(pid, NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
            handle =>
            {
                var cls = NativeMethods.GetPriorityClass(handle);
                if (cls == 0)
                    return false;
                result = FromPriorityClass(cls);
                return true;
            },
            out error);
        priority = result;
        return ok;
    }

    public bool TrySetAffinity(int pid, string exeName, ulong mask, out string? error)
    {
        if (Blocked(exeName, out error))
            return false;
        if (mask == 0)
        {
            error = "affinity mask must contain at least one CPU";
            return false;
        }

        return WithHandle(pid,
            NativeMethods.PROCESS_SET_INFORMATION | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
            handle => NativeMethods.SetProcessAffinityMask(handle, (nuint)mask),
            out error);
    }

    public bool TryGetAffinity(int pid, out ulong mask, out string? error)
    {
        ulong result = 0;
        var ok = WithHandle(pid, NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
            handle =>
            {
                if (!NativeMethods.GetProcessAffinityMask(handle, out var processMask, out _))
                    return false;
                result = processMask;
                return true;
            },
            out error);
        mask = result;
        return ok;
    }

    /// <summary>Apply CPU sets (soft core preference). Null or empty clears back to "any CPU".</summary>
    public bool TrySetCpuSets(int pid, string exeName, IReadOnlyList<uint>? cpuSetIds, out string? error)
    {
        if (Blocked(exeName, out error))
            return false;

        var ids = cpuSetIds is { Count: > 0 } ? cpuSetIds.ToArray() : null;
        return WithHandle(pid,
            NativeMethods.PROCESS_SET_INFORMATION | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
            handle => NativeMethods.SetProcessDefaultCpuSets(handle, ids, (uint)(ids?.Length ?? 0)),
            out error);
    }

    public bool TrySetIoPriority(int pid, string exeName, IoPriorityLevel level, out string? error)
    {
        if (Blocked(exeName, out error))
            return false;

        string? localError = null;
        var ok = WithHandle(pid,
            NativeMethods.PROCESS_SET_INFORMATION | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
            handle =>
            {
                int value = (int)level;
                int status = NativeMethods.NtSetInformationProcess(
                    handle, NativeMethods.ProcessIoPriority, ref value, sizeof(int));
                if (status != 0)
                {
                    localError = $"NtSetInformationProcess failed with NTSTATUS 0x{status:X8}";
                    return false;
                }
                return true;
            },
            out error);
        if (!ok && localError is not null)
            error = localError;
        return ok;
    }

    public bool TrySetMemoryPriority(int pid, string exeName, MemoryPriorityLevel level, out string? error)
    {
        if (Blocked(exeName, out error))
            return false;

        return WithHandle(pid,
            NativeMethods.PROCESS_SET_INFORMATION | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
            handle =>
            {
                var info = new NativeMethods.MEMORY_PRIORITY_INFORMATION { MemoryPriority = (uint)level };
                return NativeMethods.SetProcessInformation(handle, NativeMethods.ProcessMemoryPriorityInfo,
                    ref info, Marshal.SizeOf<NativeMethods.MEMORY_PRIORITY_INFORMATION>());
            },
            out error);
    }

    /// <summary>EcoQoS / efficiency mode. true = enable, false = force off, null = OS default.
    /// On Windows 10 this maps to legacy power throttling; failure is non-fatal.</summary>
    public bool TrySetEfficiencyMode(int pid, string exeName, bool? enable, out string? error)
    {
        if (Blocked(exeName, out error))
            return false;

        return WithHandle(pid,
            NativeMethods.PROCESS_SET_INFORMATION | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
            handle =>
            {
                var state = new NativeMethods.PROCESS_POWER_THROTTLING_STATE
                {
                    Version = NativeMethods.PROCESS_POWER_THROTTLING_CURRENT_VERSION,
                    ControlMask = enable is null ? 0 : NativeMethods.PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
                    StateMask = enable == true ? NativeMethods.PROCESS_POWER_THROTTLING_EXECUTION_SPEED : 0,
                };
                return NativeMethods.SetProcessInformation(handle, NativeMethods.ProcessPowerThrottlingInfo,
                    ref state, Marshal.SizeOf<NativeMethods.PROCESS_POWER_THROTTLING_STATE>());
            },
            out error);
    }

    public bool TryTrimWorkingSet(int pid, string exeName, out string? error)
    {
        if (Blocked(exeName, out error))
            return false;

        return WithHandle(pid,
            NativeMethods.PROCESS_SET_QUOTA | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION,
            handle => NativeMethods.SetProcessWorkingSetSize(handle, -1, -1)
                      || NativeMethods.K32EmptyWorkingSet(handle),
            out error);
    }

    private bool Blocked(string exeName, out string? error)
    {
        if (ProcessSafety.IsProtected(exeName))
        {
            error = $"{exeName} is on the never-touch list";
            _log.Warn("Safety", $"Refused to modify protected process {exeName}.");
            return true;
        }
        error = null;
        return false;
    }

    private static bool WithHandle(int pid, uint access, Func<SafeProcessHandle, bool> action, out string? error)
    {
        try
        {
            using var handle = NativeMethods.OpenProcess(access, false, (uint)pid);
            if (handle.IsInvalid)
            {
                error = $"OpenProcess: {new Win32Exception().Message}";
                return false;
            }

            if (action(handle))
            {
                error = null;
                return true;
            }

            error = new Win32Exception().Message;
            return false;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static uint ToPriorityClass(ProcessPriority priority) => priority switch
    {
        ProcessPriority.Idle => NativeMethods.IDLE_PRIORITY_CLASS,
        ProcessPriority.BelowNormal => NativeMethods.BELOW_NORMAL_PRIORITY_CLASS,
        ProcessPriority.AboveNormal => NativeMethods.ABOVE_NORMAL_PRIORITY_CLASS,
        ProcessPriority.High => NativeMethods.HIGH_PRIORITY_CLASS,
        ProcessPriority.RealTime => NativeMethods.REALTIME_PRIORITY_CLASS,
        _ => NativeMethods.NORMAL_PRIORITY_CLASS,
    };

    private static ProcessPriority FromPriorityClass(uint cls) => cls switch
    {
        NativeMethods.IDLE_PRIORITY_CLASS => ProcessPriority.Idle,
        NativeMethods.BELOW_NORMAL_PRIORITY_CLASS => ProcessPriority.BelowNormal,
        NativeMethods.ABOVE_NORMAL_PRIORITY_CLASS => ProcessPriority.AboveNormal,
        NativeMethods.HIGH_PRIORITY_CLASS => ProcessPriority.High,
        NativeMethods.REALTIME_PRIORITY_CLASS => ProcessPriority.RealTime,
        _ => ProcessPriority.Normal,
    };
}
