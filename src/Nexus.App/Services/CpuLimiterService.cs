using System.ComponentModel;
using Nexus.App.Interop;
using Nexus.Core;
using Nexus.Core.Logging;

namespace Nexus.App.Services;

/// <summary>
/// Hard CPU cap per process (Process Lasso's "CPU Limiter") via Job Object CPU
/// rate control: the kernel scheduler enforces the cap, no suspend/resume games.
/// A process cannot leave a job, so clearing a limit disables the job's rate
/// control instead; the job handle lives until the process exits.
/// </summary>
public sealed class CpuLimiterService : IDisposable
{
    private readonly ActivityLog _log;
    private readonly Dictionary<int, IntPtr> _jobs = new();
    private readonly object _gate = new();

    public CpuLimiterService(ActivityLog log)
    {
        _log = log;
    }

    /// <summary>Cap a process at <paramref name="percent"/> % of total CPU (1–99).</summary>
    public bool TryLimit(int pid, string exeName, int percent, out string? error)
    {
        error = null;
        if (ProcessSafety.IsProtected(exeName))
        {
            error = $"{exeName} is on the never-touch list";
            return false;
        }
        if (percent is < 1 or > 99)
        {
            error = "CPU limit must be between 1 and 99 percent";
            return false;
        }

        try
        {
            lock (_gate)
            {
                if (!_jobs.TryGetValue(pid, out var job))
                {
                    job = NativeMethods.CreateJobObjectW(IntPtr.Zero, null);
                    if (job == IntPtr.Zero)
                    {
                        error = $"CreateJobObject: {new Win32Exception().Message}";
                        return false;
                    }

                    using var handle = NativeMethods.OpenProcess(
                        NativeMethods.PROCESS_SET_QUOTA | NativeMethods.PROCESS_TERMINATE
                        | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, (uint)pid);
                    if (handle.IsInvalid || !NativeMethods.AssignProcessToJobObject(job, handle))
                    {
                        // Common cause: the target sits in an existing job that
                        // forbids nesting (pre-Win8 style jobs).
                        error = $"AssignProcessToJobObject: {new Win32Exception().Message}";
                        NativeMethods.CloseHandle(job);
                        return false;
                    }

                    _jobs[pid] = job;
                }

                var info = new NativeMethods.JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
                {
                    ControlFlags = NativeMethods.JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
                                 | NativeMethods.JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                    CpuRate = (uint)(percent * 100),
                };
                if (!NativeMethods.SetInformationJobObject(job, NativeMethods.JobObjectCpuRateControlInformation,
                        ref info, System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>()))
                {
                    error = $"SetInformationJobObject: {new Win32Exception().Message}";
                    return false;
                }
            }

            _log.Info("CpuLimiter", $"Capped {exeName} (PID {pid}) at {percent}% total CPU.");
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>Lift the cap (the process stays in the job, rate control off).</summary>
    public bool TryClearLimit(int pid, string exeName, out string? error)
    {
        error = null;
        lock (_gate)
        {
            if (!_jobs.TryGetValue(pid, out var job))
                return true; // nothing to clear

            var info = new NativeMethods.JOBOBJECT_CPU_RATE_CONTROL_INFORMATION { ControlFlags = 0, CpuRate = 0 };
            if (!NativeMethods.SetInformationJobObject(job, NativeMethods.JobObjectCpuRateControlInformation,
                    ref info, System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>()))
            {
                error = $"SetInformationJobObject: {new Win32Exception().Message}";
                return false;
            }
        }

        _log.Info("CpuLimiter", $"Removed the CPU cap on {exeName} (PID {pid}).");
        return true;
    }

    /// <summary>Called when a process exits so its job handle can be released.</summary>
    public void OnProcessExited(int pid)
    {
        lock (_gate)
        {
            if (_jobs.Remove(pid, out var job))
                NativeMethods.CloseHandle(job);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            foreach (var job in _jobs.Values)
            {
                // Disable rate control before releasing, so limits don't outlive Nexus.
                var info = new NativeMethods.JOBOBJECT_CPU_RATE_CONTROL_INFORMATION { ControlFlags = 0, CpuRate = 0 };
                NativeMethods.SetInformationJobObject(job, NativeMethods.JobObjectCpuRateControlInformation,
                    ref info, System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>());
                NativeMethods.CloseHandle(job);
            }
            _jobs.Clear();
        }
    }
}
