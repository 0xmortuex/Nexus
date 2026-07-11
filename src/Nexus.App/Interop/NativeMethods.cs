using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Nexus.App.Interop;

/// <summary>
/// Raw P/Invoke declarations only. Nothing outside this folder may call these
/// directly — go through ProcessApi / CpuTopologyProvider, which add error
/// handling, logging, and the never-touch safety check.
/// </summary>
internal static partial class NativeMethods
{
    // ---- Process access rights ----
    internal const uint PROCESS_TERMINATE = 0x0001;
    internal const uint PROCESS_SET_QUOTA = 0x0100;
    internal const uint PROCESS_SET_INFORMATION = 0x0200;
    internal const uint PROCESS_QUERY_INFORMATION = 0x0400;
    internal const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    // ---- Priority classes ----
    internal const uint IDLE_PRIORITY_CLASS = 0x0040;
    internal const uint BELOW_NORMAL_PRIORITY_CLASS = 0x4000;
    internal const uint NORMAL_PRIORITY_CLASS = 0x0020;
    internal const uint ABOVE_NORMAL_PRIORITY_CLASS = 0x8000;
    internal const uint HIGH_PRIORITY_CLASS = 0x0080;
    internal const uint REALTIME_PRIORITY_CLASS = 0x0100;

    // ---- SetProcessInformation classes ----
    internal const int ProcessMemoryPriorityInfo = 0;   // PROCESS_INFORMATION_CLASS.ProcessMemoryPriority
    internal const int ProcessPowerThrottlingInfo = 4;  // PROCESS_INFORMATION_CLASS.ProcessPowerThrottling

    internal const uint PROCESS_POWER_THROTTLING_CURRENT_VERSION = 1;
    internal const uint PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 0x1;
    internal const uint PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION = 0x4;

    // ---- NtSetInformationProcess classes ----
    internal const int ProcessIoPriority = 33;

    [StructLayout(LayoutKind.Sequential)]
    internal struct MEMORY_PRIORITY_INFORMATION
    {
        public uint MemoryPriority;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_POWER_THROTTLING_STATE
    {
        public uint Version;
        public uint ControlMask;
        public uint StateMask;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern SafeProcessHandle OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool SetPriorityClass(SafeProcessHandle process, uint priorityClass);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint GetPriorityClass(SafeProcessHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool SetProcessAffinityMask(SafeProcessHandle process, nuint affinityMask);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool GetProcessAffinityMask(SafeProcessHandle process, out nuint processMask, out nuint systemMask);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool SetProcessInformation(SafeProcessHandle process, int informationClass,
        ref MEMORY_PRIORITY_INFORMATION information, int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool SetProcessInformation(SafeProcessHandle process, int informationClass,
        ref PROCESS_POWER_THROTTLING_STATE information, int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool SetProcessDefaultCpuSets(SafeProcessHandle process,
        [In] uint[]? cpuSetIds, uint cpuSetIdCount);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool SetProcessWorkingSetSize(SafeProcessHandle process, nint minimumWorkingSetSize, nint maximumWorkingSetSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool K32EmptyWorkingSet(SafeProcessHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool GetLogicalProcessorInformationEx(int relationshipType, byte[]? buffer, ref uint returnedLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool GetSystemCpuSetInformation(byte[]? information, uint bufferLength,
        out uint returnedLength, IntPtr process, uint flags);

    /// <summary>Undocumented but long-stable. Returns an NTSTATUS (0 = success).</summary>
    [DllImport("ntdll.dll")]
    internal static extern int NtSetInformationProcess(SafeProcessHandle process, int informationClass,
        ref int information, int informationLength);

    // ---- System sampling ----
    internal const int SystemProcessInformationClass = 5;
    internal const int SystemProcessorPerformanceInformationClass = 8;
    internal const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

    [DllImport("ntdll.dll")]
    internal static extern int NtQuerySystemInformation(int informationClass, byte[] information,
        uint informationLength, out uint returnLength);

    [StructLayout(LayoutKind.Sequential)]
    internal struct MEMORYSTATUSEX
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhys;
        public ulong AvailPhys;
        public ulong TotalPageFile;
        public ulong AvailPageFile;
        public ulong TotalVirtual;
        public ulong AvailVirtual;
        public ulong AvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX buffer);

    // ---- Foreground window ----
    [DllImport("user32.dll")]
    internal static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    internal static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);

    // ---- Window facts (game detection) ----
    internal const int GWL_STYLE = -16;
    internal const int GWL_EXSTYLE = -20;
    internal const uint MONITOR_DEFAULTTONEAREST = 2;

    [StructLayout(LayoutKind.Sequential)]
    internal struct RECT
    {
        public int Left, Top, Right, Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MONITORINFO
    {
        public uint Size;
        public RECT Monitor;
        public RECT Work;
        public uint Flags;
    }

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);

    [DllImport("user32.dll", SetLastError = true, EntryPoint = "GetWindowLongPtrW")]
    internal static extern IntPtr GetWindowLongPtr(IntPtr hwnd, int index);

    [DllImport("user32.dll")]
    internal static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    internal static extern bool GetMonitorInfoW(IntPtr monitor, ref MONITORINFO info);

    // ---- Idle detection ----
    [StructLayout(LayoutKind.Sequential)]
    internal struct LASTINPUTINFO
    {
        public uint Size;
        public uint Time; // tick count of last input
    }

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern bool GetLastInputInfo(ref LASTINPUTINFO info);

    // ---- Job objects (CPU limiter) ----
    internal const int JobObjectCpuRateControlInformation = 15;
    internal const uint JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x1;
    internal const uint JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x4;

    [StructLayout(LayoutKind.Sequential)]
    internal struct JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
    {
        public uint ControlFlags;
        /// <summary>Portion of 10000 across all cores (e.g. 2500 = 25 %).</summary>
        public uint CpuRate;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr CreateJobObjectW(IntPtr securityAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool AssignProcessToJobObject(IntPtr job, SafeProcessHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool SetInformationJobObject(IntPtr job, int informationClass,
        ref JOBOBJECT_CPU_RATE_CONTROL_INFORMATION information, int length);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool CloseHandle(IntPtr handle);

    // ---- Standby list purge ----
    internal const int SystemMemoryListInformationClass = 80;
    internal const int MemoryPurgeStandbyList = 4;
    internal const uint SE_PRIVILEGE_ENABLED = 0x2;
    internal const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
    internal const uint TOKEN_QUERY = 0x8;

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [DllImport("ntdll.dll")]
    internal static extern int NtSetSystemInformation(int informationClass, ref int information, int length);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool LookupPrivilegeValueW(string? systemName, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
        ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll")]
    internal static extern IntPtr GetCurrentProcess();

    // ---- Timer resolution ----
    /// <summary>Requested/actual values are in 100 ns units. Returns NTSTATUS.</summary>
    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtSetTimerResolution(uint desiredResolution, bool setResolution, out uint currentResolution);

    [DllImport("ntdll.dll", SetLastError = true)]
    internal static extern int NtQueryTimerResolution(out uint minimum, out uint maximum, out uint current);

    // ---- Keep awake ----
    internal const uint ES_CONTINUOUS = 0x80000000;
    internal const uint ES_SYSTEM_REQUIRED = 0x00000001;
    internal const uint ES_DISPLAY_REQUIRED = 0x00000002;

    /// <summary>The state is per-thread: call from a long-lived dedicated thread only.</summary>
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint SetThreadExecutionState(uint flags);
}
