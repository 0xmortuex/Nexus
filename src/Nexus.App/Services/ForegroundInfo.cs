using Nexus.App.Interop;

namespace Nexus.App.Services;

/// <summary>Small helper answering "which PID owns the foreground window right now".</summary>
public static class ForegroundInfo
{
    public static int? GetForegroundPid()
    {
        try
        {
            var hwnd = NativeMethods.GetForegroundWindow();
            if (hwnd == IntPtr.Zero)
                return null;
            _ = NativeMethods.GetWindowThreadProcessId(hwnd, out var pid);
            return pid == 0 ? null : (int)pid;
        }
        catch (Exception)
        {
            return null;
        }
    }
}
