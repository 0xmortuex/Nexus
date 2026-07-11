using System.Diagnostics;
using Nexus.App.Interop;
using Nexus.Core.GameMode;

namespace Nexus.App.Services;

public sealed record ForegroundSample(int Pid, WindowInfo Window, RectPx MonitorRect);

/// <summary>
/// Polls the foreground window every 750 ms and reports (pid, window rect/styles,
/// monitor rect). Polling is used instead of SetWinEventHook deliberately: the hook
/// needs a message pump on its thread and silently dies with it, while a poll at
/// this rate is unmeasurable and works from any service context.
/// </summary>
public sealed class ForegroundMonitor : IDisposable
{
    private System.Threading.Timer? _timer;

    /// <summary>Fires on every poll (not only on change) — consumers keep their own state.</summary>
    public event Action<ForegroundSample?>? Sampled;

    public void Start()
    {
        _timer = new System.Threading.Timer(_ => Tick(), null,
            TimeSpan.FromMilliseconds(750), TimeSpan.FromMilliseconds(750));
    }

    private void Tick()
    {
        try
        {
            Sampled?.Invoke(Capture());
        }
        catch (Exception)
        {
            // A failed capture is just skipped; next poll is 750 ms away.
        }
    }

    private ForegroundSample? Capture()
    {
        var hwnd = NativeMethods.GetForegroundWindow();
        if (hwnd == IntPtr.Zero)
            return null;

        _ = NativeMethods.GetWindowThreadProcessId(hwnd, out var pid);
        if (pid == 0)
            return null;

        string exeName;
        try
        {
            using var process = Process.GetProcessById((int)pid);
            exeName = process.ProcessName + ".exe";
        }
        catch (ArgumentException)
        {
            return null; // exited between calls
        }

        if (!NativeMethods.GetWindowRect(hwnd, out var rect))
            return null;

        var monitor = NativeMethods.MonitorFromWindow(hwnd, NativeMethods.MONITOR_DEFAULTTONEAREST);
        var monitorInfo = new NativeMethods.MONITORINFO
        {
            Size = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.MONITORINFO>(),
        };
        if (monitor == IntPtr.Zero || !NativeMethods.GetMonitorInfoW(monitor, ref monitorInfo))
            return null;

        uint style = unchecked((uint)(long)NativeMethods.GetWindowLongPtr(hwnd, NativeMethods.GWL_STYLE));
        uint exStyle = unchecked((uint)(long)NativeMethods.GetWindowLongPtr(hwnd, NativeMethods.GWL_EXSTYLE));

        return new ForegroundSample(
            (int)pid,
            new WindowInfo(exeName,
                new RectPx(rect.Left, rect.Top, rect.Right, rect.Bottom), style, exStyle),
            new RectPx(monitorInfo.Monitor.Left, monitorInfo.Monitor.Top,
                monitorInfo.Monitor.Right, monitorInfo.Monitor.Bottom));
    }

    public void Dispose() => _timer?.Dispose();
}
