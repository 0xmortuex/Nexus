using Nexus.Core.Models;

namespace Nexus.Core.GameMode;

public sealed record RectPx(int Left, int Top, int Right, int Bottom)
{
    public int Width => Right - Left;
    public int Height => Bottom - Top;
}

/// <summary>Facts about the current foreground window, gathered by interop.</summary>
public sealed record WindowInfo(string ExeName, RectPx WindowRect, uint Style, uint ExStyle);

/// <summary>
/// Pure heuristic deciding whether the foreground window is a game:
/// user-listed exes always count; known non-games never do; otherwise a window
/// counts when it covers its whole monitor without a caption bar
/// (exclusive fullscreen and borderless windowed both match).
/// </summary>
public static class GameDetector
{
    private const uint WS_CAPTION = 0x00C00000;
    private const int FullscreenTolerancePx = 2;

    /// <summary>Apps that regularly run fullscreen/borderless but are not games.</summary>
    private static readonly HashSet<string> KnownNonGames = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "searchhost.exe", "lockapp.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
        "opera_gx.exe", "vivaldi.exe", "arc.exe",
        "vlc.exe", "wmplayer.exe", "mpc-hc64.exe", "mpv.exe",
        "netflix.exe", "video.ui.exe", "spotify.exe",
        "powerpnt.exe", "acrord32.exe",
        "devenv.exe", "code.exe", "rider64.exe",
        "taskmgr.exe", "mstsc.exe", "vmware.exe", "vmconnect.exe", "virtualboxvm.exe",
        "obs64.exe", "obs32.exe",
        "steam.exe", "steamwebhelper.exe", "epicgameslauncher.exe",
        "battle.net.exe", "eadesktop.exe", "galaxyclient.exe", "riotclientservices.exe",
        "nexus.exe",
    };

    public static bool LooksLikeGame(
        WindowInfo window,
        RectPx monitorRect,
        IReadOnlyCollection<string> userGameList,
        IReadOnlyCollection<string> userIgnoreList)
    {
        var exe = ProcessRule.Normalize(window.ExeName);

        if (Contains(userIgnoreList, exe))
            return false;
        if (Contains(userGameList, exe))
            return true;
        if (KnownNonGames.Contains(exe) || ProcessSafety.IsProtected(exe))
            return false;

        return CoversMonitor(window.WindowRect, monitorRect) && (window.Style & WS_CAPTION) != WS_CAPTION;
    }

    private static bool CoversMonitor(RectPx window, RectPx monitor)
    {
        return window.Left <= monitor.Left + FullscreenTolerancePx
            && window.Top <= monitor.Top + FullscreenTolerancePx
            && window.Right >= monitor.Right - FullscreenTolerancePx
            && window.Bottom >= monitor.Bottom - FullscreenTolerancePx
            && monitor.Width > 0 && monitor.Height > 0;
    }

    private static bool Contains(IReadOnlyCollection<string> list, string normalizedExe)
        => list.Any(entry => ProcessRule.Normalize(entry) == normalizedExe);
}
