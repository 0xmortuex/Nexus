namespace Nexus.Core.Tweaks;

/// <summary>
/// The curated tweak list. Descriptions are deliberately sober — the UI labels this
/// tab "Tweaks — measure before trusting", and nothing here promises FPS.
/// </summary>
public static class TweakCatalog
{
    private const string Hklm = "HKEY_LOCAL_MACHINE";
    private const string Hkcu = "HKEY_CURRENT_USER";
    private const string PriorityControl = $@"{Hklm}\SYSTEM\CurrentControlSet\Control\PriorityControl";
    private const string SystemProfile = $@"{Hklm}\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile";
    private const string GamesTask = $@"{SystemProfile}\Tasks\Games";

    public static IReadOnlyList<TweakDefinition> All { get; } =
    [
        // ---- CPU scheduling ----
        new TweakDefinition
        {
            Id = "priosep-gaming-short",
            Name = "Win32PrioritySeparation: short quanta, high foreground boost (0x26)",
            Category = "CPU scheduling",
            Description = "Foreground apps get more scheduler attention; can smooth frame pacing slightly, can also cost background throughput.",
            RegistryOps = [new(PriorityControl, "Win32PrioritySeparation", "dword", "0x26")],
        },
        new TweakDefinition
        {
            Id = "priosep-balanced",
            Name = "Win32PrioritySeparation: Windows default (0x2)",
            Category = "CPU scheduling",
            Description = "Restores the stock scheduler quantum policy — use to compare against the presets.",
            RegistryOps = [new(PriorityControl, "Win32PrioritySeparation", "dword", "0x2")],
        },
        new TweakDefinition
        {
            Id = "priosep-long-fixed",
            Name = "Win32PrioritySeparation: long fixed quanta (0x18)",
            Category = "CPU scheduling",
            Description = "Server-style long quanta; fewer context switches, slightly worse input responsiveness. Niche.",
            RegistryOps = [new(PriorityControl, "Win32PrioritySeparation", "dword", "0x18")],
        },

        // ---- Capture / overlay ----
        new TweakDefinition
        {
            Id = "gamedvr-off",
            Name = "Disable GameDVR / Game Bar background capture",
            Category = "Capture & overlays",
            Description = "Stops the background clip recorder; measurable gain only if it was actually recording (a few % GPU/CPU at most).",
            RegistryOps =
            [
                new($@"{Hkcu}\System\GameConfigStore", "GameDVR_Enabled", "dword", "0"),
                new($@"{Hkcu}\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled", "dword", "0"),
                new($@"{Hklm}\SOFTWARE\Policies\Microsoft\Windows\GameDVR", "AllowGameDVR", "dword", "0"),
            ],
        },

        // ---- GPU ----
        new TweakDefinition
        {
            Id = "hags-on",
            Name = "Hardware-accelerated GPU scheduling: ON",
            Category = "GPU",
            Description = "Can reduce latency a little on modern GPUs/drivers; on some driver versions it causes stutter instead. Reboot required.",
            RequiresReboot = true,
            RegistryOps = [new($@"{Hklm}\SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode", "dword", "2")],
        },
        new TweakDefinition
        {
            Id = "hags-off",
            Name = "Hardware-accelerated GPU scheduling: OFF",
            Category = "GPU",
            Description = "The inverse switch — try OFF if you see stutter with HAGS on. Reboot required.",
            RequiresReboot = true,
            RegistryOps = [new($@"{Hklm}\SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode", "dword", "1")],
        },

        // ---- Input ----
        new TweakDefinition
        {
            Id = "mouse-accel-off",
            Name = "Disable mouse acceleration (Enhance pointer precision)",
            Category = "Input",
            Description = "Makes mouse distance deterministic — genuinely useful for aim consistency; no performance change.",
            RegistryOps =
            [
                new($@"{Hkcu}\Control Panel\Mouse", "MouseSpeed", "string", "0"),
                new($@"{Hkcu}\Control Panel\Mouse", "MouseThreshold1", "string", "0"),
                new($@"{Hkcu}\Control Panel\Mouse", "MouseThreshold2", "string", "0"),
            ],
        },

        // ---- Network ----
        new TweakDefinition
        {
            Id = "nagle-off",
            Name = "Disable Nagle's algorithm (TcpAckFrequency / TCPNoDelay)",
            Category = "Network",
            Description = "May shave a few ms in some older/chatty-protocol games; most modern games set TCP_NODELAY themselves or use UDP — often zero effect.",
            PerNetworkAdapter = true,
            RegistryOps =
            [
                new($@"{Hklm}\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{adapter}}", "TcpAckFrequency", "dword", "1"),
                new($@"{Hklm}\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{adapter}}", "TCPNoDelay", "dword", "1"),
            ],
        },
        new TweakDefinition
        {
            Id = "network-throttling-off",
            Name = "Disable network throttling index",
            Category = "Network",
            Description = "Removes the 10-packets-per-ms cap applied while multimedia plays; relevant mainly for high-bandwidth streaming while gaming.",
            RegistryOps = [new(SystemProfile, "NetworkThrottlingIndex", "dword", "0xffffffff")],
        },

        // ---- MMCSS ----
        new TweakDefinition
        {
            Id = "mmcss-gaming",
            Name = "MMCSS: prioritize the Games task",
            Category = "CPU scheduling",
            Description = "Raises the multimedia scheduler class for games and reserves less CPU for background (SystemResponsiveness 10); subtle at best.",
            RegistryOps =
            [
                new(SystemProfile, "SystemResponsiveness", "dword", "10"),
                new(GamesTask, "GPU Priority", "dword", "8"),
                new(GamesTask, "Priority", "dword", "6"),
                new(GamesTask, "Scheduling Category", "string", "High"),
                new(GamesTask, "SFIO Priority", "string", "High"),
            ],
        },

        // ---- Shell / visuals ----
        new TweakDefinition
        {
            Id = "visual-effects-performance",
            Name = "Visual effects: adjust for best performance",
            Category = "Shell & visuals",
            Description = "Disables shell animations/shadows. Helps on weak iGPUs and old machines; imperceptible on gaming hardware. Sign out/in to fully apply.",
            RegistryOps = [new($@"{Hkcu}\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", "VisualFXSetting", "dword", "2")],
        },
        new TweakDefinition
        {
            Id = "transparency-off",
            Name = "Disable window transparency effects",
            Category = "Shell & visuals",
            Description = "Removes acrylic/blur composition cost — tiny GPU saving, mostly a preference.",
            RegistryOps = [new($@"{Hkcu}\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency", "dword", "0")],
        },
        new TweakDefinition
        {
            Id = "animations-off",
            Name = "Disable window/taskbar animations",
            Category = "Shell & visuals",
            Description = "The desktop feels snappier because animations no longer play; frame rates in games are unaffected.",
            RegistryOps =
            [
                new($@"{Hkcu}\Control Panel\Desktop\WindowMetrics", "MinAnimate", "string", "0"),
                new($@"{Hkcu}\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarAnimations", "dword", "0"),
            ],
        },

        new TweakDefinition
        {
            Id = "windows-game-mode-on",
            Name = "Windows Game Mode: ON",
            Category = "Capture & overlays",
            Description = "Lets Windows deprioritize background work while a game runs; usually neutral-to-slightly-positive on modern builds.",
            RegistryOps = [new($@"{Hkcu}\SOFTWARE\Microsoft\GameBar", "AutoGameModeEnabled", "dword", "1")],
        },
        new TweakDefinition
        {
            Id = "fse-optimizations-off",
            Name = "Disable fullscreen optimizations globally",
            Category = "Capture & overlays",
            Description = "Forces classic exclusive fullscreen behavior for legacy games; on current Windows 11 the optimized path is usually equal or better — test per game.",
            RegistryOps =
            [
                new($@"{Hkcu}\System\GameConfigStore", "GameDVR_FSEBehaviorMode", "dword", "2"),
                new($@"{Hkcu}\System\GameConfigStore", "GameDVR_HonorUserFSEBehaviorMode", "dword", "1"),
                new($@"{Hkcu}\System\GameConfigStore", "GameDVR_DXGIHonorFSEWindowsCompatible", "dword", "1"),
                new($@"{Hkcu}\System\GameConfigStore", "GameDVR_EFSEFeatureFlags", "dword", "0"),
            ],
        },

        // ---- Gaming ----
        new TweakDefinition
        {
            Id = "power-throttling-off",
            Name = "Disable global CPU power throttling",
            Category = "Gaming",
            Description = "Stops Windows from EcoQoS-throttling processes it deems background, system-wide. Costs battery on laptops; use on desktops.",
            RegistryOps = [new($@"{Hklm}\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling", "PowerThrottlingOff", "dword", "1")],
        },
        new TweakDefinition
        {
            Id = "sticky-keys-off",
            Name = "Disable Sticky Keys shortcut (5× Shift)",
            Category = "Input",
            Description = "Stops the Sticky Keys prompt from interrupting games when Shift is tapped repeatedly. Pure quality-of-life.",
            RegistryOps = [new($@"{Hkcu}\Control Panel\Accessibility\StickyKeys", "Flags", "string", "506")],
        },

        // ---- Power ----
        new TweakDefinition
        {
            Id = "hibernation-off",
            Name = "Disable hibernation",
            Category = "Power & storage",
            Description = "Frees hiberfil.sys (GBs of disk) and disables Fast Startup; no runtime performance change.",
            Risk = TweakRisk.Medium,
            Commands = [new("powercfg.exe", "/hibernate off", "/hibernate on")],
        },
    ];

    public static TweakDefinition? Find(string id) => All.FirstOrDefault(t => t.Id == id);
}
