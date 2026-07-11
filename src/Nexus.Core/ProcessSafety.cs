namespace Nexus.Core;

/// <summary>
/// The hard-coded never-touch list. Checked before EVERY mutating action (priority,
/// affinity, IO/memory priority, EcoQoS, trim, kill) — not just termination.
/// Touching these can crash Windows, break audio, or trip anti-cheat integrity checks.
/// </summary>
public static class ProcessSafety
{
    private static readonly HashSet<string> NeverTouch = new(StringComparer.OrdinalIgnoreCase)
    {
        // Windows core — killing or demoting these can bluescreen or hang the OS.
        "system", "secure system", "registry", "memory compression",
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
        "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe",
        "dwm.exe", "fontdrvhost.exe", "sihost.exe", "ctfmon.exe",
        "conhost.exe", "taskhostw.exe", "runtimebroker.exe", "wudfhost.exe",
        // Audio — restraining these causes crackling/dropouts.
        "audiodg.exe", "audiosrv.exe",
        // Defender.
        "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe",
        // Anti-cheat — touching these can flag or ban the account.
        "easyanticheat.exe", "easyanticheat_eos.exe", "beservice.exe", "bedaisy.exe",
        "vgc.exe", "vgk.exe", "vgtray.exe", "faceitclient.exe", "faceitservice.exe",
        "eseadriver.exe", "eseadriver2.exe", "anticheatexpert.exe", "ace-guard.exe",
        "xigncode3.exe", "gameguard.des", "npggnt.des", "hackshield.exe",
    };

    private static readonly string[] NeverTouchPrefixes =
    {
        "easyanticheat", "faceit", "vanguard",
    };

    /// <summary>True if no Nexus feature may modify or terminate this process.</summary>
    public static bool IsProtected(string exeName)
    {
        var name = exeName.Trim();
        if (NeverTouch.Contains(name))
            return true;
        // Also match names passed without extension.
        if (!name.Contains('.') && NeverTouch.Contains(name + ".exe"))
            return true;

        foreach (var prefix in NeverTouchPrefixes)
        {
            if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>Processes that ProBalance/SmartTrim must additionally leave alone even
    /// though direct user-initiated actions on them are allowed.</summary>
    private static readonly HashSet<string> RestraintExempt = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "searchhost.exe", "startmenuexperiencehost.exe",
        "shellexperiencehost.exe", "applicationframehost.exe", "systemsettings.exe",
        "nexus.exe",
    };

    public static bool IsRestraintExempt(string exeName)
        => IsProtected(exeName) || RestraintExempt.Contains(exeName.Trim());
}
