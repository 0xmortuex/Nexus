using System.IO;
using System.Management;
using Microsoft.Win32;
using Nexus.Core.Logging;
using Nexus.Core.Security.Persistence;

namespace Nexus.App.Services.Security;

/// <summary>
/// Reads how Windows is configured to defend itself: firewall, UAC, SmartScreen,
/// Secure Boot, drive encryption and when updates last landed.
///
/// Read-only, and deliberately so. Several of these are switched off for good
/// reasons — a developer turns SmartScreen off because it blocks their own unsigned
/// builds, a managed network handles the firewall centrally, a dual-boot machine has
/// Secure Boot off because it has to. A tool that "fixes" those breaks people's
/// machines with the best of intentions.
///
/// Every reader returns null when it cannot tell, and null produces no finding at
/// all. Reading these keys can fail on a locked-down machine, and a permission
/// failure must never be reported as a setting being switched off.
/// </summary>
public sealed class SecurityPostureService
{
    private const string FirewallRoot =
        @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

    private const string PoliciesSystem =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

    private readonly ActivityLog _log;

    public SecurityPostureService(ActivityLog log)
    {
        _log = log;
    }

    public SecurityPostureFacts Collect()
    {
        return new SecurityPostureFacts
        {
            FirewallDomain = ReadFirewallProfile("DomainProfile"),
            FirewallPrivate = ReadFirewallProfile("StandardProfile"),
            FirewallPublic = ReadFirewallProfile("PublicProfile"),
            UacEnabled = ReadFlag(Registry.LocalMachine, PoliciesSystem, "EnableLUA"),
            UacPromptLevel = ReadInt(Registry.LocalMachine, PoliciesSystem, "ConsentPromptBehaviorAdmin"),
            SmartScreenEnabled = ReadSmartScreen(),
            SecureBootEnabled = ReadFlag(
                Registry.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled"),
            SystemDriveEncrypted = ReadSystemDriveEncrypted(),
            LastUpdateInstalled = ReadLastUpdate(),
        };
    }

    /// <summary>
    /// Group Policy overrides the local setting, so it is checked first. A machine
    /// whose policy disables the firewall reports it as disabled even though the
    /// local value still says otherwise.
    /// </summary>
    private bool? ReadFirewallProfile(string profile)
    {
        return ReadFlag(Registry.LocalMachine, $@"{FirewallRoot}\{profile}", "EnableFirewall")
               ?? ReadFlag(Registry.LocalMachine,
                   $@"SOFTWARE\Policies\Microsoft\WindowsFirewall\{profile}", "EnableFirewall");
    }

    /// <summary>
    /// SmartScreen has been spelled several ways across Windows versions: a string
    /// ("Off"/"Warn"/"RequireAdmin") on older builds, a DWORD policy on newer ones.
    /// Checking only one of them reports a machine as unprotected because the setting
    /// moved.
    /// </summary>
    private bool? ReadSmartScreen()
    {
        // Group Policy wins where it is set.
        var policy = ReadInt(Registry.LocalMachine,
            @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen");

        if (policy is { } value)
            return value != 0;

        // Where Windows 11 actually keeps it. Checked against a real machine, which is
        // how the first two candidates turned out to be absent on a current build.
        var appHost = ReadInt(Registry.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost", "EnableWebContentEvaluation")
            ?? ReadInt(Registry.CurrentUser,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost", "EnableWebContentEvaluation");

        if (appHost is { } appHostValue)
            return appHostValue != 0;

        // The pre-Windows-10 spelling: "Off", "Warn" or "RequireAdmin".
        var explorer = ReadString(Registry.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled");

        if (explorer is { Length: > 0 })
            return !explorer.Equals("Off", StringComparison.OrdinalIgnoreCase);

        return null;
    }

    /// <summary>
    /// Whether the drive Windows is on is encrypted.
    ///
    /// Asked of WMI rather than the registry: the BitLockerStatus registry key does
    /// not exist on a real Windows 11 machine, so the registry approach reported
    /// "unknown" every time while looking like it worked.
    ///
    /// The provider only exists where BitLocker does, so a Home edition answers
    /// nothing at all — which stays unknown rather than becoming a finding on every
    /// Home machine.
    /// </summary>
    private bool? ReadSystemDriveEncrypted()
    {
        try
        {
            var systemDrive = Path.GetPathRoot(Environment.SystemDirectory);
            if (systemDrive is not { Length: > 0 })
                return null;

            var letter = systemDrive[..2];

            using var searcher = new ManagementObjectSearcher(
                @"root\CIMV2\Security\MicrosoftVolumeEncryption",
                $"SELECT ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter = '{letter}'");

            foreach (var volume in searcher.Get())
            {
                using (volume)
                {
                    // 0 = off, 1 = on, 2 = on but the key is not yet secured.
                    if (volume["ProtectionStatus"] is uint status)
                        return status != 0;
                }
            }

            return null;
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException
                                      or System.Runtime.InteropServices.COMException
                                      or PlatformNotSupportedException)
        {
            // No BitLocker on this edition, or not enough rights to ask.
            return null;
        }
    }

    private DateTimeOffset? ReadLastUpdate()
    {
        var raw = ReadString(Registry.LocalMachine,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install",
            "LastSuccessTime");

        // Windows writes this as local time in "yyyy-MM-dd HH:mm:ss".
        if (raw is { Length: > 0 } && DateTime.TryParse(raw, out var parsed))
            return new DateTimeOffset(DateTime.SpecifyKind(parsed, DateTimeKind.Local));

        // That key is frequently absent — it was missing on the machine this was
        // written against, while the update history plainly showed a patch from two
        // days earlier. Reporting "updates are stale" off a missing registry value
        // would have been wrong in the most alarming direction.
        return ReadNewestHotfix();
    }

    private DateTimeOffset? ReadNewestHotfix()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT InstalledOn FROM Win32_QuickFixEngineering");

            DateTimeOffset? newest = null;

            foreach (var hotfix in searcher.Get())
            {
                using (hotfix)
                {
                    if (hotfix["InstalledOn"] is not string installed || installed.Length == 0)
                        continue;

                    if (!DateTime.TryParse(installed, out var when))
                        continue;

                    var moment = new DateTimeOffset(DateTime.SpecifyKind(when, DateTimeKind.Local));
                    if (newest is null || moment > newest)
                        newest = moment;
                }
            }

            return newest;
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException
                                      or System.Runtime.InteropServices.COMException
                                      or PlatformNotSupportedException)
        {
            _log.Info("Sentinel", $"Could not read the Windows update history: {ex.Message}");
            return null;
        }
    }

    private bool? ReadFlag(RegistryKey root, string path, string name) =>
        ReadInt(root, path, name) is { } value ? value != 0 : null;

    private int? ReadInt(RegistryKey root, string path, string name)
    {
        try
        {
            using var key = root.OpenSubKey(path);
            return key?.GetValue(name) as int?;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            _log.Info("Sentinel", $"Could not read {path}\\{name}: {ex.Message}");
            return null;
        }
    }

    private string? ReadString(RegistryKey root, string path, string name)
    {
        try
        {
            using var key = root.OpenSubKey(path);
            return key?.GetValue(name) as string;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            _log.Info("Sentinel", $"Could not read {path}\\{name}: {ex.Message}");
            return null;
        }
    }
}
