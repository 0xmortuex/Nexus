namespace Nexus.Core.Security.Persistence;

/// <summary>
/// The machine's security settings, as read from the system.
///
/// Every field is nullable, and that is the whole design. "Off" and "could not tell"
/// are different answers, and collapsing them is how a permission failure turns into
/// an accusation — the same mistake that had Nexus reporting conhost.exe as
/// masquerading because it could not read the process path. A null here produces no
/// signal at all.
/// </summary>
public sealed record SecurityPostureFacts
{
    public bool? FirewallDomain { get; init; }
    public bool? FirewallPrivate { get; init; }
    public bool? FirewallPublic { get; init; }

    /// <summary>User Account Control. Off means any program that asks for
    /// administrator rights simply gets them.</summary>
    public bool? UacEnabled { get; init; }

    /// <summary>ConsentPromptBehaviorAdmin. 0 means elevate with no prompt at all.</summary>
    public int? UacPromptLevel { get; init; }

    public bool? SmartScreenEnabled { get; init; }
    public bool? SecureBootEnabled { get; init; }
    public bool? SystemDriveEncrypted { get; init; }

    /// <summary>When Windows Update last installed something successfully.</summary>
    public DateTimeOffset? LastUpdateInstalled { get; init; }
}

/// <summary>
/// Reports how the machine is configured to defend itself.
///
/// None of this is about malware being present. It is about whether the doors are
/// shut, which is a question no scan answers and which people genuinely do not know
/// about their own machine — settings get changed by a game guide, a "fix your
/// network" forum post, or an installer years ago, and nothing ever mentions it again.
///
/// Nexus changes none of it. Some of these are switched off deliberately and for good
/// reasons: developers turn off SmartScreen because it blocks their own unsigned
/// builds, and a machine on a managed network may have its firewall handled
/// elsewhere. Reporting is useful; deciding is not Nexus's job.
/// </summary>
public static class SecurityPostureAudit
{
    /// <summary>Windows Update quiet for longer than this is worth mentioning.</summary>
    public static readonly TimeSpan StaleUpdateThreshold = TimeSpan.FromDays(60);

    public static IReadOnlyList<SecuritySignal> Evaluate(SecurityPostureFacts facts, DateTimeOffset now)
    {
        var signals = new List<SecuritySignal>();

        AddFirewallSignals(facts, signals);
        AddUacSignals(facts, signals);
        AddSmartScreenSignal(facts, signals);
        AddSecureBootSignal(facts, signals);
        AddEncryptionSignal(facts, signals);
        AddUpdateSignal(facts, now, signals);

        return signals;
    }

    private static void AddFirewallSignals(SecurityPostureFacts facts, List<SecuritySignal> signals)
    {
        var off = new List<string>();

        if (facts.FirewallPublic == false)
            off.Add("public networks");
        if (facts.FirewallPrivate == false)
            off.Add("private networks");
        if (facts.FirewallDomain == false)
            off.Add("domain networks");

        if (off.Count == 0)
            return;

        // Public is the profile that matters: it is what a laptop uses on café and
        // airport wifi, where anything else on the network is a stranger.
        bool publicOff = facts.FirewallPublic == false;

        signals.Add(new SecuritySignal(
            SignalSource.Persistence,
            publicOff ? SignalWeight.Moderate : SignalWeight.Weak,
            "posture-firewall-off",
            $"The Windows firewall is switched off for {string.Join(", ", off)}. " +
            (publicOff
                ? "That is the setting used on public wifi, where everything else on the network " +
                  "belongs to someone else."
                : "Some networks are managed centrally and turn this off deliberately.")));
    }

    private static void AddUacSignals(SecurityPostureFacts facts, List<SecuritySignal> signals)
    {
        if (facts.UacEnabled == false)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Moderate,
                "posture-uac-off",
                "User Account Control is switched off. Any program that asks for administrator " +
                "rights is given them without asking you, which removes the last step between " +
                "running something and it being able to change the whole machine."));

            return;
        }

        // 0 = elevate silently. The prompt is the entire mechanism; without it UAC is
        // on in name only, which is worse than off because it looks protected.
        if (facts.UacEnabled == true && facts.UacPromptLevel == 0)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Moderate,
                "posture-uac-silent",
                "User Account Control is on, but set to elevate without prompting. Programs get " +
                "administrator rights with no prompt shown, so the protection reads as active " +
                "while doing nothing."));
        }
    }

    private static void AddSmartScreenSignal(SecurityPostureFacts facts, List<SecuritySignal> signals)
    {
        if (facts.SmartScreenEnabled != false)
            return;

        signals.Add(new SecuritySignal(
            SignalSource.Persistence,
            SignalWeight.Weak,
            "posture-smartscreen-off",
            "SmartScreen is off, so Windows will not warn you about programs downloaded from the " +
            "internet that it does not recognise. Plenty of people turn this off on purpose because " +
            "it blocks their own unsigned builds."));
    }

    private static void AddSecureBootSignal(SecurityPostureFacts facts, List<SecuritySignal> signals)
    {
        if (facts.SecureBootEnabled != false)
            return;

        signals.Add(new SecuritySignal(
            SignalSource.Persistence,
            SignalWeight.Informational,
            "posture-secure-boot-off",
            "Secure Boot is off. It is commonly off on machines that dual-boot Linux or use older " +
            "hardware, and turning it on is a firmware setting rather than a Windows one."));
    }

    private static void AddEncryptionSignal(SecurityPostureFacts facts, List<SecuritySignal> signals)
    {
        if (facts.SystemDriveEncrypted != false)
            return;

        signals.Add(new SecuritySignal(
            SignalSource.Persistence,
            SignalWeight.Informational,
            "posture-drive-not-encrypted",
            "The system drive is not encrypted. That matters if the machine is lost or stolen — " +
            "anyone who can hold the disk can read everything on it — and matters very little " +
            "otherwise. It is not a malware risk."));
    }

    private static void AddUpdateSignal(SecurityPostureFacts facts, DateTimeOffset now, List<SecuritySignal> signals)
    {
        if (facts.LastUpdateInstalled is not { } last)
            return;

        var age = now - last;
        if (age < StaleUpdateThreshold)
            return;

        signals.Add(new SecuritySignal(
            SignalSource.Persistence,
            SignalWeight.Weak,
            "posture-updates-stale",
            $"Windows last installed an update {(int)age.TotalDays} days ago. Most of what actually " +
            "compromises a machine uses a hole that was patched months earlier."));
    }
}
