using Nexus.Core.Security;
using Nexus.Core.Security.Persistence;
using Xunit;

namespace Nexus.Core.Tests;

public class SecurityPostureAuditTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 31, 12, 0, 0, TimeSpan.Zero);

    private static string[] Codes(SecurityPostureFacts facts) =>
        SecurityPostureAudit.Evaluate(facts, Now).Select(s => s.Code).ToArray();

    /// <summary>
    /// The rule this whole type is built around. Nexus cannot always read these
    /// settings, and "could not tell" must never be reported as "switched off" — that
    /// is the mistake that had a process with an unreadable path accused of
    /// masquerading.
    /// </summary>
    [Fact]
    public void Settings_that_could_not_be_read_produce_nothing()
    {
        Assert.Empty(SecurityPostureAudit.Evaluate(new SecurityPostureFacts(), Now));
    }

    [Fact]
    public void A_properly_configured_machine_produces_nothing()
    {
        var facts = new SecurityPostureFacts
        {
            FirewallDomain = true,
            FirewallPrivate = true,
            FirewallPublic = true,
            UacEnabled = true,
            UacPromptLevel = 5,
            SmartScreenEnabled = true,
            SecureBootEnabled = true,
            SystemDriveEncrypted = true,
            LastUpdateInstalled = Now.AddDays(-3),
        };

        Assert.Empty(SecurityPostureAudit.Evaluate(facts, Now));
    }

    // ---- Firewall ----

    [Fact]
    public void The_public_profile_being_off_is_weighted_above_the_others()
    {
        var onPublic = SecurityPostureAudit.Evaluate(
            new SecurityPostureFacts { FirewallPublic = false }, Now);
        var onDomain = SecurityPostureAudit.Evaluate(
            new SecurityPostureFacts { FirewallDomain = false }, Now);

        Assert.Equal(SignalWeight.Moderate, Assert.Single(onPublic).Weight);

        // A managed network may turn the domain profile off deliberately.
        Assert.Equal(SignalWeight.Weak, Assert.Single(onDomain).Weight);
    }

    [Fact]
    public void Every_disabled_profile_is_named_in_one_signal()
    {
        var signal = Assert.Single(SecurityPostureAudit.Evaluate(
            new SecurityPostureFacts { FirewallPublic = false, FirewallPrivate = false }, Now));

        Assert.Contains("public networks", signal.Explanation);
        Assert.Contains("private networks", signal.Explanation);
    }

    // ---- UAC ----

    [Fact]
    public void Uac_switched_off_is_reported()
    {
        Assert.Contains("posture-uac-off", Codes(new SecurityPostureFacts { UacEnabled = false }));
    }

    /// <summary>
    /// UAC on but set to elevate silently is the worse case of the two, because the
    /// machine reports itself as protected while the prompt — the entire mechanism —
    /// never appears.
    /// </summary>
    [Fact]
    public void Uac_that_never_prompts_is_reported_even_though_it_is_enabled()
    {
        Assert.Contains("posture-uac-silent",
            Codes(new SecurityPostureFacts { UacEnabled = true, UacPromptLevel = 0 }));
    }

    [Fact]
    public void A_normal_uac_prompt_level_is_not_reported()
    {
        Assert.Empty(Codes(new SecurityPostureFacts { UacEnabled = true, UacPromptLevel = 5 }));
    }

    [Fact]
    public void Uac_being_off_is_not_also_reported_as_never_prompting()
    {
        var codes = Codes(new SecurityPostureFacts { UacEnabled = false, UacPromptLevel = 0 });

        Assert.Contains("posture-uac-off", codes);
        Assert.DoesNotContain("posture-uac-silent", codes);
    }

    // ---- The softer ones ----

    /// <summary>
    /// These are configuration choices, not evidence of anything. Weighting them like
    /// malware is how a security tool starts nagging.
    /// </summary>
    [Theory]
    [InlineData("posture-secure-boot-off")]
    [InlineData("posture-drive-not-encrypted")]
    public void Hardware_and_privacy_settings_are_informational_only(string code)
    {
        var facts = new SecurityPostureFacts { SecureBootEnabled = false, SystemDriveEncrypted = false };

        var signal = Assert.Single(SecurityPostureAudit.Evaluate(facts, Now), s => s.Code == code);

        Assert.Equal(SignalWeight.Informational, signal.Weight);
        Assert.Equal(0, signal.Points);
    }

    [Fact]
    public void Smartscreen_off_is_weak_because_developers_turn_it_off_on_purpose()
    {
        var signal = Assert.Single(SecurityPostureAudit.Evaluate(
            new SecurityPostureFacts { SmartScreenEnabled = false }, Now));

        Assert.Equal(SignalWeight.Weak, signal.Weight);
    }

    // ---- Updates ----

    [Fact]
    public void Recent_updates_are_not_reported()
    {
        Assert.Empty(Codes(new SecurityPostureFacts { LastUpdateInstalled = Now.AddDays(-10) }));
    }

    [Fact]
    public void Updates_that_stopped_months_ago_are_reported_with_the_number_of_days()
    {
        var signal = Assert.Single(SecurityPostureAudit.Evaluate(
            new SecurityPostureFacts { LastUpdateInstalled = Now.AddDays(-200) }, Now));

        Assert.Equal("posture-updates-stale", signal.Code);
        Assert.Contains("200 days", signal.Explanation);
    }

    [Fact]
    public void An_unknown_update_date_is_not_treated_as_never_updated()
    {
        Assert.DoesNotContain("posture-updates-stale", Codes(new SecurityPostureFacts()));
    }

    // ---- Overall ----

    /// <summary>
    /// A badly configured machine should be worth reporting, but it is not a malware
    /// finding. Nothing here should on its own read as "your machine is infected".
    /// </summary>
    [Fact]
    public void Even_the_worst_configuration_does_not_read_as_malicious()
    {
        var facts = new SecurityPostureFacts
        {
            FirewallDomain = false,
            FirewallPrivate = false,
            FirewallPublic = false,
            UacEnabled = false,
            SmartScreenEnabled = false,
            SecureBootEnabled = false,
            SystemDriveEncrypted = false,
            LastUpdateInstalled = Now.AddDays(-400),
        };

        var verdict = VerdictEngine.Evaluate(new VerdictInput
        {
            Target = ScanTarget.ForFile("Windows security settings"),
            Signals = SecurityPostureAudit.Evaluate(facts, Now),
            EnginesConsulted = new HashSet<SignalSource> { SignalSource.Persistence },
        }, Now);

        Assert.True(verdict.WarrantsAlert, "a wide-open machine should still be worth telling the user about");
        Assert.True(verdict.Level < ThreatLevel.Malicious,
            $"misconfiguration reached {verdict.Level}, which reads as an infection");
    }
}
