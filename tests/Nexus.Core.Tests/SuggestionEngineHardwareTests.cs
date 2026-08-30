using Nexus.Core.Suggestions;
using Xunit;

namespace Nexus.Core.Tests;

/// <summary>
/// Covers the facts that come from measurement rather than from a registry read.
/// These matter more than the tweak suggestions and are ordered ahead of them, so
/// the tests check the ordering as well as the content.
/// </summary>
public class SuggestionEngineHardwareTests
{
    /// <summary>An already-optimized machine with nothing wrong in hardware or security.</summary>
    private static SystemFacts Healthy => new()
    {
        GameDvrCaptureEnabled = false,
        MouseAccelerationEnabled = false,
        WindowsGameModeEnabled = true,
        StickyKeysShortcutEnabled = false,
        DiagTrackEnabled = false,
        CompatAppraiserTaskEnabled = false,
        ProBalanceEnabled = true,
        GameModeEnabled = true,
        IsHybridCpu = false,
        GameProfileCount = 3,
        NexusPerformancePlanExists = true,
        ThrottledByPowerPlan = false,
        ThrottledByFirmware = false,
        ThrottleCeilingPercent = 100,
        DefenderRealTimeOff = false,
        DefenderHasBroadExclusion = false,
    };

    private static string[] Ids(SystemFacts facts) =>
        SuggestionEngine.Evaluate(facts).Select(s => s.Id).ToArray();

    [Fact]
    public void A_healthy_machine_still_gets_no_suggestions()
    {
        Assert.Empty(SuggestionEngine.Evaluate(Healthy));
    }

    [Fact]
    public void A_power_plan_throttle_is_suggested_and_is_actionable()
    {
        var suggestion = Assert.Single(SuggestionEngine.Evaluate(
            Healthy with { ThrottledByPowerPlan = true, ThrottleCeilingPercent = 50 }));

        Assert.Equal("sug-throttle-power-plan", suggestion.Id);
        Assert.Equal(SuggestionKind.EnableFeature, suggestion.Kind);
        Assert.Contains("50%", suggestion.Reason, StringComparison.Ordinal);
    }

    /// <summary>A firmware limit must be a hint, never something with an Apply button —
    /// offering to "fix" a thermal limit would be a lie.</summary>
    [Fact]
    public void A_firmware_throttle_is_a_hint_with_nothing_to_apply()
    {
        var suggestion = Assert.Single(SuggestionEngine.Evaluate(
            Healthy with { ThrottledByFirmware = true, ThrottleCeilingPercent = 40 }));

        Assert.Equal("sug-throttle-firmware", suggestion.Id);
        Assert.Equal(SuggestionKind.Hint, suggestion.Kind);
        Assert.Equal("", suggestion.TargetId);
        Assert.Contains("Nexus cannot raise it", suggestion.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void Defender_being_off_is_suggested()
    {
        var suggestion = Assert.Single(SuggestionEngine.Evaluate(
            Healthy with { DefenderRealTimeOff = true }));

        Assert.Equal("sug-defender-off", suggestion.Id);
    }

    [Fact]
    public void A_broad_defender_exclusion_is_suggested()
    {
        var suggestion = Assert.Single(SuggestionEngine.Evaluate(
            Healthy with { DefenderHasBroadExclusion = true }));

        Assert.Equal("sug-defender-exclusion", suggestion.Id);
    }

    /// <summary>Hardware and security problems dwarf registry tweaks, so they must not
    /// be buried underneath them in the list the user reads top-down.</summary>
    [Fact]
    public void Hardware_and_security_are_listed_before_tweaks()
    {
        var ids = Ids(Healthy with
        {
            ThrottledByPowerPlan = true,
            DefenderRealTimeOff = true,
            GameDvrCaptureEnabled = true,
            MouseAccelerationEnabled = true,
            DiagTrackEnabled = true,
        });

        int throttle = Array.IndexOf(ids, "sug-throttle-power-plan");
        int defender = Array.IndexOf(ids, "sug-defender-off");
        int firstTweak = Array.IndexOf(ids, "sug-gamedvr");

        Assert.True(throttle >= 0 && defender >= 0 && firstTweak >= 0);
        Assert.True(throttle < firstTweak, "the throttle should be listed before registry tweaks");
        Assert.True(defender < firstTweak, "Defender being off should be listed before registry tweaks");
    }

    [Fact]
    public void A_throttled_machine_still_reports_its_other_problems()
    {
        var ids = Ids(Healthy with { ThrottledByFirmware = true, GameDvrCaptureEnabled = true });

        Assert.Contains("sug-throttle-firmware", ids);
        Assert.Contains("sug-gamedvr", ids);
    }
}
