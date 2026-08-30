using Nexus.Core.Performance;
using Xunit;

namespace Nexus.Core.Tests;

public class ThrottleAnalysisTests
{
    private static CoreFrequency[] Cores(int count, int maxMhz, int currentMhz, int limitMhz) =>
        Enumerable.Range(0, count)
            .Select(i => new CoreFrequency(i, maxMhz, currentMhz, limitMhz))
            .ToArray();

    [Fact]
    public void No_readings_produces_no_finding()
    {
        Assert.Null(ThrottleAnalysis.Analyse([]));
    }

    [Fact]
    public void A_processor_at_its_rated_ceiling_is_not_flagged()
    {
        Assert.Null(ThrottleAnalysis.Analyse(Cores(8, maxMhz: 4900, currentMhz: 4700, limitMhz: 4900)));
    }

    [Fact]
    public void Boost_behaviour_within_tolerance_is_not_flagged()
    {
        // A ceiling a few percent under the rated maximum is normal.
        Assert.Null(ThrottleAnalysis.Analyse(Cores(8, maxMhz: 4900, currentMhz: 4600, limitMhz: 4750)));
    }

    [Fact]
    public void Running_slowly_while_idle_is_not_a_throttle()
    {
        // Low current speed with a full ceiling is just power saving doing its job.
        Assert.Null(ThrottleAnalysis.Analyse(Cores(8, maxMhz: 4900, currentMhz: 800, limitMhz: 4900)));
    }

    [Fact]
    public void A_ceiling_matching_the_power_plan_is_blamed_on_the_power_plan()
    {
        var finding = ThrottleAnalysis.Analyse(
            Cores(8, maxMhz: 4000, currentMhz: 2000, limitMhz: 2000),
            powerPlanMaxPercent: 50);

        Assert.NotNull(finding);
        Assert.Equal(ThrottleCause.PowerPlan, finding.Cause);
        Assert.True(finding.ActionableInSoftware);
        Assert.Equal(50, finding.CeilingPercent);
        Assert.Contains("power plan", finding.Summary, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The honest case: Nexus must not imply it can fix a hardware limit.</summary>
    [Fact]
    public void A_ceiling_the_power_plan_does_not_explain_is_reported_as_not_fixable()
    {
        var finding = ThrottleAnalysis.Analyse(
            Cores(8, maxMhz: 4900, currentMhz: 1900, limitMhz: 2000),
            powerPlanMaxPercent: 100);

        Assert.NotNull(finding);
        Assert.Equal(ThrottleCause.FirmwareOrThermal, finding.Cause);
        Assert.False(finding.ActionableInSoftware);
        Assert.Contains("No software tweak will raise it", finding.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unknown_power_plan_state_does_not_produce_a_false_accusation()
    {
        var finding = ThrottleAnalysis.Analyse(
            Cores(8, maxMhz: 4900, currentMhz: 2000, limitMhz: 2400),
            powerPlanMaxPercent: null);

        Assert.NotNull(finding);
        Assert.Equal(ThrottleCause.FirmwareOrThermal, finding.Cause);
    }

    /// <summary>On a hybrid CPU the P-cores set the rated maximum, and the lowest
    /// enforced ceiling is what actually holds a pinned thread back.</summary>
    [Fact]
    public void Hybrid_cpus_use_the_highest_rating_and_the_lowest_ceiling()
    {
        CoreFrequency[] hybrid =
        [
            new(0, MaxMhz: 5000, CurrentMhz: 3000, MhzLimit: 5000),
            new(1, MaxMhz: 5000, CurrentMhz: 3000, MhzLimit: 5000),
            new(2, MaxMhz: 3800, CurrentMhz: 2000, MhzLimit: 2500),
        ];

        var finding = ThrottleAnalysis.Analyse(hybrid);

        Assert.NotNull(finding);
        Assert.Equal(5000, finding.MaxMhz);
        Assert.Equal(2500, finding.CeilingMhz);
    }

    [Fact]
    public void Cores_reporting_no_limit_do_not_drag_the_ceiling_to_zero()
    {
        CoreFrequency[] cores =
        [
            new(0, MaxMhz: 4000, CurrentMhz: 3000, MhzLimit: 0),
            new(1, MaxMhz: 4000, CurrentMhz: 3000, MhzLimit: 0),
        ];

        // Every core reports "no limit", so there is nothing to flag.
        Assert.Null(ThrottleAnalysis.Analyse(cores));
    }

    [Fact]
    public void A_zero_rated_maximum_is_ignored_rather_than_dividing_by_zero()
    {
        Assert.Null(ThrottleAnalysis.Analyse(Cores(4, maxMhz: 0, currentMhz: 0, limitMhz: 0)));
    }
}
