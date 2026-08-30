using Nexus.Core.Performance;
using Xunit;

namespace Nexus.Core.Tests;

public class LatencyStatisticsTests
{
    /// <summary>
    /// A realistic latency distribution: a tight body with a heavy tail, which is
    /// what scheduling jitter actually looks like. Deterministic so the tests do not
    /// flake.
    /// </summary>
    private static double[] Distribution(int count, double baseMs, double spikeMs, int seed, double spikeRate = 0.02)
    {
        var random = new Random(seed);
        var samples = new double[count];

        for (int i = 0; i < count; i++)
        {
            samples[i] = random.NextDouble() < spikeRate
                ? spikeMs + random.NextDouble() * spikeMs
                : baseMs + random.NextDouble() * baseMs * 0.1;
        }

        return samples;
    }

    // ---- Order statistics ----

    [Fact]
    public void An_empty_run_summarizes_to_zero_rather_than_throwing()
    {
        var summary = LatencyStatistics.Summarize([]);
        Assert.Equal(0, summary.SampleCount);
        Assert.Equal(0, summary.MedianMs);
    }

    [Fact]
    public void Percentiles_are_ordered_and_bracketed_by_min_and_max()
    {
        var summary = LatencyStatistics.Summarize(Distribution(1000, 1.0, 20.0, seed: 1));

        Assert.True(summary.MinMs <= summary.MedianMs);
        Assert.True(summary.MedianMs <= summary.P95Ms);
        Assert.True(summary.P95Ms <= summary.P99Ms);
        Assert.True(summary.P99Ms <= summary.MaxMs);
    }

    [Fact]
    public void Percentile_interpolates_between_samples()
    {
        double[] sorted = [0, 10];
        Assert.Equal(5, LatencyStatistics.Percentile(sorted, 0.50), precision: 6);
        Assert.Equal(0, LatencyStatistics.Percentile(sorted, 0.00), precision: 6);
        Assert.Equal(10, LatencyStatistics.Percentile(sorted, 1.00), precision: 6);
    }

    /// <summary>The reason this module uses order statistics: a rare huge spike moves
    /// the mean and barely touches the median, and the spike is what a player feels.</summary>
    [Fact]
    public void The_median_resists_spikes_that_drag_the_mean()
    {
        var withSpikes = Distribution(1000, 1.0, 100.0, seed: 2, spikeRate: 0.03);
        var summary = LatencyStatistics.Summarize(withSpikes);

        Assert.True(summary.MedianMs < 1.5, $"median was dragged to {summary.MedianMs}");
        Assert.True(summary.MeanMs > summary.MedianMs, "the mean should be pulled up by the tail");
        Assert.True(summary.JitterMs > 1.0, "p99 minus median should expose the hitching");
    }

    // ---- Comparison ----

    [Fact]
    public void Too_few_samples_reports_not_enough_data_rather_than_guessing()
    {
        var comparison = LatencyStatistics.Compare([1, 2, 3], [1, 2, 3]);

        Assert.Equal(ComparisonVerdict.NotEnoughData, comparison.Verdict);
        Assert.Contains("Not enough measurements", comparison.Explanation, StringComparison.Ordinal);
    }

    /// <summary>The headline behaviour: two samples of the same system must not be
    /// reported as an improvement just because their medians differ slightly.</summary>
    [Fact]
    public void Two_runs_of_an_unchanged_system_report_no_measurable_difference()
    {
        var before = Distribution(500, 1.0, 20.0, seed: 10);
        var after = Distribution(500, 1.0, 20.0, seed: 11);

        var comparison = LatencyStatistics.Compare(before, after);

        Assert.Equal(ComparisonVerdict.NoMeasurableDifference, comparison.Verdict);
    }

    [Fact]
    public void A_large_genuine_improvement_is_detected()
    {
        var before = Distribution(500, 4.0, 40.0, seed: 20);
        var after = Distribution(500, 1.0, 10.0, seed: 21);

        var comparison = LatencyStatistics.Compare(before, after);

        Assert.Equal(ComparisonVerdict.Better, comparison.Verdict);
        Assert.True(comparison.MedianDeltaMs < 0);
        Assert.True(comparison.PercentChange < 0);
    }

    [Fact]
    public void A_large_genuine_regression_is_detected()
    {
        var before = Distribution(500, 1.0, 10.0, seed: 30);
        var after = Distribution(500, 4.0, 40.0, seed: 31);

        var comparison = LatencyStatistics.Compare(before, after);

        Assert.Equal(ComparisonVerdict.Worse, comparison.Verdict);
        Assert.True(comparison.MedianDeltaMs > 0);
    }

    /// <summary>A shift too small to perceive is reported as no difference even when
    /// the statistics can resolve it.</summary>
    [Fact]
    public void A_statistically_real_but_imperceptible_shift_is_not_sold_as_a_win()
    {
        var before = Enumerable.Repeat(1.000, 500).ToArray();
        var after = Enumerable.Repeat(1.000 - LatencyStatistics.MeaningfulShiftMs / 2, 500).ToArray();

        var comparison = LatencyStatistics.Compare(before, after);

        Assert.Equal(ComparisonVerdict.NoMeasurableDifference, comparison.Verdict);
    }

    [Fact]
    public void The_same_data_always_produces_the_same_verdict()
    {
        var before = Distribution(300, 2.0, 20.0, seed: 40);
        var after = Distribution(300, 2.0, 20.0, seed: 41);

        var first = LatencyStatistics.Compare(before, after);
        var second = LatencyStatistics.Compare(before, after);

        Assert.Equal(first.Verdict, second.Verdict);
        Assert.Equal(first.LowerBoundMs, second.LowerBoundMs, precision: 10);
        Assert.Equal(first.UpperBoundMs, second.UpperBoundMs, precision: 10);
    }

    [Fact]
    public void The_confidence_interval_brackets_the_observed_shift_when_a_difference_is_claimed()
    {
        var before = Distribution(500, 4.0, 40.0, seed: 50);
        var after = Distribution(500, 1.0, 10.0, seed: 51);

        var comparison = LatencyStatistics.Compare(before, after);

        Assert.NotEqual(ComparisonVerdict.NoMeasurableDifference, comparison.Verdict);
        Assert.True(comparison.LowerBoundMs <= comparison.MedianDeltaMs);
        Assert.True(comparison.MedianDeltaMs <= comparison.UpperBoundMs);
        Assert.True(comparison.UpperBoundMs < 0, "a confident improvement should have an interval entirely below zero");
    }

    /// <summary>Noisy data must widen the interval enough to withdraw the claim,
    /// even when the medians happen to differ.</summary>
    [Fact]
    public void Very_noisy_runs_do_not_produce_a_confident_verdict()
    {
        var random = new Random(60);
        var before = Enumerable.Range(0, 300).Select(_ => random.NextDouble() * 50).ToArray();
        var after = Enumerable.Range(0, 300).Select(_ => random.NextDouble() * 50).ToArray();

        var comparison = LatencyStatistics.Compare(before, after);

        Assert.Equal(ComparisonVerdict.NoMeasurableDifference, comparison.Verdict);
    }
}
