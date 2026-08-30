namespace Nexus.Core.Performance;

/// <summary>
/// Summary of one measurement run.
///
/// Latency distributions are heavy-tailed: the mean is close to meaningless and the
/// interesting part lives in the last percentile. A frame that takes 40 ms once a
/// second is what a player feels, and it barely moves an average. So every figure
/// here is an order statistic, and the mean is carried only because people expect
/// to see one.
/// </summary>
public sealed record LatencySummary
{
    public required int SampleCount { get; init; }
    public required double MinMs { get; init; }
    public required double MedianMs { get; init; }
    public required double P95Ms { get; init; }
    public required double P99Ms { get; init; }
    public required double MaxMs { get; init; }
    public required double MeanMs { get; init; }

    /// <summary>Spread between the median and the 99th percentile — the number that
    /// corresponds to "it mostly runs fine but hitches".</summary>
    public double JitterMs => P99Ms - MedianMs;

    public static LatencySummary Empty => new()
    {
        SampleCount = 0,
        MinMs = 0,
        MedianMs = 0,
        P95Ms = 0,
        P99Ms = 0,
        MaxMs = 0,
        MeanMs = 0,
    };
}

/// <summary>Which way a comparison went.</summary>
public enum ComparisonVerdict
{
    /// <summary>The difference could not be told apart from measurement noise.
    /// This is the honest answer for most tweaks, and it is not a failure.</summary>
    NoMeasurableDifference,

    Better,
    Worse,

    /// <summary>Not enough samples on one side to say anything at all.</summary>
    NotEnoughData,
}

/// <summary>The result of an A/B comparison, in terms a person can act on.</summary>
public sealed record LatencyComparison
{
    public required ComparisonVerdict Verdict { get; init; }
    public required LatencySummary Before { get; init; }
    public required LatencySummary After { get; init; }

    /// <summary>Median shift in milliseconds; negative means faster.</summary>
    public required double MedianDeltaMs { get; init; }

    /// <summary>Bootstrap 95% confidence interval for that shift.</summary>
    public required double LowerBoundMs { get; init; }
    public required double UpperBoundMs { get; init; }

    /// <summary>Plain-language conclusion, written to be quotable in the UI.</summary>
    public required string Explanation { get; init; }

    /// <summary>Change in the median as a percentage; negative means faster.</summary>
    public double PercentChange => Before.MedianMs > 0
        ? MedianDeltaMs / Before.MedianMs * 100
        : 0;
}

/// <summary>
/// Order statistics and A/B comparison for latency measurements.
///
/// The comparison deliberately refuses to claim an improvement it cannot defend.
/// It uses a bootstrap confidence interval on the median shift, and if that interval
/// contains zero it reports "no measurable difference" — even when the medians
/// differ, which they always will. Every optimizer on the internet reports a win
/// after every change; the only way to be worth trusting is to be willing to say
/// nothing happened.
/// </summary>
public static class LatencyStatistics
{
    /// <summary>Below this, ordering statistics is meaningless.</summary>
    public const int MinimumSamples = 30;

    /// <summary>Resamples used for the bootstrap interval. 2000 is enough for a
    /// stable 95% interval and still runs in milliseconds.</summary>
    public const int BootstrapResamples = 2000;

    /// <summary>
    /// A shift smaller than this is not reported as a win even when it is
    /// statistically detectable, because nobody can feel it and claiming it would
    /// be the same dishonesty in a more sophisticated form.
    /// </summary>
    public const double MeaningfulShiftMs = 0.05;

    public static LatencySummary Summarize(IReadOnlyList<double> samplesMs)
    {
        if (samplesMs.Count == 0)
            return LatencySummary.Empty;

        var sorted = samplesMs.ToArray();
        Array.Sort(sorted);

        return new LatencySummary
        {
            SampleCount = sorted.Length,
            MinMs = sorted[0],
            MedianMs = Percentile(sorted, 0.50),
            P95Ms = Percentile(sorted, 0.95),
            P99Ms = Percentile(sorted, 0.99),
            MaxMs = sorted[^1],
            MeanMs = sorted.Average(),
        };
    }

    /// <summary>Linear-interpolated percentile over an already-sorted array.</summary>
    public static double Percentile(double[] sorted, double quantile)
    {
        if (sorted.Length == 0)
            return 0;
        if (sorted.Length == 1)
            return sorted[0];

        double position = quantile * (sorted.Length - 1);
        int lower = (int)Math.Floor(position);
        int upper = (int)Math.Ceiling(position);

        if (lower == upper)
            return sorted[lower];

        double weight = position - lower;
        return sorted[lower] * (1 - weight) + sorted[upper] * weight;
    }

    /// <summary>
    /// Compare two runs. <paramref name="seed"/> makes the bootstrap deterministic,
    /// so the same two data sets always produce the same verdict — a comparison that
    /// flickers between "better" and "no difference" on re-runs is worthless.
    /// </summary>
    public static LatencyComparison Compare(
        IReadOnlyList<double> beforeMs, IReadOnlyList<double> afterMs, int seed = 12345)
    {
        var before = Summarize(beforeMs);
        var after = Summarize(afterMs);

        if (beforeMs.Count < MinimumSamples || afterMs.Count < MinimumSamples)
        {
            return new LatencyComparison
            {
                Verdict = ComparisonVerdict.NotEnoughData,
                Before = before,
                After = after,
                MedianDeltaMs = 0,
                LowerBoundMs = 0,
                UpperBoundMs = 0,
                Explanation =
                    $"Not enough measurements to compare — {MinimumSamples} are needed on each side " +
                    $"and there are {beforeMs.Count} before and {afterMs.Count} after.",
            };
        }

        double delta = after.MedianMs - before.MedianMs;
        var (lower, upper) = BootstrapMedianDifference(beforeMs, afterMs, seed);

        // The interval straddling zero means the data cannot distinguish the two runs.
        bool indistinguishable = lower <= 0 && upper >= 0;
        bool tooSmallToFeel = Math.Abs(delta) < MeaningfulShiftMs;

        if (indistinguishable || tooSmallToFeel)
        {
            return new LatencyComparison
            {
                Verdict = ComparisonVerdict.NoMeasurableDifference,
                Before = before,
                After = after,
                MedianDeltaMs = delta,
                LowerBoundMs = lower,
                UpperBoundMs = upper,
                Explanation = tooSmallToFeel && !indistinguishable
                    ? $"The change is real but tiny ({delta:+0.000;-0.000} ms). It is far below what " +
                      "anyone can perceive, so treat it as no difference."
                    : "No measurable difference. The two runs overlap within measurement noise, so " +
                      "any change here is not something this test can detect.",
            };
        }

        bool better = delta < 0;

        return new LatencyComparison
        {
            Verdict = better ? ComparisonVerdict.Better : ComparisonVerdict.Worse,
            Before = before,
            After = after,
            MedianDeltaMs = delta,
            LowerBoundMs = lower,
            UpperBoundMs = upper,
            Explanation =
                $"Typical latency went {(better ? "down" : "up")} by {Math.Abs(delta):0.000} ms " +
                $"({Math.Abs(before.MedianMs > 0 ? delta / before.MedianMs * 100 : 0):0.0}%), " +
                $"and the worst 1% went from {before.P99Ms:0.000} ms to {after.P99Ms:0.000} ms.",
        };
    }

    /// <summary>
    /// Bootstrap 95% confidence interval for the difference in medians.
    ///
    /// Non-parametric on purpose: latency is not normally distributed, so a t-test on
    /// the means would answer a question nobody asked and answer it wrongly.
    /// </summary>
    private static (double Lower, double Upper) BootstrapMedianDifference(
        IReadOnlyList<double> before, IReadOnlyList<double> after, int seed)
    {
        var random = new Random(seed);
        var differences = new double[BootstrapResamples];

        var beforeBuffer = new double[before.Count];
        var afterBuffer = new double[after.Count];

        for (int i = 0; i < BootstrapResamples; i++)
        {
            for (int j = 0; j < beforeBuffer.Length; j++)
                beforeBuffer[j] = before[random.Next(before.Count)];

            for (int j = 0; j < afterBuffer.Length; j++)
                afterBuffer[j] = after[random.Next(after.Count)];

            Array.Sort(beforeBuffer);
            Array.Sort(afterBuffer);

            differences[i] = Percentile(afterBuffer, 0.50) - Percentile(beforeBuffer, 0.50);
        }

        Array.Sort(differences);
        return (Percentile(differences, 0.025), Percentile(differences, 0.975));
    }
}
