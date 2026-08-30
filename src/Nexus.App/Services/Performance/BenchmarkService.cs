using Nexus.Core.Logging;
using Nexus.Core.Performance;

namespace Nexus.App.Services.Performance;

/// <summary>
/// The "measure before trusting" harness: capture a baseline, change something,
/// measure again, and get an answer that is allowed to be "nothing happened".
///
/// This is the piece that makes the rest of Nexus falsifiable. Every optimizer
/// claims a win after every change; almost none of them can be checked, and the
/// ones that show a number usually show a single run against a single run, which
/// cannot distinguish a real effect from the machine having a different afternoon.
/// Storing the raw samples and comparing with a bootstrap interval is what lets this
/// one say "no measurable difference" and mean it.
/// </summary>
public sealed class BenchmarkService
{
    /// <summary>The label used by the one-click before/after flow.</summary>
    public const string DefaultLabel = "system latency";

    private readonly LatencyProbeService _probe;
    private readonly BaselineStore _baselines;
    private readonly ThrottleDetectorService _throttle;
    private readonly ActivityLog _log;

    public BenchmarkService(
        LatencyProbeService probe,
        BaselineStore baselines,
        ThrottleDetectorService throttle,
        ActivityLog log)
    {
        _probe = probe;
        _baselines = baselines;
        _throttle = throttle;
        _log = log;
    }

    /// <summary>
    /// Measure and save as the baseline for <paramref name="label"/>.
    /// </summary>
    public async Task<ProbeRun> CaptureBaselineAsync(
        string label = DefaultLabel, int samples = 2000, CancellationToken cancellationToken = default)
    {
        _log.Info("Performance", $"Measuring {label} — hold off on doing anything heavy for a few seconds.");

        var run = await _probe.RunAsync(label, samples, cancellationToken).ConfigureAwait(false);

        _baselines.Save(new StoredBaseline
        {
            Label = label,
            CapturedAt = run.StartedAt,
            Summary = run.Summary,
            Samples = run.Samples,
            Notes = DescribeConditions(run),
        });

        _log.Info("Performance", $"Baseline saved. {LatencyProbeService.Describe(run.Summary)}");
        return run;
    }

    /// <summary>
    /// Measure again and compare against the stored baseline, without overwriting it —
    /// the baseline has to stay put or the next comparison has nothing to compare to.
    /// </summary>
    public async Task<(ProbeRun Run, LatencyComparison? Comparison)> CompareAgainstBaselineAsync(
        string label = DefaultLabel, int samples = 2000, CancellationToken cancellationToken = default)
    {
        var baseline = _baselines.Latest(label);
        var run = await _probe.RunAsync(label, samples, cancellationToken).ConfigureAwait(false);

        if (baseline is null)
        {
            _log.Info("Performance", "No baseline to compare against yet — this run has been saved as one.");

            _baselines.Save(new StoredBaseline
            {
                Label = label,
                CapturedAt = run.StartedAt,
                Summary = run.Summary,
                Samples = run.Samples,
                Notes = DescribeConditions(run),
            });

            return (run, null);
        }

        var comparison = LatencyStatistics.Compare(baseline.Samples, run.Samples);

        _log.Info("Performance", $"Compared against the baseline from {baseline.CapturedAt:g}: {comparison.Explanation}");

        return (run, comparison);
    }

    /// <summary>
    /// A one-line health read for the dashboard: is anything holding this machine
    /// back that Nexus cannot fix with a tweak?
    /// </summary>
    public string DescribeMachineState()
    {
        var throttle = _throttle.Detect();
        if (throttle is null)
            return "The processor is running at its rated speed.";

        return throttle.Summary;
    }

    private string DescribeConditions(ProbeRun run)
    {
        var parts = new List<string>();

        if (run.TimerResolutionMs is { } resolution)
            parts.Add($"timer resolution {resolution:0.000} ms");

        if (_throttle.Detect() is { } throttle)
            parts.Add($"CPU capped at {throttle.CeilingPercent}%");

        return parts.Count > 0 ? string.Join(", ", parts) : "no special conditions recorded";
    }
}
