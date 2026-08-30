using System.Diagnostics;
using System.Runtime.InteropServices;
using Nexus.Core.Logging;
using Nexus.Core.Performance;

namespace Nexus.App.Services.Performance;

/// <summary>What a probe run measured.</summary>
public sealed record ProbeRun
{
    public required string Label { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required LatencySummary Summary { get; init; }
    public required IReadOnlyList<double> Samples { get; init; }

    /// <summary>Timer resolution in effect during the run, for context.</summary>
    public double? TimerResolutionMs { get; init; }
}

/// <summary>
/// Measures how punctually Windows can wake a thread.
///
/// The method is deliberately simple: ask to sleep for a fixed interval, measure how
/// long it actually took with the high-resolution counter, and record the overshoot.
/// Every millisecond of overshoot is the scheduler being late — because a core was
/// parked, because a driver held a DPC too long, because something else with a higher
/// priority was running, or because the timer resolution is coarse.
///
/// This is not a frame-time counter and does not pretend to be one. Nexus refuses to
/// hook a game's present loop (that is what cheats do and it gets accounts banned),
/// so it measures the thing it legitimately can measure: whether this machine can
/// service a thread on time. A machine that cannot do that at idle will not do it
/// under load either, and that is exactly the class of stutter the optimizer half of
/// Nexus is meant to address.
///
/// Two honest caveats, shown in the UI:
/// - It measures the system, not the game. A good score does not promise good frames.
/// - It is affected by whatever else is running, which is the point: run it twice
///   under the same conditions and compare.
/// </summary>
public sealed class LatencyProbeService
{
    /// <summary>Requested sleep per sample. 1 ms is short enough that the scheduler's
    /// punctuality dominates the measurement rather than the sleep itself.</summary>
    private const int SleepMilliseconds = 1;

    /// <summary>Discarded before recording, to let the thread's priority change take
    /// effect and the caches warm up. A cold first sample is not representative.</summary>
    private const int WarmupSamples = 50;

    private readonly ActivityLog _log;

    public LatencyProbeService(ActivityLog log)
    {
        _log = log;
    }

    /// <summary>
    /// Run a measurement. Executes on a dedicated high-priority thread so the probe
    /// measures the system rather than its own scheduling.
    /// </summary>
    public Task<ProbeRun> RunAsync(
        string label, int sampleCount = 2000, CancellationToken cancellationToken = default)
    {
        if (sampleCount < LatencyStatistics.MinimumSamples)
            sampleCount = LatencyStatistics.MinimumSamples;

        var completion = new TaskCompletionSource<ProbeRun>(TaskCreationOptions.RunContinuationsAsynchronously);
        var startedAt = DateTimeOffset.Now;

        var thread = new Thread(() =>
        {
            try
            {
                var samples = Measure(sampleCount, cancellationToken);

                completion.TrySetResult(new ProbeRun
                {
                    Label = label,
                    StartedAt = startedAt,
                    Summary = LatencyStatistics.Summarize(samples),
                    Samples = samples,
                    TimerResolutionMs = QueryTimerResolutionMs(),
                });
            }
            catch (OperationCanceledException)
            {
                completion.TrySetCanceled(cancellationToken);
            }
            catch (Exception ex)
            {
                completion.TrySetException(ex);
            }
        })
        {
            IsBackground = true,
            Name = "Nexus latency probe",
            // Above the UI but deliberately not Highest: a measurement tool that
            // starves the machine it is measuring changes the thing it measures.
            Priority = ThreadPriority.AboveNormal,
        };

        thread.Start();
        return completion.Task;
    }

    private static double[] Measure(int sampleCount, CancellationToken cancellationToken)
    {
        var samples = new double[sampleCount];
        var stopwatch = new Stopwatch();

        double expectedMs = SleepMilliseconds;

        for (int i = 0; i < WarmupSamples; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Thread.Sleep(SleepMilliseconds);
        }

        for (int i = 0; i < sampleCount; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            stopwatch.Restart();
            Thread.Sleep(SleepMilliseconds);
            stopwatch.Stop();

            // Record the overshoot, not the total: the requested sleep is a constant
            // and carrying it would just shift every number by the same amount and
            // make the percentages meaningless.
            double actualMs = stopwatch.Elapsed.TotalMilliseconds;
            samples[i] = Math.Max(0, actualMs - expectedMs);
        }

        return samples;
    }

    /// <summary>Actual system timer resolution, for context alongside a run.</summary>
    public static double? QueryTimerResolutionMs()
    {
        try
        {
            if (NtQueryTimerResolution(out _, out _, out uint current) == 0)
                return current / 10_000.0;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            // Not available; the run is still valid without it.
        }

        return null;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryTimerResolution(out uint minimum, out uint maximum, out uint current);

    /// <summary>
    /// Turn a summary into plain language, with the thresholds stated rather than
    /// hidden behind a colour.
    /// </summary>
    public static string Describe(LatencySummary summary)
    {
        if (summary.SampleCount == 0)
            return "No measurements yet.";

        string body = summary.MedianMs switch
        {
            < 0.3 => "This machine wakes threads on time.",
            < 1.0 => "Thread wake-ups are slightly late, which is normal on a busy desktop.",
            < 3.0 => "Thread wake-ups are consistently late. Something is holding the scheduler up.",
            _ => "Thread wake-ups are very late. Expect stutter in anything timing-sensitive.",
        };

        string tail = summary.JitterMs switch
        {
            < 1.0 => "The worst cases are close to typical, so it is steady.",
            < 5.0 => $"The worst 1% run {summary.JitterMs:0.00} ms behind typical — occasional hitching.",
            _ => $"The worst 1% run {summary.JitterMs:0.00} ms behind typical, which is the pattern " +
                 "behind sudden frame drops.",
        };

        return $"{body} {tail} (median {summary.MedianMs:0.000} ms late, worst {summary.MaxMs:0.000} ms, " +
               $"{summary.SampleCount:N0} samples)";
    }
}
