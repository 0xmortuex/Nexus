using Nexus.Core.Performance;
using Nexus.Core.Persistence;
using Xunit;

namespace Nexus.Core.Tests;

public class BaselineStoreTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nexus-baseline-tests-").FullName;
    private static readonly DateTimeOffset Now = new(2026, 8, 30, 12, 0, 0, TimeSpan.Zero);

    private BaselineStore NewStore(string name = "baselines.json") => new(
        new JsonStore<BaselineState>(
            Path.Combine(_dir, name), NexusJsonContext.Default.BaselineState,
            static () => new BaselineState()));

    private static StoredBaseline Baseline(string label, DateTimeOffset at, int sampleCount = 100)
    {
        var samples = Enumerable.Range(0, sampleCount).Select(i => i * 0.01).ToArray();

        return new StoredBaseline
        {
            Label = label,
            CapturedAt = at,
            Summary = LatencyStatistics.Summarize(samples),
            Samples = samples,
        };
    }

    [Fact]
    public void A_saved_baseline_survives_a_reload()
    {
        NewStore().Save(Baseline("system latency", Now));

        var reloaded = NewStore().Latest("system latency");

        Assert.NotNull(reloaded);
        Assert.Equal(100, reloaded.Samples.Count);
        Assert.Equal(Now, reloaded.CapturedAt);
    }

    [Fact]
    public void Latest_returns_the_most_recent_run_for_a_label()
    {
        var store = NewStore();
        store.Save(Baseline("a", Now.AddHours(-2)));
        store.Save(Baseline("a", Now));
        store.Save(Baseline("a", Now.AddHours(-1)));

        Assert.Equal(Now, store.Latest("a")!.CapturedAt);
    }

    [Fact]
    public void Labels_are_matched_case_insensitively()
    {
        var store = NewStore();
        store.Save(Baseline("System Latency", Now));

        Assert.NotNull(store.Latest("system latency"));
    }

    [Fact]
    public void An_unknown_label_returns_null_rather_than_a_wrong_baseline()
    {
        var store = NewStore();
        store.Save(Baseline("a", Now));

        Assert.Null(store.Latest("b"));
    }

    [Fact]
    public void Only_the_most_recent_runs_per_label_are_kept()
    {
        var store = NewStore();
        for (int i = 0; i < BaselineStore.MaxRunsPerLabel + 4; i++)
            store.Save(Baseline("a", Now.AddMinutes(i)));

        Assert.Equal(BaselineStore.MaxRunsPerLabel, store.All().Count);
        Assert.Equal(Now.AddMinutes(BaselineStore.MaxRunsPerLabel + 3), store.Latest("a")!.CapturedAt);
    }

    [Fact]
    public void Trimming_one_label_does_not_evict_another()
    {
        var store = NewStore();
        store.Save(Baseline("keep-me", Now));

        for (int i = 0; i < BaselineStore.MaxRunsPerLabel + 4; i++)
            store.Save(Baseline("noisy", Now.AddMinutes(i)));

        Assert.NotNull(store.Latest("keep-me"));
    }

    [Fact]
    public void Oversized_runs_are_trimmed_so_the_file_stays_bounded()
    {
        var store = NewStore();
        store.Save(Baseline("a", Now, sampleCount: BaselineStore.MaxSamplesPerRun + 500));

        Assert.Equal(BaselineStore.MaxSamplesPerRun, store.Latest("a")!.Samples.Count);
    }

    /// <summary>The stored samples must remain usable for a real comparison — that is
    /// the only reason they are persisted at all.</summary>
    [Fact]
    public void Stored_samples_can_still_drive_a_comparison_after_a_reload()
    {
        var before = Enumerable.Range(0, 300).Select(i => 4.0 + i % 3 * 0.01).ToArray();
        var after = Enumerable.Range(0, 300).Select(i => 1.0 + i % 3 * 0.01).ToArray();

        NewStore().Save(new StoredBaseline
        {
            Label = "a",
            CapturedAt = Now,
            Summary = LatencyStatistics.Summarize(before),
            Samples = before,
        });

        var reloaded = NewStore().Latest("a")!;
        var comparison = LatencyStatistics.Compare(reloaded.Samples, after);

        Assert.Equal(ComparisonVerdict.Better, comparison.Verdict);
    }

    [Fact]
    public void Clearing_removes_everything()
    {
        var store = NewStore();
        store.Save(Baseline("a", Now));
        store.Clear();

        Assert.Empty(store.All());
        Assert.Empty(NewStore().All());
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup.
        }
    }
}
