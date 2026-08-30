using Nexus.Core.Persistence;
using Nexus.Core.Security;
using Xunit;

namespace Nexus.Core.Tests;

public class ScanHistoryTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "nexus-history-" + Guid.NewGuid().ToString("N"));

    private ScanHistory NewHistory() => new(new JsonStore<ScanHistoryState>(
        Path.Combine(_directory, "scan-history.json"),
        NexusJsonContext.Default.ScanHistoryState,
        static () => new ScanHistoryState()));

    private static ScanRun Run(DateTimeOffset at, ScanKind kind = ScanKind.Folder,
        int files = 10, int findings = 0, bool completed = true) =>
        new()
        {
            StartedAt = at,
            Kind = kind,
            Target = @"C:\somewhere",
            FilesScanned = files,
            Findings = findings,
            DurationSeconds = 12,
            Completed = completed,
        };

    private static DateTimeOffset At(int day) => new(2026, 8, day, 12, 0, 0, TimeSpan.Zero);

    public void Dispose()
    {
        try { Directory.Delete(_directory, recursive: true); } catch (IOException) { }
    }

    [Fact]
    public void A_new_history_is_empty()
    {
        var history = NewHistory();

        Assert.Empty(history.All);
        Assert.Null(history.Latest);
    }

    [Fact]
    public void Runs_come_back_newest_first()
    {
        var history = NewHistory();

        history.Record(Run(At(1)));
        history.Record(Run(At(3)));
        history.Record(Run(At(2)));

        Assert.Equal([At(3), At(2), At(1)], history.All.Select(r => r.StartedAt));
        Assert.Equal(At(3), history.Latest?.StartedAt);
    }

    [Fact]
    public void History_survives_a_restart()
    {
        NewHistory().Record(Run(At(1), ScanKind.FullDisk, files: 4321, findings: 2));

        var reloaded = NewHistory().All;

        var run = Assert.Single(reloaded);
        Assert.Equal(ScanKind.FullDisk, run.Kind);
        Assert.Equal(4321, run.FilesScanned);
        Assert.Equal(2, run.Findings);
    }

    /// <summary>
    /// The oldest entry must go, not the last one added. A long full scan can finish
    /// after a quick check that started later, so entries do arrive out of order.
    /// </summary>
    [Fact]
    public void Trimming_drops_the_oldest_run_not_the_newest_arrival()
    {
        var history = NewHistory();

        for (int i = 0; i < ScanHistory.MaxRuns; i++)
            history.Record(Run(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero).AddHours(i + 1)));

        // Arrives last, but is older than everything already stored.
        var ancient = new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero);
        history.Record(Run(ancient));

        Assert.Equal(ScanHistory.MaxRuns, history.Count);
        Assert.DoesNotContain(history.All, r => r.StartedAt == ancient);

        // And a genuinely new one still displaces the oldest survivor.
        var newest = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
        history.Record(Run(newest));

        Assert.Equal(ScanHistory.MaxRuns, history.Count);
        Assert.Equal(newest, history.Latest?.StartedAt);
    }

    [Fact]
    public void Clearing_empties_the_history_on_disk_too()
    {
        var history = NewHistory();
        history.Record(Run(At(1)));
        history.Clear();

        Assert.Empty(NewHistory().All);
    }

    // ---- How a run reads ----

    [Fact]
    public void A_cancelled_run_says_so()
    {
        var run = Run(At(1), completed: false);

        Assert.Contains("stopped early", run.Outcome);
    }

    [Fact]
    public void A_clean_run_does_not_imply_it_was_interrupted()
    {
        Assert.DoesNotContain("stopped early", Run(At(1)).Outcome);
        Assert.Contains("nothing flagged", Run(At(1)).Outcome);
    }

    [Fact]
    public void One_file_is_not_described_as_one_files()
    {
        Assert.Contains("1 file,", Run(At(1), ScanKind.SingleFile, files: 1).Outcome);
    }

    // ---- Report ----

    [Fact]
    public void An_empty_report_says_nothing_has_run_rather_than_showing_a_blank()
    {
        Assert.Contains("No scans have been run yet", NewHistory().BuildReport(At(5)));
    }

    [Fact]
    public void The_report_totals_every_run()
    {
        var history = NewHistory();
        history.Record(Run(At(1), files: 100, findings: 1));
        history.Record(Run(At(2), files: 250, findings: 2));

        var report = history.BuildReport(At(5));

        Assert.Contains("2 scan(s)", report);
        Assert.Contains("350", report);
        Assert.Contains("3 finding(s)", report);

        // The whole product's promise, restated wherever the user might paste it.
        Assert.Contains("never acts on its own", report);
    }
}
