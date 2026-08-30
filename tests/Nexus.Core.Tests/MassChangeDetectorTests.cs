using Nexus.Core.Security.Ransomware;
using Xunit;

namespace Nexus.Core.Tests;

public class MassChangeDetectorTests
{
    private static readonly DateTimeOffset Start = new(2026, 8, 30, 12, 0, 0, TimeSpan.Zero);

    private static FileChangeEvent Change(
        string path,
        FileChangeKind kind = FileChangeKind.Modified,
        double secondsIn = 0,
        bool canary = false,
        string? oldPath = null) =>
        new()
        {
            Path = path,
            Kind = kind,
            At = Start.AddSeconds(secondsIn),
            IsCanary = canary,
            OldPath = oldPath,
        };

    /// <summary>Feed a run of events and return the first finding, if any.</summary>
    private static RansomwareFinding? FeedUntilFinding(
        MassChangeDetector detector, IEnumerable<FileChangeEvent> events)
    {
        RansomwareFinding? finding = null;
        foreach (var change in events)
            finding ??= detector.Observe(change);
        return finding;
    }

    // ---- Quiet on ordinary activity ----

    [Fact]
    public void Editing_a_document_reports_nothing()
    {
        var detector = new MassChangeDetector();
        Assert.Null(detector.Observe(Change(@"C:\Users\fadi\Documents\notes.docx")));
    }

    [Fact]
    public void Build_output_churn_is_ignored()
    {
        var detector = new MassChangeDetector();

        var events = Enumerable.Range(0, 500)
            .Select(i => Change($@"C:\repo\bin\Debug\file{i}.obj", secondsIn: i * 0.01));

        Assert.Null(FeedUntilFinding(detector, events));
    }

    /// <summary>A backup or sync tool rewriting documents must not, on the burst rule
    /// alone, be reported as ransomware.</summary>
    [Fact]
    public void A_large_burst_of_document_changes_alone_does_not_alert()
    {
        var detector = new MassChangeDetector();

        var events = Enumerable.Range(0, MassChangeDetector.BurstThreshold * 3)
            .Select(i => Change($@"C:\Users\fadi\Documents\report{i}.docx", secondsIn: i * 0.01));

        Assert.Null(FeedUntilFinding(detector, events));
    }

    [Fact]
    public void Creating_files_without_renaming_is_not_counted()
    {
        var detector = new MassChangeDetector();

        var events = Enumerable.Range(0, 200)
            .Select(i => Change($@"C:\Users\fadi\Pictures\img{i}.jpg", FileChangeKind.Created, i * 0.01));

        FeedUntilFinding(detector, events);
        Assert.Equal(0, detector.TrackedFileCount);
    }

    // ---- Canary ----

    [Fact]
    public void Touching_a_canary_file_alerts_immediately()
    {
        var detector = new MassChangeDetector();

        var finding = detector.Observe(Change(
            @"C:\Users\fadi\Documents\___nexus_canary.docx", FileChangeKind.Modified, canary: true));

        Assert.NotNull(finding);
        Assert.Contains(finding.Signals, s => s.Code == "ransom-canary-touched");
    }

    [Fact]
    public void Creating_the_canary_does_not_alert_on_its_own_placement()
    {
        var detector = new MassChangeDetector();

        Assert.Null(detector.Observe(Change(
            @"C:\Users\fadi\Documents\___nexus_canary.docx", FileChangeKind.Created, canary: true)));
    }

    // ---- Uniform extension ----

    [Fact]
    public void Many_files_renamed_to_one_new_extension_alerts()
    {
        var detector = new MassChangeDetector();

        var events = Enumerable.Range(0, MassChangeDetector.UniformExtensionThreshold + 2)
            .Select(i => Change(
                $@"C:\Users\fadi\Documents\report{i}.docx.locked",
                FileChangeKind.Renamed,
                secondsIn: i * 0.1,
                oldPath: $@"C:\Users\fadi\Documents\report{i}.docx"));

        var finding = FeedUntilFinding(detector, events);

        Assert.NotNull(finding);
        Assert.Contains(finding.Signals, s => s.Code == "ransom-uniform-extension");
        Assert.Equal(".locked", finding.SuspiciousExtension);
    }

    [Fact]
    public void Renaming_many_files_to_ordinary_extensions_does_not_alert()
    {
        var detector = new MassChangeDetector();

        // A bulk photo export: lots of renames, all to a normal extension.
        var events = Enumerable.Range(0, 50)
            .Select(i => Change(
                $@"C:\Users\fadi\Pictures\export{i}.jpg",
                FileChangeKind.Renamed,
                secondsIn: i * 0.1,
                oldPath: $@"C:\Users\fadi\Pictures\DSC{i}.jpg"));

        Assert.Null(FeedUntilFinding(detector, events));
    }

    // ---- Ransom notes ----

    [Theory]
    [InlineData("HOW_TO_DECRYPT.txt")]
    [InlineData("recover_files.html")]
    [InlineData("!!!README!!!.txt")]
    public void Ransom_note_filenames_alert(string name)
    {
        var detector = new MassChangeDetector();

        var finding = detector.Observe(Change(
            $@"C:\Users\fadi\Documents\{name}", FileChangeKind.Created));

        Assert.NotNull(finding);
        Assert.Contains(finding.Signals, s => s.Code == "ransom-note-created");
    }

    [Fact]
    public void An_ordinary_readme_does_not_alert()
    {
        var detector = new MassChangeDetector();
        Assert.Null(detector.Observe(Change(@"C:\repo\README.md", FileChangeKind.Created)));
    }

    // ---- Rate limiting and bookkeeping ----

    [Fact]
    public void Repeated_alarms_are_suppressed_by_the_cooldown()
    {
        var detector = new MassChangeDetector();
        var canary = @"C:\Users\fadi\Documents\___nexus_canary.docx";

        Assert.NotNull(detector.Observe(Change(canary, FileChangeKind.Modified, 0, canary: true)));
        Assert.Null(detector.Observe(Change(canary, FileChangeKind.Modified, 10, canary: true)));
        Assert.Null(detector.Observe(Change(canary, FileChangeKind.Modified, 60, canary: true)));
    }

    [Fact]
    public void The_cooldown_expires()
    {
        var detector = new MassChangeDetector();
        var canary = @"C:\Users\fadi\Documents\___nexus_canary.docx";

        detector.Observe(Change(canary, FileChangeKind.Modified, 0, canary: true));

        double afterCooldown = MassChangeDetector.Cooldown.TotalSeconds + 1;
        Assert.NotNull(detector.Observe(Change(canary, FileChangeKind.Modified, afterCooldown, canary: true)));
    }

    [Fact]
    public void Events_outside_the_window_stop_being_counted()
    {
        var detector = new MassChangeDetector();

        foreach (var i in Enumerable.Range(0, 20))
            detector.Observe(Change($@"C:\Users\fadi\Documents\a{i}.docx", secondsIn: i * 0.1));

        Assert.True(detector.TrackedFileCount > 0);

        // One event well past the window prunes everything before it.
        detector.Observe(Change(@"C:\Users\fadi\Documents\later.docx",
            secondsIn: MassChangeDetector.Window.TotalSeconds * 2));

        Assert.Equal(1, detector.TrackedFileCount);
    }

    [Fact]
    public void Tracking_is_bounded_under_a_flood()
    {
        var detector = new MassChangeDetector();

        for (int i = 0; i < MassChangeDetector.MaxTrackedEvents + 5000; i++)
            detector.Observe(Change($@"C:\Users\fadi\Documents\f{i}.docx", secondsIn: i * 0.0001));

        Assert.True(detector.TrackedFileCount <= MassChangeDetector.MaxTrackedEvents);
    }

    [Fact]
    public void Reset_clears_state_and_the_cooldown()
    {
        var detector = new MassChangeDetector();
        var canary = @"C:\Users\fadi\Documents\___nexus_canary.docx";

        detector.Observe(Change(canary, FileChangeKind.Modified, 0, canary: true));
        detector.Reset();

        Assert.Equal(0, detector.TrackedFileCount);
        Assert.NotNull(detector.Observe(Change(canary, FileChangeKind.Modified, 1, canary: true)));
    }

    /// <summary>The realistic case: an encryption run touches a canary, renames
    /// everything to one extension, and drops a note.</summary>
    [Fact]
    public void A_realistic_encryption_run_is_caught_on_the_canary_first()
    {
        var detector = new MassChangeDetector();

        var finding = detector.Observe(Change(
            @"C:\Users\fadi\Documents\___nexus_canary.docx", FileChangeKind.Modified, 0.5, canary: true));

        Assert.NotNull(finding);
        Assert.Contains(finding.Signals, s => s.Code == "ransom-canary-touched");
    }
}
