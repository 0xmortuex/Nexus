using Nexus.Core.GameMode;
using Nexus.Core.Models;
using Nexus.Core.Persistence;
using Xunit;

namespace Nexus.Core.Tests;

public class GameDetectorTests
{
    private const uint WS_CAPTION = 0x00C00000;
    private const uint WS_POPUP = 0x80000000;

    private static readonly RectPx Monitor1080 = new(0, 0, 1920, 1080);
    private static readonly string[] NoList = [];

    private static WindowInfo Window(string exe, RectPx rect, uint style = WS_POPUP)
        => new(exe, rect, style, 0);

    [Fact]
    public void Borderless_fullscreen_unknown_exe_is_a_game()
    {
        var window = Window("eldenring.exe", new RectPx(0, 0, 1920, 1080));

        Assert.True(GameDetector.LooksLikeGame(window, Monitor1080, NoList, NoList));
    }

    [Fact]
    public void Fullscreen_within_tolerance_still_counts()
    {
        var window = Window("game.exe", new RectPx(-1, -1, 1921, 1081));

        Assert.True(GameDetector.LooksLikeGame(window, Monitor1080, NoList, NoList));
    }

    [Fact]
    public void Windowed_app_is_not_a_game()
    {
        // Smaller than the monitor and carrying a caption bar.
        var window = Window("app.exe", new RectPx(100, 100, 1400, 900), style: WS_CAPTION);

        Assert.False(GameDetector.LooksLikeGame(window, Monitor1080, NoList, NoList));
    }

    [Fact]
    public void Maximized_captioned_window_is_not_a_game()
    {
        // Covers the monitor but has a title bar (e.g. a maximized editor).
        var window = Window("editor.exe", new RectPx(0, 0, 1920, 1080), style: WS_CAPTION | 0x10000000);

        Assert.False(GameDetector.LooksLikeGame(window, Monitor1080, NoList, NoList));
    }

    [Fact]
    public void Known_non_games_are_rejected_even_fullscreen()
    {
        foreach (var exe in new[] { "chrome.exe", "vlc.exe", "explorer.exe", "obs64.exe", "powerpnt.exe" })
        {
            var window = Window(exe, new RectPx(0, 0, 1920, 1080));
            Assert.False(GameDetector.LooksLikeGame(window, Monitor1080, NoList, NoList));
        }
    }

    [Fact]
    public void User_listed_game_counts_even_windowed()
    {
        var window = Window("factorio.exe", new RectPx(100, 100, 1200, 800), style: WS_CAPTION);

        Assert.True(GameDetector.LooksLikeGame(window, Monitor1080, ["Factorio"], NoList));
    }

    [Fact]
    public void User_ignore_list_beats_everything()
    {
        var window = Window("game.exe", new RectPx(0, 0, 1920, 1080));

        Assert.False(GameDetector.LooksLikeGame(window, Monitor1080, ["game.exe"], ["game.exe"]));
    }

    [Fact]
    public void Window_spanning_only_part_of_ultrawide_is_not_a_game()
    {
        var ultrawide = new RectPx(0, 0, 3440, 1440);
        var window = Window("app.exe", new RectPx(0, 0, 1920, 1440));

        Assert.False(GameDetector.LooksLikeGame(window, ultrawide, NoList, NoList));
    }

    [Fact]
    public void Protected_processes_are_never_games()
    {
        var window = Window("easyanticheat.exe", new RectPx(0, 0, 1920, 1080));

        Assert.False(GameDetector.LooksLikeGame(window, Monitor1080, NoList, NoList));
    }
}

public class IntendedStateJournalTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nexus-journal-").FullName;

    private IntendedStateJournal NewJournal() => new(new JsonStore<IntendedState>(
        Path.Combine(_dir, "intended-state.json"),
        NexusJsonContext.Default.IntendedState,
        static () => new IntendedState()));

    [Fact]
    public void Empty_journal_reports_nothing_pending()
    {
        Assert.Null(NewJournal().LoadPending());
    }

    [Fact]
    public void Journal_survives_process_restart()
    {
        var journal = NewJournal();
        journal.SetActiveGame("game.exe");
        journal.RecordPreviousPowerPlan("381b4222-f694-41f0-9685-ff5bb260df2e");
        journal.RecordWindowsUpdatePaused();
        journal.RecordMutation(new ProcessMutationRecord(
            123, "game.exe", ProcessPriority.Normal, 0xFF, true, true));

        // A fresh instance (≈ app restart after crash) must see everything.
        var pending = NewJournal().LoadPending();

        Assert.NotNull(pending);
        Assert.Equal("game.exe", pending.ActiveGameExe);
        Assert.Equal("381b4222-f694-41f0-9685-ff5bb260df2e", pending.PreviousPowerPlanGuid);
        Assert.True(pending.WindowsUpdatePaused);
        var mutation = Assert.Single(pending.Mutations);
        Assert.Equal(123, mutation.Pid);
        Assert.Equal(ProcessPriority.Normal, mutation.OriginalPriority);
        Assert.Equal(0xFFUL, mutation.OriginalAffinityMask);
    }

    [Fact]
    public void First_mutation_record_per_pid_wins()
    {
        var journal = NewJournal();
        journal.RecordMutation(new ProcessMutationRecord(1, "a.exe", ProcessPriority.High, null, false, false));
        // A second record for the same PID (e.g. hog demoted twice) must not
        // overwrite the true original values.
        journal.RecordMutation(new ProcessMutationRecord(1, "a.exe", ProcessPriority.BelowNormal, null, false, true));

        var mutation = Assert.Single(NewJournal().LoadPending()!.Mutations);

        Assert.Equal(ProcessPriority.High, mutation.OriginalPriority);
    }

    [Fact]
    public void Previous_power_plan_is_not_overwritten()
    {
        var journal = NewJournal();
        journal.RecordPreviousPowerPlan("plan-a");
        journal.RecordPreviousPowerPlan("plan-b");

        Assert.Equal("plan-a", NewJournal().LoadPending()!.PreviousPowerPlanGuid);
    }

    [Fact]
    public void Clear_leaves_nothing_pending()
    {
        var journal = NewJournal();
        journal.SetActiveGame("game.exe");
        journal.Clear();

        Assert.Null(NewJournal().LoadPending());
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);
}
