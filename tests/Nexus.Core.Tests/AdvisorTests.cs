using Nexus.Core.Advisor;
using Nexus.Core.GameMode;
using Nexus.Core.Models;
using Nexus.Core.Tweaks;
using Xunit;

namespace Nexus.Core.Tests;

public class OptimizationCatalogTests
{
    [Fact]
    public void Every_tweak_has_effectiveness_metadata_with_pros_and_cons()
    {
        // The UI shows an effectiveness meter + pros/cons for every tweak; a missing
        // entry would render a blank card, so this must stay complete.
        foreach (var tweak in TweakCatalog.All)
        {
            var info = OptimizationCatalog.Find(tweak.Id);
            Assert.NotNull(info);
            Assert.NotEmpty(info!.Pros);
            Assert.NotEmpty(info.Cons);
        }
    }

    [Fact]
    public void Effectiveness_of_unknown_id_defaults_to_minor()
    {
        Assert.Equal(Effectiveness.Minor, OptimizationCatalog.EffectivenessOf("nope"));
    }

    [Fact]
    public void Mouse_accel_is_rated_strong_nagle_situational()
    {
        // Sanity on the honesty of the ratings: a deterministic-aim tweak is strong,
        // a usually-no-op network tweak is situational.
        Assert.Equal(Effectiveness.Strong, OptimizationCatalog.Find("mouse-accel-off")!.Effectiveness);
        Assert.Equal(Effectiveness.Situational, OptimizationCatalog.Find("nagle-off")!.Effectiveness);
    }
}

public class SystemRatingEngineTests
{
    private static RatingFactor F(string cat, Effectiveness eff, bool active)
        => new($"{cat}-{eff}-{active}", cat, eff, active);

    [Fact]
    public void All_active_scores_100_grade_a()
    {
        var rating = SystemRatingEngine.Rate(
        [
            F("Responsiveness", Effectiveness.Strong, true),
            F("Latency", Effectiveness.Moderate, true),
        ]);

        Assert.Equal(100, rating.Score);
        Assert.Equal("A", rating.Grade);
    }

    [Fact]
    public void Nothing_active_scores_zero_grade_f()
    {
        var rating = SystemRatingEngine.Rate(
        [
            F("Responsiveness", Effectiveness.Strong, false),
            F("Latency", Effectiveness.Minor, false),
        ]);

        Assert.Equal(0, rating.Score);
        Assert.Equal("F", rating.Grade);
    }

    [Fact]
    public void Situational_toggles_barely_move_the_score()
    {
        // A category carrying one Strong (weight 4) factor, off, plus four
        // Situational (weight 1) factors, on. Score must stay low — you can't game
        // the rating by flipping low-value switches.
        var factors = new List<RatingFactor> { F("Latency", Effectiveness.Strong, false) };
        for (int i = 0; i < 4; i++)
            factors.Add(new RatingFactor($"s{i}", "Latency", Effectiveness.Situational, true));

        var rating = SystemRatingEngine.Rate(factors);

        Assert.InRange(rating.Score, 40, 55); // 4 of 8 weight → 50%
    }

    [Fact]
    public void Category_breakdown_counts_active_and_total()
    {
        var rating = SystemRatingEngine.Rate(
        [
            F("Privacy", Effectiveness.Moderate, true),
            F("Privacy", Effectiveness.Moderate, false),
            F("Memory", Effectiveness.Minor, true),
        ]);

        var privacy = rating.Categories.Single(c => c.Category == "Privacy");
        Assert.Equal(1, privacy.ActiveCount);
        Assert.Equal(2, privacy.TotalCount);
        Assert.Equal(50, privacy.Score);

        var memory = rating.Categories.Single(c => c.Category == "Memory");
        Assert.Equal(100, memory.Score);
    }

    [Fact]
    public void Empty_input_is_safe()
    {
        var rating = SystemRatingEngine.Rate([]);
        Assert.Equal(0, rating.Score);
        Assert.Empty(rating.Categories);
    }

    [Theory]
    [InlineData(95, "A")]
    [InlineData(85, "B")]
    [InlineData(70, "C")]
    [InlineData(55, "D")]
    [InlineData(20, "F")]
    public void Grade_boundaries(int score, string grade) => Assert.Equal(grade, SystemRatingEngine.GradeFor(score));
}

public class GameRatingEngineTests
{
    [Fact]
    public void Fully_configured_hybrid_profile_scores_high()
    {
        var profile = new GameProfile
        {
            ExeName = "game.exe",
            Priority = ProcessPriority.High,
            Pinning = CpuAffinityMode.PCoresOnly,
            DemoteBackgroundHogs = true,
            UsePerformancePowerPlan = true,
            PauseWindowsUpdate = true,
        };

        var rating = GameRatingEngine.Rate(profile, isHybridCpu: true);

        Assert.Equal(100, rating.Score);
        Assert.Equal("A", rating.Grade);
        Assert.All(rating.Aspects, a => Assert.True(a.Active));
    }

    [Fact]
    public void Bare_profile_scores_low_and_lists_what_is_missing()
    {
        var profile = new GameProfile
        {
            ExeName = "game.exe",
            Priority = ProcessPriority.Normal,
            Pinning = CpuAffinityMode.None,
            DemoteBackgroundHogs = false,
            UsePerformancePowerPlan = false,
            PauseWindowsUpdate = false,
        };

        var rating = GameRatingEngine.Rate(profile, isHybridCpu: true);

        Assert.Equal(0, rating.Score);
        Assert.Contains(rating.Aspects, a => a.Name == "Pinned to P-cores" && !a.Active);
    }

    [Fact]
    public void Pinning_aspect_is_labelled_by_cpu_kind()
    {
        var profile = new GameProfile { ExeName = "g.exe", Pinning = CpuAffinityMode.PhysicalCoresOnly };

        var hybrid = GameRatingEngine.Rate(profile, isHybridCpu: true);
        var flat = GameRatingEngine.Rate(profile, isHybridCpu: false);

        Assert.Contains(hybrid.Aspects, a => a.Name == "Pinned to P-cores");
        Assert.Contains(flat.Aspects, a => a.Name == "Pinned to physical cores");
    }
}

public class WizardModelTests
{
    [Fact]
    public void Steps_run_welcome_to_finish_in_order()
    {
        Assert.Equal(WizardStepId.Welcome, WizardModel.Steps[0].Id);
        Assert.Equal(WizardStepId.Finish, WizardModel.Steps[^1].Id);
    }

    [Fact]
    public void Navigation_stops_at_both_ends()
    {
        Assert.Null(WizardModel.Previous(WizardStepId.Welcome));
        Assert.Equal(WizardStepId.Scan, WizardModel.Next(WizardStepId.Welcome));
        Assert.Equal(WizardStepId.Apply, WizardModel.Previous(WizardStepId.Finish));
        Assert.Null(WizardModel.Next(WizardStepId.Finish));
    }

    [Fact]
    public void Every_step_has_title_and_subtitle()
    {
        Assert.All(WizardModel.Steps, s =>
        {
            Assert.False(string.IsNullOrWhiteSpace(s.Title));
            Assert.False(string.IsNullOrWhiteSpace(s.Subtitle));
        });
    }
}
