using Nexus.Core.Suggestions;
using Nexus.Core.Tweaks;
using Xunit;

namespace Nexus.Core.Tests;

public class SuggestionEngineTests
{
    /// <summary>Facts describing an already-optimized machine (no suggestions expected).</summary>
    private static SystemFacts OptimizedFacts => new()
    {
        GameDvrCaptureEnabled = false,
        MouseAccelerationEnabled = false,
        WindowsGameModeEnabled = true,
        StickyKeysShortcutEnabled = false,
        DiagTrackEnabled = false,
        CompatAppraiserTaskEnabled = false,
        ProBalanceEnabled = true,
        GameModeEnabled = true,
        IsHybridCpu = false,
        GameProfileCount = 3,
        NexusPerformancePlanExists = true,
    };

    [Fact]
    public void Optimized_machine_gets_no_suggestions()
    {
        Assert.Empty(SuggestionEngine.Evaluate(OptimizedFacts));
    }

    [Fact]
    public void Each_negative_fact_produces_exactly_its_suggestion()
    {
        AssertSuggests(OptimizedFacts with { GameDvrCaptureEnabled = true }, "sug-gamedvr");
        AssertSuggests(OptimizedFacts with { MouseAccelerationEnabled = true }, "sug-mouse-accel");
        AssertSuggests(OptimizedFacts with { WindowsGameModeEnabled = false }, "sug-win-game-mode");
        AssertSuggests(OptimizedFacts with { StickyKeysShortcutEnabled = true }, "sug-sticky-keys");
        AssertSuggests(OptimizedFacts with { DiagTrackEnabled = true }, "sug-diagtrack");
        AssertSuggests(OptimizedFacts with { CompatAppraiserTaskEnabled = true }, "sug-appraiser");
        AssertSuggests(OptimizedFacts with { ProBalanceEnabled = false }, "sug-probalance");
        AssertSuggests(OptimizedFacts with { GameModeEnabled = false }, "sug-game-mode");
        AssertSuggests(OptimizedFacts with { NexusPerformancePlanExists = false }, "sug-perf-plan");
    }

    [Fact]
    public void Hybrid_cpu_without_games_suggests_adding_games_as_a_hint()
    {
        var suggestion = Assert.Single(SuggestionEngine.Evaluate(
            OptimizedFacts with { IsHybridCpu = true, GameProfileCount = 0 }));

        Assert.Equal("sug-hybrid-games", suggestion.Id);
        Assert.Equal(SuggestionKind.Hint, suggestion.Kind);
        Assert.Equal("", suggestion.TargetId);
    }

    [Fact]
    public void Non_hybrid_cpu_never_suggests_hybrid_hint()
    {
        Assert.DoesNotContain(SuggestionEngine.Evaluate(OptimizedFacts with { GameProfileCount = 0 }),
            s => s.Id == "sug-hybrid-games");
    }

    [Fact]
    public void Actionable_tweak_suggestions_reference_real_catalog_ids()
    {
        // The whole point of the panel is one-click apply — every ApplyTweak suggestion
        // must target a tweak that actually exists, or the Apply button would fail.
        var facts = new SystemFacts
        {
            GameDvrCaptureEnabled = true,
            MouseAccelerationEnabled = true,
            WindowsGameModeEnabled = false,
            StickyKeysShortcutEnabled = true,
        };

        foreach (var suggestion in SuggestionEngine.Evaluate(facts)
                     .Where(s => s.Kind == SuggestionKind.ApplyTweak))
        {
            Assert.NotNull(TweakCatalog.Find(suggestion.TargetId));
        }
    }

    [Fact]
    public void Every_suggestion_has_a_reason()
    {
        var facts = new SystemFacts
        {
            GameDvrCaptureEnabled = true,
            DiagTrackEnabled = true,
            ProBalanceEnabled = false,
        };

        Assert.All(SuggestionEngine.Evaluate(facts), s =>
        {
            Assert.False(string.IsNullOrWhiteSpace(s.Title));
            Assert.False(string.IsNullOrWhiteSpace(s.Reason));
        });
    }

    private static void AssertSuggests(SystemFacts facts, string expectedId)
    {
        Assert.Contains(SuggestionEngine.Evaluate(facts), s => s.Id == expectedId);
    }
}
