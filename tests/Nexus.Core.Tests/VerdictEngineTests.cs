using Nexus.Core.Security;
using Xunit;

namespace Nexus.Core.Tests;

public class VerdictEngineTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 30, 12, 0, 0, TimeSpan.Zero);

    private static readonly ScanTarget Target = ScanTarget.ForFile(
        @"C:\Users\x\Downloads\thing.exe", "abc123", 4096);

    private static SecuritySignal Bad(SignalSource source, SignalWeight weight, string code = "bad") =>
        new(source, weight, code, "test signal");

    private static SecuritySignal Good(SignalSource source, SignalWeight weight, string code = "good") =>
        new(source, weight, code, "test signal", Exonerating: true);

    private static Verdict Evaluate(
        IEnumerable<SecuritySignal> signals,
        IEnumerable<SignalSource>? consulted = null,
        bool userTrusted = false) =>
        VerdictEngine.Evaluate(new VerdictInput
        {
            Target = Target,
            Signals = signals.ToArray(),
            EnginesConsulted = new HashSet<SignalSource>(consulted ?? []),
            UserTrusted = userTrusted,
        }, Now);

    private static readonly SignalSource[] AllEngines =
    [
        SignalSource.Reputation, SignalSource.CodeSignature,
        SignalSource.StaticRules, SignalSource.MachineLearning,
    ];

    [Fact]
    public void No_signals_and_no_coverage_is_unknown_not_clean()
    {
        var verdict = Evaluate([]);
        Assert.Equal(ThreatLevel.Unknown, verdict.Level);
        Assert.Equal(0, verdict.Score);
    }

    [Fact]
    public void No_signals_with_full_engine_coverage_is_clean()
    {
        Assert.Equal(ThreatLevel.Clean, Evaluate([], AllEngines).Level);
    }

    [Fact]
    public void A_strong_exonerating_signal_makes_it_trusted()
    {
        var verdict = Evaluate([Good(SignalSource.CodeSignature, SignalWeight.Strong)], AllEngines);
        Assert.Equal(ThreatLevel.Trusted, verdict.Level);
        Assert.Equal(0, verdict.Score);
    }

    [Fact]
    public void A_decisive_bad_signal_is_malicious_and_scores_100()
    {
        var verdict = Evaluate([Bad(SignalSource.Reputation, SignalWeight.Decisive)]);
        Assert.Equal(ThreatLevel.Malicious, verdict.Level);
        Assert.Equal(100, verdict.Score);
    }

    [Fact]
    public void Known_bad_beats_known_good_when_both_are_decisive()
    {
        var verdict = Evaluate(
        [
            Bad(SignalSource.Reputation, SignalWeight.Decisive),
            Good(SignalSource.Reputation, SignalWeight.Decisive),
        ]);
        Assert.Equal(ThreatLevel.Malicious, verdict.Level);
    }

    /// <summary>The corroboration property: the per-source cap sits below the
    /// malicious threshold, so one engine shouting cannot condemn a file.</summary>
    [Fact]
    public void No_single_non_decisive_source_can_reach_malicious()
    {
        foreach (var source in AllEngines)
        {
            var shouting = Enumerable.Range(0, 20)
                .Select(i => Bad(source, SignalWeight.Strong, $"rule-{i}"))
                .ToArray();

            var verdict = Evaluate(shouting);

            Assert.True(verdict.Score <= VerdictEngine.MaxPointsPerSource,
                $"{source} alone scored {verdict.Score}, above the per-source cap");
            Assert.True(verdict.Level < ThreatLevel.Malicious,
                $"{source} alone reached {verdict.Level} without corroboration");
        }
    }

    [Fact]
    public void Two_corroborating_sources_can_reach_malicious()
    {
        var verdict = Evaluate(
        [
            Bad(SignalSource.StaticRules, SignalWeight.Strong, "yara"),
            Bad(SignalSource.MachineLearning, SignalWeight.Strong, "ml"),
            Bad(SignalSource.Behavior, SignalWeight.Strong, "beh"),
        ]);
        Assert.Equal(ThreatLevel.Malicious, verdict.Level);
    }

    [Fact]
    public void Repeated_signals_from_one_source_have_diminishing_returns()
    {
        int one = Evaluate([Bad(SignalSource.StaticRules, SignalWeight.Moderate, "a")]).Score;
        int two = Evaluate(
        [
            Bad(SignalSource.StaticRules, SignalWeight.Moderate, "a"),
            Bad(SignalSource.StaticRules, SignalWeight.Moderate, "b"),
        ]).Score;

        Assert.Equal(20, one);
        Assert.Equal(30, two); // 20 + half of 20, not 40
    }

    [Fact]
    public void Exonerating_signals_offset_suspicion()
    {
        var signals = new[] { Bad(SignalSource.MachineLearning, SignalWeight.Strong) };
        int without = Evaluate(signals).Score;
        int with = Evaluate([.. signals, Good(SignalSource.CodeSignature, SignalWeight.Moderate)]).Score;

        Assert.Equal(35, without);
        Assert.Equal(15, with);
    }

    [Fact]
    public void Informational_signals_never_move_the_score()
    {
        var verdict = Evaluate(
        [
            Bad(SignalSource.Behavior, SignalWeight.Informational, "note-1"),
            Bad(SignalSource.Persistence, SignalWeight.Informational, "note-2"),
        ], AllEngines);

        Assert.Equal(0, verdict.Score);
        Assert.Empty(verdict.Reasons);
    }

    [Theory]
    [InlineData(SignalWeight.Weak, ThreatLevel.Unknown)]
    [InlineData(SignalWeight.Moderate, ThreatLevel.Unknown)]
    [InlineData(SignalWeight.Strong, ThreatLevel.Suspicious)]
    public void Single_signal_levels_are_conservative(SignalWeight weight, ThreatLevel expected)
    {
        Assert.Equal(expected, Evaluate([Bad(SignalSource.StaticRules, weight)]).Level);
    }

    /// <summary>
    /// The calibration that matters in practice. "Unsigned" plus one other mild
    /// observation describes an enormous number of perfectly ordinary files, and on a
    /// real machine that combination produced hundreds of false alarms.
    /// </summary>
    [Fact]
    public void Two_weak_signals_do_not_warrant_an_alert()
    {
        var verdict = Evaluate(
        [
            Bad(SignalSource.CodeSignature, SignalWeight.Weak, "unsigned"),
            Bad(SignalSource.StaticRules, SignalWeight.Weak, "odd-but-common"),
        ]);

        Assert.False(verdict.WarrantsAlert, $"scored {verdict.Score}/100 as {verdict.Level}");
    }

    [Fact]
    public void A_moderate_signal_needs_corroboration_before_it_alerts()
    {
        Assert.False(Evaluate([Bad(SignalSource.StaticRules, SignalWeight.Moderate)]).WarrantsAlert);

        Assert.True(Evaluate(
        [
            Bad(SignalSource.StaticRules, SignalWeight.Moderate),
            Bad(SignalSource.Behavior, SignalWeight.Moderate),
        ]).WarrantsAlert);
    }

    [Fact]
    public void Signals_are_ordered_incriminating_strongest_first_then_exonerating()
    {
        var verdict = Evaluate(
        [
            Good(SignalSource.CodeSignature, SignalWeight.Strong, "signed"),
            Bad(SignalSource.StaticRules, SignalWeight.Weak, "weak"),
            Bad(SignalSource.MachineLearning, SignalWeight.Strong, "strong"),
        ]);

        Assert.Equal(["strong", "weak", "signed"], verdict.Signals.Select(s => s.Code));
    }

    [Fact]
    public void User_trusted_files_never_warrant_an_alert()
    {
        var signals = new[] { Bad(SignalSource.Reputation, SignalWeight.Decisive) };

        Assert.True(Evaluate(signals).WarrantsAlert);
        Assert.False(Evaluate(signals, userTrusted: true).WarrantsAlert);
    }

    [Fact]
    public void Clean_and_trusted_never_warrant_an_alert()
    {
        Assert.False(Evaluate([], AllEngines).WarrantsAlert);
        Assert.False(Evaluate([Good(SignalSource.CodeSignature, SignalWeight.Strong)], AllEngines).WarrantsAlert);
    }
}
