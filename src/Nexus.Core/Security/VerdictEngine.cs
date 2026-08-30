namespace Nexus.Core.Security;

/// <summary>Everything the fusion step needs. Pure data, so the engine stays testable.</summary>
public sealed record VerdictInput
{
    public required ScanTarget Target { get; init; }
    public required IReadOnlyList<SecuritySignal> Signals { get; init; }

    /// <summary>Which engines actually got to run. A file nobody could parse is
    /// "unknown", not "clean" — this is how the engine tells those two apart.</summary>
    public IReadOnlySet<SignalSource> EnginesConsulted { get; init; } =
        new HashSet<SignalSource>();

    /// <summary>The user has previously vouched for this exact content hash.</summary>
    public bool UserTrusted { get; init; }
}

/// <summary>
/// Fuses the signals from every detection engine into one explainable verdict.
///
/// Two rules shape the scoring, both aimed at the same thing — an advisory tool
/// that cries wolf is worse than useless, because the user learns to dismiss it:
///
/// 1. <b>Diminishing returns per source.</b> A source's strongest signal counts in
///    full; every additional signal from that same source counts half, and the source
///    is capped at <see cref="MaxPointsPerSource"/>. Forty YARA hits on one packer are
///    one opinion, not forty.
/// 2. <b>Corroboration required for the top verdict.</b> Because that cap (60) sits
///    below the malicious threshold (75), no single non-decisive engine can call
///    anything malicious on its own. Only an exact known-bad hash — a
///    <see cref="SignalWeight.Decisive"/> signal — gets to do that unaided.
/// </summary>
public static class VerdictEngine
{
    public const int MaxPointsPerSource = 60;

    /// <summary>
    /// Raised from 15 after a real machine produced 948 findings, almost all of them
    /// wrong. At 15, two Weak signals from different sources — "unsigned" plus almost
    /// anything — cleared the bar, and a single Moderate did too. That contradicted
    /// this file's own stated principle that packing alone is not malware.
    ///
    /// At 25 a lone Moderate no longer alerts and neither do two Weaks, so a finding
    /// needs either something Strong or genuine corroboration. An advisory tool that
    /// flags a thousand ordinary files has not found a thousand problems; it has
    /// taught its user to close the window.
    /// </summary>
    public const int SuspiciousAt = 25;
    public const int LikelyMaliciousAt = 45;
    public const int MaliciousAt = 75;

    /// <summary>Below this many engines reporting, a zero score means "we didn't
    /// look hard enough", not "this is fine".</summary>
    public const int EnginesNeededForClean = 3;

    public static Verdict Evaluate(VerdictInput input, DateTimeOffset now)
    {
        var incriminating = input.Signals.Where(s => !s.Exonerating).ToArray();
        var exonerating = input.Signals.Where(s => s.Exonerating).ToArray();

        int suspicion = Aggregate(incriminating);
        int defence = Aggregate(exonerating);

        bool decisivelyBad = incriminating.Any(s => s.Weight == SignalWeight.Decisive);
        bool decisivelyGood = exonerating.Any(s => s.Weight == SignalWeight.Decisive);

        int score = Math.Clamp(suspicion - defence, 0, 100);
        var level = Classify(score, decisivelyBad, decisivelyGood, exonerating, input.EnginesConsulted);

        // A decisive verdict should read as 0 or 100, not as whatever the arithmetic
        // happened to produce, so the number and the label never contradict each other.
        if (decisivelyBad)
            score = 100;
        else if (level == ThreatLevel.Trusted)
            score = 0;

        return new Verdict
        {
            Target = input.Target,
            Level = level,
            Score = score,
            Signals = Order(input.Signals),
            EvaluatedAt = now,
            UserTrusted = input.UserTrusted,
        };
    }

    /// <summary>Strongest signal at full value, the rest at half, capped per source.</summary>
    private static int Aggregate(IReadOnlyList<SecuritySignal> signals)
    {
        int total = 0;

        foreach (var group in signals.GroupBy(s => s.Source))
        {
            var ordered = group.OrderByDescending(s => s.Points).ToArray();
            int subtotal = 0;

            for (int i = 0; i < ordered.Length; i++)
                subtotal += i == 0 ? ordered[i].Points : ordered[i].Points / 2;

            // A decisive signal must survive the cap — that is what makes it decisive.
            int cap = ordered.Any(s => s.Weight == SignalWeight.Decisive) ? 100 : MaxPointsPerSource;
            total += Math.Min(subtotal, cap);
        }

        return total;
    }

    private static ThreatLevel Classify(
        int score,
        bool decisivelyBad,
        bool decisivelyGood,
        IReadOnlyList<SecuritySignal> exonerating,
        IReadOnlySet<SignalSource> enginesConsulted)
    {
        // Known-bad beats known-good. A hash in both a known-good set and a malware
        // feed means the known-good set is stale or poisoned; assume the worse.
        if (decisivelyBad)
            return ThreatLevel.Malicious;

        if (score >= MaliciousAt)
            return ThreatLevel.Malicious;
        if (score >= LikelyMaliciousAt)
            return ThreatLevel.LikelyMalicious;
        if (score >= SuspiciousAt)
            return ThreatLevel.Suspicious;

        // Nothing incriminating survived. Now separate "vouched for" from "looks
        // fine" from "we simply don't know".
        if (score == 0 && (decisivelyGood || exonerating.Any(s => s.Weight >= SignalWeight.Strong)))
            return ThreatLevel.Trusted;

        if (score == 0 && enginesConsulted.Count >= EnginesNeededForClean)
            return ThreatLevel.Clean;

        return ThreatLevel.Unknown;
    }

    /// <summary>Incriminating signals first (strongest first), then exonerating ones.
    /// The UI renders this list in order, so it is the order a human reads.</summary>
    private static IReadOnlyList<SecuritySignal> Order(IReadOnlyList<SecuritySignal> signals) =>
        signals
            .OrderBy(s => s.Exonerating)
            .ThenByDescending(s => s.Points)
            .ThenBy(s => s.Code, StringComparer.Ordinal)
            .ToArray();
}
