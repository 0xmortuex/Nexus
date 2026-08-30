namespace Nexus.Core.Security;

/// <summary>Which detection engine produced a piece of evidence.</summary>
public enum SignalSource
{
    /// <summary>Hash reputation: known-good (NSRL) or known-bad (MalwareBazaar / VirusTotal) lists.</summary>
    Reputation,

    /// <summary>Authenticode signature state, via WinVerifyTrust.</summary>
    CodeSignature,

    /// <summary>YARA rule matches over the file's bytes.</summary>
    StaticRules,

    /// <summary>The PE-feature classifier's opinion.</summary>
    MachineLearning,

    /// <summary>Runtime behaviour observed over ETW (process trees, command lines, network).</summary>
    Behavior,

    /// <summary>Autorun/persistence surface auditing (Run keys, tasks, services, WMI, IFEO).</summary>
    Persistence,
}

/// <summary>
/// How much one signal moves the needle. Deliberately coarse: engines are bad at
/// expressing calibrated probabilities, and a five-step scale is honest about that.
/// </summary>
public enum SignalWeight
{
    /// <summary>Context for the human; contributes nothing to the score.</summary>
    Informational,
    Weak,
    Moderate,
    Strong,

    /// <summary>On its own sufficient to call something malicious (e.g. an exact known-bad hash).</summary>
    Decisive,
}

/// <summary>
/// One piece of evidence about one file or process. <see cref="Explanation"/> is
/// shown verbatim to the user, so it is written in plain language and states what
/// was observed — never what the user should feel about it.
/// </summary>
/// <param name="Code">Stable identifier for the check (e.g. "sig-unsigned"), used
/// for suppression and tests. Never shown to the user.</param>
/// <param name="Exonerating">True when this signal is evidence of innocence and
/// should push the score down rather than up.</param>
public sealed record SecuritySignal(
    SignalSource Source,
    SignalWeight Weight,
    string Code,
    string Explanation,
    bool Exonerating = false)
{
    /// <summary>Points this signal contributes to the 0–100 suspicion score.</summary>
    public int Points => Weight switch
    {
        SignalWeight.Informational => 0,
        SignalWeight.Weak => 8,
        SignalWeight.Moderate => 20,
        SignalWeight.Strong => 35,
        SignalWeight.Decisive => 100,
        _ => 0,
    };
}

/// <summary>
/// The conclusion Nexus reports. Ordered by increasing suspicion; the UI colours
/// and sorts by this, and nothing in the codebase acts on it automatically.
/// </summary>
public enum ThreatLevel
{
    /// <summary>Positively vouched for — a valid signature from a publisher the
    /// machine trusts, or an exact match in a known-good hash set.</summary>
    Trusted,

    /// <summary>Nothing of concern found, but nothing vouched for it either.</summary>
    Clean,

    /// <summary>Not enough evidence in either direction. The honest default for
    /// most small unsigned utilities, and NOT an accusation.</summary>
    Unknown,

    /// <summary>Enough odd properties to be worth a human look.</summary>
    Suspicious,

    /// <summary>Strong evidence, short of certainty.</summary>
    LikelyMalicious,

    /// <summary>Certain: an exact known-bad match or an equivalent decisive signal.</summary>
    Malicious,
}

/// <summary>
/// The complete, explainable result for one target.
///
/// This type is the whole point of Sentinel's advisory design: it carries evidence
/// and a conclusion, and it carries no instruction. There is no "Action" member and
/// no engine anywhere in Nexus.Core that consumes a verdict to mutate the system —
/// everything a verdict can lead to goes through an explicit user gesture. See
/// <see cref="UserConsent"/>.
/// </summary>
public sealed record Verdict
{
    public required ScanTarget Target { get; init; }
    public required ThreatLevel Level { get; init; }

    /// <summary>0–100 suspicion score. Exposed because hiding the number behind a
    /// label is exactly the kind of opacity this project exists to avoid.</summary>
    public required int Score { get; init; }

    /// <summary>Every signal considered, strongest first, exonerating ones last.</summary>
    public required IReadOnlyList<SecuritySignal> Signals { get; init; }

    public required DateTimeOffset EvaluatedAt { get; init; }

    /// <summary>True when the user has previously told Nexus to trust this exact file.</summary>
    public bool UserTrusted { get; init; }

    /// <summary>One-line plain-language summary for the log and the notification.</summary>
    public string Headline => Level switch
    {
        ThreatLevel.Trusted => $"{Target.FileName} is signed and trusted.",
        ThreatLevel.Clean => $"{Target.FileName} looks fine.",
        ThreatLevel.Unknown => $"{Target.FileName} is unknown — nothing bad found, nothing vouching for it.",
        ThreatLevel.Suspicious => $"{Target.FileName} has properties worth a look.",
        ThreatLevel.LikelyMalicious => $"{Target.FileName} looks malicious.",
        ThreatLevel.Malicious => $"{Target.FileName} is known malware.",
        _ => Target.FileName,
    };

    /// <summary>The signals a human should read first: everything that actually moved
    /// the score, strongest first.</summary>
    public IReadOnlyList<SecuritySignal> Reasons =>
        Signals.Where(s => s.Weight != SignalWeight.Informational).ToArray();

    /// <summary>True when this verdict is worth interrupting the user for.</summary>
    public bool WarrantsAlert => !UserTrusted && Level >= ThreatLevel.Suspicious;
}
