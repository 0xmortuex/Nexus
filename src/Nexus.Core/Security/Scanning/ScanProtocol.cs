namespace Nexus.Core.Security.Scanning;

/// <summary>
/// The line-delimited JSON protocol between Nexus and its scanner worker.
///
/// The worker exists for one reason: parsing hostile files is the most dangerous
/// thing a security tool does, and Nexus runs elevated. Every remote code execution
/// bug of consequence in a mainstream antivirus has been in its file parsers, and
/// putting those parsers in the same process as an administrator token turns a
/// parser bug into a full machine compromise. So the parsing happens in a separate,
/// short-lived, lower-privilege process, and only this small, boring data structure
/// crosses back.
///
/// The boundary is only worth having if what crosses it is inert: these records
/// carry text and enums, never paths to act on, never commands, never a verdict the
/// host will execute.
/// </summary>
public sealed record ScanRequest
{
    /// <summary>Correlates the response; the host generates it.</summary>
    public required string Id { get; init; }

    public required string Path { get; init; }
}

/// <summary>A signal as it crosses the process boundary.</summary>
public sealed record ScanSignal
{
    public required string Source { get; init; }
    public required string Weight { get; init; }
    public required string Code { get; init; }
    public required string Explanation { get; init; }
    public bool Exonerating { get; init; }

    public static ScanSignal From(SecuritySignal signal) => new()
    {
        Source = signal.Source.ToString(),
        Weight = signal.Weight.ToString(),
        Code = signal.Code,
        Explanation = signal.Explanation,
        Exonerating = signal.Exonerating,
    };

    /// <summary>
    /// Convert back on the host side. Unparseable values become an informational
    /// signal rather than an exception — a compromised or buggy worker must not be
    /// able to crash the host by sending nonsense, and must not be able to
    /// manufacture a weight the enum does not define.
    /// </summary>
    public SecuritySignal ToSignal()
    {
        var source = Enum.TryParse<SignalSource>(Source, ignoreCase: false, out var parsedSource)
            ? parsedSource
            : SignalSource.StaticRules;

        var weight = Enum.TryParse<SignalWeight>(Weight, ignoreCase: false, out var parsedWeight)
            ? parsedWeight
            : SignalWeight.Informational;

        return new SecuritySignal(source, weight, Code, Explanation, Exonerating);
    }
}

public sealed record ScanResponse
{
    public required string Id { get; init; }
    public IReadOnlyList<ScanSignal> Signals { get; init; } = [];

    /// <summary>Set when the worker could not analyse the file at all.</summary>
    public string? Error { get; init; }

    /// <summary>Which engines actually ran, so the host can tell "clean" from
    /// "nobody looked".</summary>
    public IReadOnlyList<string> EnginesConsulted { get; init; } = [];
}
