using Nexus.Core.Persistence;
using Nexus.Core.Security;
using Nexus.Core.Security.StaticAnalysis;

namespace Nexus.Scanner.Engines;

/// <summary>
/// Literal byte-pattern signatures loaded from assets/patterns.txt.
///
/// Available whenever a pattern file is present — no native dependency, no model,
/// no download. This is the engine that makes signature detection work out of the
/// box; YARA, when present, runs alongside it rather than replacing it.
/// </summary>
public sealed class PatternSignatureEngine : IStaticEngine
{
    private readonly PatternEngine? _engine;

    private PatternSignatureEngine(PatternEngine? engine)
    {
        _engine = engine;
    }

    public string Name => "byte patterns";

    public SignalSource SignalSource => SignalSource.StaticRules;

    public bool IsAvailable => _engine is { HasPatterns: true };

    public static PatternSignatureEngine Create()
    {
        var path = Path.Combine(NexusPaths.AssetsDirectory, "patterns.txt");
        if (!File.Exists(path))
            return new PatternSignatureEngine(null);

        try
        {
            var patterns = PatternEngine.ParseRules(File.ReadLines(path), out var errors);

            foreach (var error in errors)
                Console.Error.WriteLine($"patterns.txt: {error}");

            return new PatternSignatureEngine(new PatternEngine(patterns));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"could not read patterns.txt: {ex.Message}");
            return new PatternSignatureEngine(null);
        }
    }

    public IReadOnlyList<SecuritySignal> Analyse(ReadOnlySpan<byte> bytes, string path) =>
        _engine?.Scan(bytes) ?? [];
}

/// <summary>
/// YARA rule matching, when a YARA-X native library and compiled rules are present
/// beside the executable.
///
/// Not wired up in this build, and it reports itself unavailable rather than
/// pretending otherwise. Two things have to be true before it can do anything: the
/// native library has to be shipped, and a rule set has to be chosen — and rule
/// sets carry licences (Elastic's are open, some commercial feeds are not) that are
/// a deliberate decision rather than a default.
///
/// An unavailable engine is excluded from the "engines consulted" count, so its
/// absence makes files come back "unknown" rather than falsely "clean".
/// </summary>
public sealed class YaraEngine : IStaticEngine
{
    private YaraEngine()
    {
    }

    public string Name => "YARA";

    public SignalSource SignalSource => SignalSource.StaticRules;

    public bool IsAvailable => false;

    public static YaraEngine Create() => new();

    public IReadOnlyList<SecuritySignal> Analyse(ReadOnlySpan<byte> bytes, string path) => [];
}
