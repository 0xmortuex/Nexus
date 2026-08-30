using Nexus.Core.Security;
using Nexus.Core.Security.StaticAnalysis;

namespace Nexus.Scanner.Engines;

/// <summary>
/// Reads script files and reports the shapes that mean "this is trying not to be
/// read". Always available: it is text analysis with no external data.
/// </summary>
public sealed class ScriptStaticEngine : IStaticEngine
{
    public string Name => "script analysis";

    public SignalSource SignalSource => SignalSource.StaticRules;

    public bool IsAvailable => true;

    public IReadOnlyList<SecuritySignal> Analyse(ReadOnlySpan<byte> bytes, string path)
    {
        var kind = ScriptAnalyzer.KindFromExtension(path);
        if (kind == ScriptKind.Unknown)
            return [];

        return ScriptAnalyzer.Analyse(ScriptAnalyzer.DecodeText(bytes), kind);
    }
}

/// <summary>
/// Looks inside ZIP archives, because that is how most malware arrives — a scanner
/// that stops at the container reports "unknown" on the very files it most needs an
/// opinion about.
///
/// The limits, the traversal check and the entry walk all live in
/// <see cref="ArchiveInspector"/> in Core, where they are unit-tested: they are
/// security controls against an attacker-controlled file, and an untested limit is
/// a limit nobody has checked. This class only supplies the engines that look at
/// each entry's contents.
/// </summary>
public sealed class ArchiveStaticEngine : IStaticEngine
{
    private readonly PeStaticEngine _pe = new();
    private readonly ScriptStaticEngine _scripts = new();

    public string Name => "archive contents";

    public SignalSource SignalSource => SignalSource.StaticRules;

    public bool IsAvailable => true;

    public IReadOnlyList<SecuritySignal> Analyse(ReadOnlySpan<byte> bytes, string path)
    {
        if (!ArchiveInspector.LooksLikeZip(bytes))
            return [];

        using var stream = new MemoryStream(bytes.ToArray(), writable: false);

        return ArchiveInspector.Inspect(stream, AnalyseEntry);
    }

    private IReadOnlyList<SecuritySignal> AnalyseEntry(byte[] content, string entryName)
    {
        var signals = new List<SecuritySignal>();
        signals.AddRange(_pe.Analyse(content, entryName));
        signals.AddRange(_scripts.Analyse(content, entryName));
        return signals;
    }
}
