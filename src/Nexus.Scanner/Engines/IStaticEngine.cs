using Nexus.Core.Security;
using Nexus.Core.Security.StaticAnalysis;

namespace Nexus.Scanner.Engines;

/// <summary>One static analysis engine operating on a file's bytes.</summary>
public interface IStaticEngine
{
    string Name { get; }

    SignalSource SignalSource { get; }

    /// <summary>
    /// False when the engine's data or native dependency is missing. An unavailable
    /// engine is skipped and, crucially, is not counted among the engines consulted —
    /// so a file nobody could analyse comes back "unknown" rather than "clean".
    /// </summary>
    bool IsAvailable { get; }

    IReadOnlyList<SecuritySignal> Analyse(ReadOnlySpan<byte> bytes, string path);
}

/// <summary>Structural analysis of Windows executables. Always available: it is
/// managed code with no external data.</summary>
public sealed class PeStaticEngine : IStaticEngine
{
    public string Name => "PE structure";

    public SignalSource SignalSource => SignalSource.StaticRules;

    public bool IsAvailable => true;

    public IReadOnlyList<SecuritySignal> Analyse(ReadOnlySpan<byte> bytes, string path)
    {
        var image = PeImage.TryParse(bytes);
        if (image is null)
        {
            // Not a PE file. That is only worth saying when the name claims otherwise,
            // because a mismatch between extension and contents is itself a finding.
            var extension = Path.GetExtension(path);
            bool claimsExecutable = extension is ".exe" or ".dll" or ".scr" or ".sys" or ".ocx";

            return claimsExecutable
                ?
                [
                    new SecuritySignal(SignalSource.StaticRules, SignalWeight.Moderate, "pe-not-an-executable",
                        $"This file is named like a program ({extension}) but its contents are not a " +
                        "Windows executable."),
                ]
                : [];
        }

        return PeHeuristics.Evaluate(image);
    }
}
