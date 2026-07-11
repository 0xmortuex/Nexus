using System.Text.RegularExpressions;

namespace Nexus.Core.Power;

/// <summary>Well-known power scheme GUIDs.</summary>
public static class PowerSchemes
{
    public const string UltimatePerformance = "e9a42b02-d5df-448d-aa00-03f14749eb61";
    public const string HighPerformance = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";
    public const string Balanced = "381b4222-f694-41f0-9685-ff5bb260df2e";
    public const string PowerSaver = "a1841308-3541-4fab-bc81-f71556f20b4a";
}

/// <summary>
/// Pure parsing of powercfg.exe output. Only GUIDs are parsed — never label text,
/// which is localized.
/// </summary>
public static partial class PowerCfgParser
{
    [GeneratedRegex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")]
    private static partial Regex GuidRegex();

    /// <summary>First GUID in the text, e.g. from `powercfg /duplicatescheme` or
    /// `powercfg /getactivescheme` output. Null if none.</summary>
    public static string? ParseFirstGuid(string output)
    {
        var match = GuidRegex().Match(output);
        return match.Success ? match.Value.ToLowerInvariant() : null;
    }

    /// <summary>All scheme GUIDs in `powercfg /list` output, in order, with the raw
    /// line each came from (for display; the line text is localized).</summary>
    public static IReadOnlyList<(string Guid, string RawLine)> ParseSchemeList(string output)
    {
        var result = new List<(string, string)>();
        foreach (var line in output.Split('\n'))
        {
            var match = GuidRegex().Match(line);
            if (match.Success)
                result.Add((match.Value.ToLowerInvariant(), line.Trim()));
        }
        return result;
    }
}
