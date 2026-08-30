using System.Text;

namespace Nexus.Core.Security;

/// <summary>
/// The hash-list format Sentinel reads for reputation, and writes when it builds a
/// known-good baseline from the local machine.
///
/// One lowercase hex SHA-256 per line. Blank lines and lines starting with '#' are
/// ignored, so a list can carry its own provenance — which matters more than it
/// sounds: a hash list is a trust decision in bulk, and one that arrives with no
/// record of where it came from should not be believed.
///
/// Exports from other tools commonly append a name after the hash, separated by a
/// comma, space or tab, so that shape is accepted too. Anything that is not a
/// 64-character hex string is skipped rather than aborting the load: one malformed
/// line must not disarm an entire list.
/// </summary>
public static class HashListFile
{
    public const int Sha256HexLength = 64;

    /// <summary>Read hashes from lines, ignoring comments, blanks and malformed entries.</summary>
    public static IReadOnlySet<string> Parse(IEnumerable<string> lines)
    {
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in lines)
        {
            if (TryParseLine(raw, out var hash))
                hashes.Add(hash);
        }

        return hashes;
    }

    /// <summary>True when the line yields a usable SHA-256.</summary>
    public static bool TryParseLine(string line, out string hash)
    {
        hash = "";

        var trimmed = line.Trim();
        if (trimmed.Length == 0 || trimmed[0] == '#')
            return false;

        // Tolerate "hash,name", "hash name" and "hash<tab>name".
        int separator = trimmed.IndexOfAny([',', ' ', '\t']);
        var candidate = separator > 0 ? trimmed[..separator] : trimmed;

        if (!IsSha256Hex(candidate))
            return false;

        hash = candidate.ToLowerInvariant();
        return true;
    }

    public static bool IsSha256Hex(string value)
    {
        if (value.Length != Sha256HexLength)
            return false;

        foreach (char c in value)
        {
            if (!char.IsAsciiHexDigit(c))
                return false;
        }

        return true;
    }

    /// <summary>
    /// Render a list with a header explaining where it came from.
    ///
    /// The header is not decoration. A known-good list silently exonerates every file
    /// it contains, so anyone looking at one later needs to know what produced it and
    /// when — a baseline built from a machine that was already compromised is worth
    /// knowing about.
    /// </summary>
    public static string Write(IEnumerable<string> hashes, string provenance, DateTimeOffset generatedAt)
    {
        var builder = new StringBuilder();

        builder.AppendLine("# Nexus Sentinel hash list");
        builder.AppendLine("# " + provenance);
        builder.AppendLine($"# Generated {generatedAt:u}");
        builder.AppendLine("#");
        builder.AppendLine("# One lowercase hex SHA-256 per line. Delete this file to discard it.");
        builder.AppendLine();

        foreach (var hash in hashes.Where(IsSha256Hex).Select(h => h.ToLowerInvariant()).Order(StringComparer.Ordinal))
            builder.AppendLine(hash);

        return builder.ToString();
    }
}
