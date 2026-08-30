using System.Globalization;
using System.Text;

namespace Nexus.Core.Security.StaticAnalysis;

/// <summary>One byte-pattern signature.</summary>
/// <param name="Bytes">The literal bytes to find. Wildcards are not supported —
/// a signature format with wildcards needs a real matching engine, and pretending
/// otherwise would be worse than being clear about the limit.</param>
public sealed record BytePattern(
    string Name,
    byte[] Bytes,
    SignalWeight Weight,
    string Description);

/// <summary>
/// A literal byte-pattern scanner.
///
/// This is deliberately not a YARA clone. It matches exact byte sequences and
/// nothing else, which covers the useful cases — embedded C2 strings, known shellcode
/// stubs, ransom-note templates, packer stubs — without pretending to implement a
/// rule language it does not have. When the real YARA engine is present the worker
/// runs that too; this exists so Sentinel has working signature detection out of the
/// box rather than an engine that is always "unavailable".
///
/// Matching is bucketed by first byte, so adding a few hundred patterns costs
/// roughly one comparison per input byte rather than one full scan per pattern.
/// </summary>
public sealed class PatternEngine
{
    /// <summary>Stop after this many distinct hits. A file that matches hundreds of
    /// patterns has told us everything it is going to; the rest is wasted work.</summary>
    public const int MaxMatches = 32;

    private readonly Dictionary<byte, List<BytePattern>> _byFirstByte = [];

    public PatternEngine(IEnumerable<BytePattern> patterns)
    {
        foreach (var pattern in patterns)
        {
            if (pattern.Bytes.Length == 0)
                continue;

            if (!_byFirstByte.TryGetValue(pattern.Bytes[0], out var bucket))
                _byFirstByte[pattern.Bytes[0]] = bucket = [];

            bucket.Add(pattern);
            PatternCount++;
        }
    }

    public int PatternCount { get; }

    public bool HasPatterns => PatternCount > 0;

    public IReadOnlyList<SecuritySignal> Scan(ReadOnlySpan<byte> data)
    {
        if (PatternCount == 0 || data.Length == 0)
            return [];

        var matched = new List<BytePattern>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        for (int i = 0; i < data.Length && matched.Count < MaxMatches; i++)
        {
            if (!_byFirstByte.TryGetValue(data[i], out var candidates))
                continue;

            foreach (var candidate in candidates)
            {
                if (candidate.Bytes.Length > data.Length - i)
                    continue;

                if (!data.Slice(i, candidate.Bytes.Length).SequenceEqual(candidate.Bytes))
                    continue;

                if (seen.Add(candidate.Name))
                    matched.Add(candidate);

                if (matched.Count >= MaxMatches)
                    break;
            }
        }

        return matched
            .Select(pattern => new SecuritySignal(
                SignalSource.StaticRules,
                pattern.Weight,
                "pat-" + pattern.Name,
                pattern.Description))
            .ToArray();
    }

    /// <summary>
    /// Parse a pattern file. One rule per line:
    /// <c>name | weight | pattern | description</c>
    ///
    /// The pattern is either <c>hex:4D5A9000</c> or <c>text:some literal string</c>.
    /// Blank lines and lines starting with '#' are ignored. A malformed line is
    /// skipped rather than aborting the load, so one bad rule cannot disarm the
    /// whole engine.
    /// </summary>
    public static IReadOnlyList<BytePattern> ParseRules(IEnumerable<string> lines, out IReadOnlyList<string> errors)
    {
        var patterns = new List<BytePattern>();
        var problems = new List<string>();
        int lineNumber = 0;

        foreach (var raw in lines)
        {
            lineNumber++;
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#')
                continue;

            var fields = line.Split('|', 4);
            if (fields.Length < 4)
            {
                problems.Add($"line {lineNumber}: expected 'name | weight | pattern | description'");
                continue;
            }

            var name = fields[0].Trim();
            if (name.Length == 0)
            {
                problems.Add($"line {lineNumber}: the rule has no name");
                continue;
            }

            if (!Enum.TryParse<SignalWeight>(fields[1].Trim(), ignoreCase: true, out var weight))
            {
                problems.Add($"line {lineNumber}: '{fields[1].Trim()}' is not a signal weight");
                continue;
            }

            // A literal pattern can never be decisive on its own: a byte sequence
            // appears in benign files too, and this engine has no rule language to
            // express the surrounding context that would justify certainty.
            if (weight == SignalWeight.Decisive)
                weight = SignalWeight.Strong;

            var bytes = ParsePattern(fields[2].Trim());
            if (bytes is null || bytes.Length < 4)
            {
                problems.Add($"line {lineNumber}: pattern is unreadable or shorter than 4 bytes");
                continue;
            }

            patterns.Add(new BytePattern(name, bytes, weight, fields[3].Trim()));
        }

        errors = problems;
        return patterns;
    }

    private static byte[]? ParsePattern(string pattern)
    {
        if (pattern.StartsWith("text:", StringComparison.OrdinalIgnoreCase))
            return Encoding.UTF8.GetBytes(pattern[5..]);

        if (!pattern.StartsWith("hex:", StringComparison.OrdinalIgnoreCase))
            return null;

        var hex = pattern[4..].Replace(" ", "").Replace("-", "");
        if (hex.Length == 0 || hex.Length % 2 != 0)
            return null;

        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            if (!byte.TryParse(hex.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out bytes[i]))
                return null;
        }

        return bytes;
    }
}
