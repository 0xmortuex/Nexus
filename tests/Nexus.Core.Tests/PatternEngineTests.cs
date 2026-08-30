using Nexus.Core.Security;
using Nexus.Core.Security.StaticAnalysis;
using Xunit;

namespace Nexus.Core.Tests;

public class PatternEngineTests
{
    private static readonly string[] SampleRules =
    [
        "# a comment line",
        "",
        "ransom-note | Strong | text:All your files have been encrypted | Contains ransom note text.",
        "mz-header   | Weak   | hex:4D5A9000 | Starts with a DOS executable header.",
    ];

    private static PatternEngine Build(params string[] lines)
    {
        var patterns = PatternEngine.ParseRules(lines, out _);
        return new PatternEngine(patterns);
    }

    [Fact]
    public void Comments_and_blank_lines_are_skipped()
    {
        var patterns = PatternEngine.ParseRules(SampleRules, out var errors);

        Assert.Equal(2, patterns.Count);
        Assert.Empty(errors);
    }

    [Fact]
    public void A_text_pattern_matches()
    {
        var engine = Build(SampleRules);
        var data = "readme: All your files have been encrypted, pay up"u8;

        var signal = Assert.Single(engine.Scan(data));
        Assert.Equal("pat-ransom-note", signal.Code);
        Assert.Equal(SignalWeight.Strong, signal.Weight);
    }

    [Fact]
    public void A_hex_pattern_matches()
    {
        var engine = Build(SampleRules);
        var data = new byte[] { 0x00, 0x4D, 0x5A, 0x90, 0x00, 0xFF };

        Assert.Single(engine.Scan(data), s => s.Code == "pat-mz-header");
    }

    [Fact]
    public void A_clean_file_matches_nothing()
    {
        Assert.Empty(Build(SampleRules).Scan("nothing interesting in here at all"u8));
    }

    [Fact]
    public void Each_pattern_reports_at_most_once()
    {
        var engine = Build(SampleRules);
        var repeated = System.Text.Encoding.UTF8.GetBytes(
            string.Concat(Enumerable.Repeat("All your files have been encrypted ", 50)));

        Assert.Single(engine.Scan(repeated));
    }

    [Fact]
    public void Literal_patterns_are_never_decisive()
    {
        // A byte sequence appears in benign files too; this engine has no way to
        // express the context that would justify certainty, so Decisive is demoted.
        var patterns = PatternEngine.ParseRules(
            ["x | Decisive | text:some literal bytes | test"], out _);

        Assert.Equal(SignalWeight.Strong, Assert.Single(patterns).Weight);
    }

    [Theory]
    [InlineData("missing fields")]
    [InlineData("name | NotAWeight | text:abcd | desc")]
    [InlineData("name | Weak | hex:ZZZZ | desc")]
    [InlineData("name | Weak | hex:4D5 | desc")]
    [InlineData("name | Weak | text:ab | desc")]
    [InlineData(" | Weak | text:abcd | desc")]
    public void Malformed_rules_are_skipped_with_an_error(string line)
    {
        var patterns = PatternEngine.ParseRules([line], out var errors);

        Assert.Empty(patterns);
        Assert.Single(errors);
    }

    [Fact]
    public void One_bad_rule_does_not_disarm_the_rest()
    {
        var patterns = PatternEngine.ParseRules(
            ["broken line", "good | Weak | text:abcdef | fine"], out var errors);

        Assert.Single(patterns);
        Assert.Single(errors);
    }

    [Fact]
    public void Matching_is_bounded_on_a_pathological_file()
    {
        var rules = Enumerable.Range(0, 200)
            .Select(i => $"rule{i} | Weak | text:pattern{i:D4}xx | test")
            .ToArray();
        var engine = Build(rules);

        var data = System.Text.Encoding.UTF8.GetBytes(
            string.Concat(Enumerable.Range(0, 200).Select(i => $"pattern{i:D4}xx")));

        Assert.True(engine.Scan(data).Count <= PatternEngine.MaxMatches);
    }

    [Fact]
    public void An_empty_ruleset_is_inert()
    {
        var engine = new PatternEngine([]);

        Assert.False(engine.HasPatterns);
        Assert.Empty(engine.Scan("anything at all"u8));
    }
}
