using Nexus.Core.Security;
using Xunit;

namespace Nexus.Core.Tests;

public class HashListFileTests
{
    private const string HashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string HashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    [Fact]
    public void A_plain_list_parses()
    {
        var hashes = HashListFile.Parse([HashA, HashB]);

        Assert.Equal(2, hashes.Count);
        Assert.Contains(HashA, hashes);
    }

    [Fact]
    public void Comments_and_blank_lines_are_ignored()
    {
        var hashes = HashListFile.Parse(["# a comment", "", "   ", HashA]);
        Assert.Single(hashes);
    }

    [Theory]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,notepad.exe")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa notepad.exe")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\tnotepad.exe")]
    public void Exports_with_a_trailing_name_are_accepted(string line)
    {
        Assert.True(HashListFile.TryParseLine(line, out var hash));
        Assert.Equal(HashA, hash);
    }

    [Fact]
    public void Hashes_are_normalised_to_lowercase()
    {
        Assert.True(HashListFile.TryParseLine(HashA.ToUpperInvariant(), out var hash));
        Assert.Equal(HashA, hash);
    }

    [Fact]
    public void Lookup_is_case_insensitive()
    {
        var hashes = HashListFile.Parse([HashA.ToUpperInvariant()]);
        Assert.Contains(HashA, hashes);
    }

    [Theory]
    [InlineData("not a hash")]
    [InlineData("aaaa")]                                                              // too short
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")] // too long
    [InlineData("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")]   // not hex
    public void Malformed_entries_are_skipped(string line)
    {
        Assert.False(HashListFile.TryParseLine(line, out _));
    }

    /// <summary>One bad line must never disarm an entire reputation list.</summary>
    [Fact]
    public void One_bad_line_does_not_lose_the_good_ones()
    {
        var hashes = HashListFile.Parse([HashA, "garbage", HashB]);
        Assert.Equal(2, hashes.Count);
    }

    [Fact]
    public void Duplicates_collapse()
    {
        Assert.Single(HashListFile.Parse([HashA, HashA, HashA.ToUpperInvariant()]));
    }

    // ---- Writing ----

    [Fact]
    public void A_written_list_round_trips()
    {
        var text = HashListFile.Write([HashB, HashA], "test provenance", DateTimeOffset.UnixEpoch);
        var hashes = HashListFile.Parse(text.Split('\n'));

        Assert.Equal(2, hashes.Count);
        Assert.Contains(HashA, hashes);
        Assert.Contains(HashB, hashes);
    }

    /// <summary>A known-good list silently exonerates everything in it, so it has to
    /// say where it came from.</summary>
    [Fact]
    public void A_written_list_records_its_provenance_and_date()
    {
        var text = HashListFile.Write([HashA], "built from C:\\Windows\\System32", DateTimeOffset.UnixEpoch);

        Assert.Contains("built from C:\\Windows\\System32", text, StringComparison.Ordinal);
        Assert.Contains("1970", text, StringComparison.Ordinal);
        Assert.StartsWith("#", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Writing_skips_anything_that_is_not_a_hash()
    {
        var text = HashListFile.Write([HashA, "nonsense", ""], "test", DateTimeOffset.UnixEpoch);
        Assert.Single(HashListFile.Parse(text.Split('\n')));
    }

    [Fact]
    public void Written_hashes_are_sorted_so_diffs_between_baselines_are_readable()
    {
        var text = HashListFile.Write([HashB, HashA], "test", DateTimeOffset.UnixEpoch);
        var lines = text.Split('\n').Where(l => HashListFile.TryParseLine(l, out _)).ToArray();

        Assert.Equal([HashA, HashB], lines.Select(l => l.Trim()));
    }

    [Fact]
    public void An_empty_list_still_writes_a_readable_header()
    {
        var text = HashListFile.Write([], "nothing found", DateTimeOffset.UnixEpoch);

        Assert.Empty(HashListFile.Parse(text.Split('\n')));
        Assert.Contains("nothing found", text, StringComparison.Ordinal);
    }
}
