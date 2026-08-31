using System.IO.Compression;
using System.Text;
using Nexus.Core.Security;
using Nexus.Core.Security.StaticAnalysis;
using Xunit;

namespace Nexus.Core.Tests;

/// <summary>
/// The archive limits are security controls against an attacker-controlled file, so
/// they get tested against real archives — including ones built specifically to be
/// hostile.
/// </summary>
public class ArchiveInspectorTests
{
    /// <summary>Builds a real ZIP in memory.</summary>
    private static MemoryStream BuildZip(params (string Name, byte[] Content)[] entries)
    {
        var stream = new MemoryStream();

        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, content) in entries)
            {
                var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
                using var entryStream = entry.Open();
                entryStream.Write(content);
            }
        }

        stream.Position = 0;
        return stream;
    }

    private static byte[] Text(string value) => Encoding.UTF8.GetBytes(value);

    /// <summary>Highly compressible content: expands enormously from a tiny stored size.</summary>
    private static byte[] Compressible(int size) => new byte[size];

    /// <summary>An analyser that reports one signal per entry, so requalification is visible.</summary>
    private static IReadOnlyList<SecuritySignal> EchoAnalyser(byte[] content, string entryName) =>
    [
        new SecuritySignal(SignalSource.StaticRules, SignalWeight.Moderate, "echo",
            $"Saw {content.Length} bytes."),
    ];

    private static IReadOnlyList<SecuritySignal> NullAnalyser(byte[] content, string entryName) => [];

    private static string[] Codes(MemoryStream zip, ArchiveInspector.EntryAnalyser? analyser = null) =>
        ArchiveInspector.Inspect(zip, analyser ?? NullAnalyser).Select(s => s.Code).ToArray();

    // ---- Detection of the container ----

    [Fact]
    public void Zip_magic_bytes_are_recognised()
    {
        using var zip = BuildZip(("a.txt", Text("hello")));
        Assert.True(ArchiveInspector.LooksLikeZip(zip.ToArray()));
    }

    [Theory]
    [InlineData(new byte[] { 0x4D, 0x5A, 0x90, 0x00 })] // a PE
    [InlineData(new byte[] { 0x00 })]
    [InlineData(new byte[0])]
    public void Non_zip_input_is_not_treated_as_an_archive(byte[] bytes)
    {
        Assert.False(ArchiveInspector.LooksLikeZip(bytes));
    }

    [Fact]
    public void A_corrupt_archive_is_reported_rather_than_throwing()
    {
        using var broken = new MemoryStream([0x50, 0x4B, 0x03, 0x04, 0xFF, 0xFF, 0xFF, 0xFF]);
        Assert.Contains("archive-corrupt", Codes(broken));
    }

    // ---- Contents ----

    [Fact]
    public void An_ordinary_archive_of_documents_reports_nothing_alarming()
    {
        using var zip = BuildZip(("notes.txt", Text("hello")), ("data.csv", Text("a,b,c")));
        Assert.Empty(Codes(zip));
    }

    [Fact]
    public void Executables_inside_an_archive_are_listed()
    {
        using var zip = BuildZip(("setup.exe", Text("not really a pe")), ("readme.txt", Text("hi")));
        Assert.Contains("archive-contains-executable", Codes(zip));
    }

    [Fact]
    public void Findings_from_an_entry_name_the_entry_they_came_from()
    {
        using var zip = BuildZip(("inner/payload.bin", Text("some content here")));

        var signals = ArchiveInspector.Inspect(zip, EchoAnalyser);
        var signal = Assert.Single(signals, s => s.Code == "archive-echo");

        Assert.Contains("inner/payload.bin", signal.Explanation, StringComparison.Ordinal);
        Assert.StartsWith("Inside the archive,", signal.Explanation, StringComparison.Ordinal);
    }

    // ---- Path traversal ----

    [Theory]
    [InlineData("../../Windows/System32/evil.dll", true)]
    [InlineData(@"..\..\Windows\System32\evil.dll", true)]
    [InlineData("/etc/passwd", true)]
    [InlineData(@"C:\Windows\evil.dll", true)]
    [InlineData("folder/../../escape.txt", true)]
    [InlineData("..", true)]
    [InlineData("folder/sub/file.txt", false)]
    [InlineData("file.txt", false)]
    [InlineData("my..file.txt", false)]
    [InlineData("..hidden/file.txt", false)]
    public void Traversal_paths_are_recognised_without_false_positives(string entryName, bool expected)
    {
        Assert.Equal(expected, ArchiveInspector.HasTraversalPath(entryName));
    }

    [Fact]
    public void A_traversal_entry_is_reported_and_not_analysed()
    {
        using var zip = BuildZip(("../../escape.txt", Text("payload")));

        var signals = ArchiveInspector.Inspect(zip, EchoAnalyser);

        Assert.Contains(signals, s => s.Code == "archive-path-traversal");
        Assert.DoesNotContain(signals, s => s.Code == "archive-echo");
    }

    // ---- Zip bombs ----

    [Fact]
    public void A_hugely_compressible_entry_is_reported_and_not_expanded()
    {
        // 8 MB of zeroes stores in a few KB — well past the ratio limit.
        using var zip = BuildZip(("bomb.bin", Compressible(8 * 1024 * 1024)));

        var signals = ArchiveInspector.Inspect(zip, EchoAnalyser);

        Assert.Contains(signals, s => s.Code == "archive-zip-bomb");
        Assert.DoesNotContain(signals, s => s.Code == "archive-echo");
    }

    [Fact]
    public void Normally_compressible_content_is_not_called_a_bomb()
    {
        var prose = Text(string.Concat(Enumerable.Repeat(
            "The quick brown fox jumps over the lazy dog. ", 200)));

        using var zip = BuildZip(("story.txt", prose));

        Assert.DoesNotContain("archive-zip-bomb", Codes(zip));
    }

    // ---- Nested archives ----

    /// <summary>
    /// Nested archives used to be reported and skipped. They are now opened, because
    /// putting the payload inside a second archive is the oldest way past a scanner
    /// that stops at the container, and reporting "there is an archive in here" left
    /// the obvious case unexamined.
    ///
    /// Opening is delegated to the caller's analyser — Core knows the limits, the
    /// scanner worker knows how to open 7z and RAR — so from here the entry is handed
    /// over like any other. What Core still guarantees is the budget and the depth cap.
    /// </summary>
    [Theory]
    [InlineData("inner.zip")]
    [InlineData("inner.RAR")]
    [InlineData("payload.7z")]
    public void A_nested_archive_is_handed_to_the_analyser_to_open(string name)
    {
        using var zip = BuildZip((name, Text("PK not really")));

        var signals = ArchiveInspector.Inspect(zip, EchoAnalyser);

        Assert.Contains(signals, s => s.Code == "archive-echo");
        Assert.DoesNotContain(signals, s => s.Code == "archive-nested-unopened");
    }

    /// <summary>
    /// ...but only while the budget allows. Past the depth cap it goes back to being
    /// reported and skipped, and the wording must not imply it was cleared.
    /// </summary>
    [Fact]
    public void Past_the_depth_cap_a_nested_archive_is_reported_and_not_opened()
    {
        using var zip = BuildZip(("inner.zip", Text("PK not really")));

        var budget = new ArchiveInspector.ArchiveBudget { Depth = ArchiveInspector.MaxNestingDepth };
        var signals = ArchiveInspector.Inspect(zip, EchoAnalyser, budget);

        Assert.Contains(signals, s => s.Code == "archive-nested-unopened");
        Assert.DoesNotContain(signals, s => s.Code == "archive-echo");
    }

    // ---- Limits ----

    [Fact]
    public void An_archive_with_too_many_entries_stops_and_says_so()
    {
        var entries = Enumerable.Range(0, ArchiveInspector.MaxEntries + 50)
            .Select(i => ($"file{i}.txt", Text($"content {i}")))
            .ToArray();

        using var zip = BuildZip(entries);
        var signals = ArchiveInspector.Inspect(zip, EchoAnalyser);

        Assert.Contains(signals, s => s.Code == "archive-not-fully-examined");
        Assert.True(
            signals.Count(s => s.Code == "archive-echo") <= ArchiveInspector.MaxEntries,
            "more entries were analysed than the limit allows");
    }

    /// <summary>A partial look must never read as a clean bill of health.</summary>
    [Fact]
    public void Stopping_early_is_stated_rather_than_implied_to_be_clean()
    {
        var entries = Enumerable.Range(0, ArchiveInspector.MaxEntries + 5)
            .Select(i => ($"f{i}.txt", Text("x")))
            .ToArray();

        using var zip = BuildZip(entries);
        var signal = Assert.Single(
            ArchiveInspector.Inspect(zip, NullAnalyser),
            s => s.Code == "archive-not-fully-examined");

        Assert.Contains("has not been cleared", signal.Explanation, StringComparison.Ordinal);
    }

    [Fact]
    public void Empty_entries_are_skipped()
    {
        using var zip = BuildZip(("empty.txt", []), ("real.txt", Text("content")));

        var signals = ArchiveInspector.Inspect(zip, EchoAnalyser);

        Assert.Single(signals, s => s.Code == "archive-echo");
    }

    [Fact]
    public void A_folder_entry_does_not_produce_a_finding()
    {
        using var zip = BuildZip(("folder/", []));
        Assert.Empty(Codes(zip, EchoAnalyser));
    }

    // ---- Format detection ----
    //
    // By magic bytes, never by extension. A file named .txt is still a 7z archive if
    // it starts like one, and malware delivered in archives depends on the extension
    // being believed.

    [Fact]
    public void A_zip_is_recognised()
    {
        Assert.Equal(ArchiveInspector.ArchiveFormat.Zip,
            ArchiveInspector.DetectFormat([0x50, 0x4B, 0x03, 0x04, 0, 0, 0, 0]));
    }

    [Fact]
    public void A_seven_zip_archive_is_recognised()
    {
        Assert.Equal(ArchiveInspector.ArchiveFormat.SevenZip,
            ArchiveInspector.DetectFormat([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 0]));
    }

    [Fact]
    public void A_rar_archive_is_recognised()
    {
        // RAR4 and RAR5 differ only after the sixth byte.
        Assert.Equal(ArchiveInspector.ArchiveFormat.Rar,
            ArchiveInspector.DetectFormat([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]));

        Assert.Equal(ArchiveInspector.ArchiveFormat.Rar,
            ArchiveInspector.DetectFormat([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]));
    }

    [Theory]
    [InlineData(new byte[] { 0x1F, 0x8B, 0x08 }, ArchiveInspector.ArchiveFormat.GZip)]
    [InlineData(new byte[] { 0x42, 0x5A, 0x68, 0x39 }, ArchiveInspector.ArchiveFormat.BZip2)]
    [InlineData(new byte[] { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 }, ArchiveInspector.ArchiveFormat.Xz)]
    public void The_single_file_compressors_are_recognised(byte[] header, ArchiveInspector.ArchiveFormat expected)
    {
        Assert.Equal(expected, ArchiveInspector.DetectFormat(header));
    }

    /// <summary>TAR has no leading magic at all; the marker sits 257 bytes in.</summary>
    [Fact]
    public void A_tar_is_recognised_by_its_offset_marker()
    {
        var tar = new byte[512];
        "ustar"u8.CopyTo(tar.AsSpan(257));

        Assert.Equal(ArchiveInspector.ArchiveFormat.Tar, ArchiveInspector.DetectFormat(tar));
    }

    [Fact]
    public void Ordinary_files_are_not_mistaken_for_archives()
    {
        Assert.Equal(ArchiveInspector.ArchiveFormat.None, ArchiveInspector.DetectFormat([]));
        Assert.Equal(ArchiveInspector.ArchiveFormat.None, ArchiveInspector.DetectFormat("hello there"u8));
        Assert.Equal(ArchiveInspector.ArchiveFormat.None, ArchiveInspector.DetectFormat(new byte[4096]));

        // An MZ executable is not an archive, however much of one it embeds.
        Assert.Equal(ArchiveInspector.ArchiveFormat.None, ArchiveInspector.DetectFormat([0x4D, 0x5A, 0x90, 0x00]));
    }

    [Fact]
    public void Detection_never_reads_past_a_short_buffer()
    {
        // Every prefix of every magic number must be refused without throwing.
        byte[][] headers =
        [
            [0x50, 0x4B, 0x03, 0x04],
            [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
            [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
            [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],
        ];

        foreach (var header in headers)
            for (int length = 0; length <= header.Length; length++)
                ArchiveInspector.DetectFormat(header.AsSpan(0, length));
    }

    // ---- Nesting ----

    /// <summary>
    /// One budget for the whole file, shared by every level. A fresh allowance per
    /// level would let nested archives multiply the expansion ceiling, turning the
    /// zip-bomb defence into a zip-bomb amplifier.
    /// </summary>
    [Fact]
    public void A_nested_archive_spends_the_same_budget_as_its_parent()
    {
        var budget = new ArchiveInspector.ArchiveBudget();

        ArchiveInspector.InspectEntries(
            [Entry("a.txt", 1000, 500), Entry("b.txt", 1000, 500)],
            static (_, _) => [],
            budget);

        Assert.Equal(2, budget.EntriesExamined);

        // A second archive, handed the same budget, continues from where it left off.
        ArchiveInspector.InspectEntries([Entry("c.txt", 1000, 500)], static (_, _) => [], budget);

        Assert.Equal(3, budget.EntriesExamined);
    }

    [Fact]
    public void Descent_stops_at_the_depth_limit()
    {
        var budget = new ArchiveInspector.ArchiveBudget();

        Assert.True(budget.CanDescend);

        budget.Depth = ArchiveInspector.MaxNestingDepth;
        Assert.False(budget.CanDescend);
    }

    [Fact]
    public void An_exhausted_budget_stops_descent_even_at_depth_zero()
    {
        var budget = new ArchiveInspector.ArchiveBudget
        {
            EntriesExamined = ArchiveInspector.MaxEntries,
        };

        Assert.True(budget.Exhausted);
        Assert.False(budget.CanDescend);
    }

    /// <summary>An archive too deep to open must be reported, never silently dropped:
    /// unexamined is not the same as clean.</summary>
    [Fact]
    public void An_unopened_nested_archive_is_reported()
    {
        var budget = new ArchiveInspector.ArchiveBudget { Depth = ArchiveInspector.MaxNestingDepth };

        var signals = ArchiveInspector.InspectEntries(
            [Entry("payload.zip", 5000, 2000)], static (_, _) => [], budget);

        var signal = Assert.Single(signals, s => s.Code == "archive-nested-unopened");
        Assert.Contains("not been cleared", signal.Explanation);
    }

    /// <summary>
    /// Codes are what suppression and tests match on, so the prefix is applied once
    /// however deep the nesting goes -- never "archive-archive-script-...".
    /// </summary>
    [Fact]
    public void The_archive_prefix_is_not_applied_twice()
    {
        var signals = ArchiveInspector.InspectEntries(
            [Entry("inner", 100, 50)],
            static (_, _) =>
            [
                new SecuritySignal(SignalSource.StaticRules, SignalWeight.Weak,
                    "archive-script-download-and-run", "Already came from an archive."),
            ]);

        Assert.Equal("archive-script-download-and-run", Assert.Single(signals).Code);
    }

    /// <summary>
    /// Every entry seen costs budget, not only the ones whose contents were read.
    /// Counting after the skips let an archive of a million empty or undecodable
    /// entries walk its whole directory without the cap ever tripping — each one
    /// still costing a traversal check and a ratio check.
    /// </summary>
    [Fact]
    public void Entries_that_are_skipped_still_cost_budget()
    {
        var budget = new ArchiveInspector.ArchiveBudget();

        // All empty, so every one hits the zero-length skip.
        var empties = Enumerable.Range(0, 50).Select(i => Entry($"empty{i}.txt", 0, 0));

        ArchiveInspector.InspectEntries(empties, static (_, _) => [], budget);

        Assert.Equal(50, budget.EntriesExamined);
    }

    [Fact]
    public void An_archive_of_empty_entries_still_stops_at_the_cap()
    {
        var budget = new ArchiveInspector.ArchiveBudget();

        var many = Enumerable.Range(0, ArchiveInspector.MaxEntries * 3)
            .Select(i => Entry($"empty{i}.txt", 0, 0));

        var signals = ArchiveInspector.InspectEntries(many, static (_, _) => [], budget);

        Assert.Equal(ArchiveInspector.MaxEntries, budget.EntriesExamined);
        Assert.Contains(signals, s => s.Code == "archive-not-fully-examined");
    }

    /// <summary>
    /// A compressed size of zero means the format did not report one. 7-Zip's solid
    /// compression never does, and briefly treating that as an infinite ratio flagged
    /// every 7z archive as a bomb -- and because a flagged entry is skipped, it hid the
    /// dropper inside one. An unknown ratio stays unknown; the real defence against
    /// expansion is the byte caps, enforced on bytes actually read.
    /// </summary>
    [Fact]
    public void An_unreported_compressed_size_is_not_treated_as_a_bomb()
    {
        var signals = ArchiveInspector.InspectEntries(
            [Entry("solid.bin", 100_000_000, 0)], static (_, _) => []);

        Assert.DoesNotContain(signals, s => s.Code == "archive-zip-bomb");
    }

    [Fact]
    public void A_genuine_expansion_ratio_is_still_a_bomb()
    {
        var signals = ArchiveInspector.InspectEntries(
            [Entry("bomb.bin", 100_000_000, 1000)], static (_, _) => []);

        Assert.Contains(signals, s => s.Code == "archive-zip-bomb");
    }

    [Fact]
    public void An_ordinary_ratio_is_still_not_a_bomb()
    {
        var signals = ArchiveInspector.InspectEntries(
            [Entry("normal.txt", 1000, 400)], static (_, _) => []);

        Assert.DoesNotContain(signals, s => s.Code == "archive-zip-bomb");
    }

    // ---- The shared limits apply to every format ----

    private static ArchiveInspector.ArchiveEntryView Entry(
        string name, long uncompressed, long compressed, byte[]? content = null) =>
        new(name, uncompressed, compressed, _ => content ?? new byte[Math.Min(uncompressed, 64)]);

    [Fact]
    public void A_traversal_entry_is_caught_whatever_produced_it()
    {
        var signals = ArchiveInspector.InspectEntries(
            [Entry(@"..\..\Windows\System32\evil.dll", 100, 50)],
            static (_, _) => []);

        Assert.Contains(signals, s => s.Code == "archive-path-traversal");
    }

    [Fact]
    public void The_expansion_ratio_is_checked_whatever_produced_it()
    {
        var signals = ArchiveInspector.InspectEntries(
            [Entry("bomb.bin", 1_000_000_000, 1_000)],
            static (_, _) => []);

        Assert.Contains(signals, s => s.Code == "archive-zip-bomb");
    }

    /// <summary>
    /// The entry cap must hold for a forward-only reader too, and a partial look must
    /// never read as a clean bill of health.
    /// </summary>
    [Fact]
    public void Stopping_early_is_reported_rather_than_hidden()
    {
        var many = Enumerable.Range(0, ArchiveInspector.MaxEntries + 50)
            .Select(i => Entry($"file{i}.txt", 64, 32));

        var signals = ArchiveInspector.InspectEntries(many, static (_, _) => []);

        Assert.Contains(signals, s => s.Code == "archive-not-fully-examined");
    }

    [Fact]
    public void An_entry_that_will_not_decompress_does_not_lose_the_rest()
    {
        var entries = new[]
        {
            new ArchiveInspector.ArchiveEntryView("locked.bin", 100, 50, _ => []),
            Entry("readable.txt", 100, 50, "content"u8.ToArray()),
        };

        var seen = new List<string>();
        ArchiveInspector.InspectEntries(entries, (_, name) => { seen.Add(name); return []; });

        Assert.Equal(["readable.txt"], seen);
    }
}
