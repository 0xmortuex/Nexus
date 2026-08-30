using Nexus.Core.Security;
using Xunit;

namespace Nexus.Core.Tests;

public class ScanTargetingTests
{
    // ---- What is worth scanning ----

    [Theory]
    [InlineData(@"C:\a\setup.exe", true)]
    [InlineData(@"C:\a\lib.DLL", true)]
    [InlineData(@"C:\a\script.ps1", true)]
    [InlineData(@"C:\a\link.lnk", true)]
    [InlineData(@"C:\a\payload", true)]          // extensionless: a renamed payload is real
    [InlineData(@"C:\a\holiday.jpg", false)]
    [InlineData(@"C:\a\report.docx", false)]
    [InlineData(@"C:\a\video.mkv", false)]
    public void Only_file_types_an_engine_can_judge_are_scanned(string path, bool expected)
    {
        Assert.Equal(expected, ScanTargeting.IsWorthScanning(path));
    }

    // ---- Noise directories ----

    [Theory]
    [InlineData(@"C:\repo\.git\objects\ab\cdef", true)]
    [InlineData(@"C:\repo\node_modules\pkg\index.js", true)]
    [InlineData(@"C:\repo\src\obj\Debug\thing.dll", true)]
    [InlineData(@"C:\Windows\WinSxS\amd64_something\file.dll", true)]
    [InlineData(@"C:/repo/.git/objects/ab/cdef", true)]   // forward slashes normalise
    [InlineData(@"C:\repo\src\Program.cs", false)]
    [InlineData(@"C:\Users\fadi\Downloads\setup.exe", false)]
    public void Machine_generated_trees_are_skipped(string path, bool expected)
    {
        Assert.Equal(expected, ScanTargeting.IsNoiseDirectory(path));
    }

    /// <summary>Each entry is separator-bounded, so a directory that merely starts
    /// with the same letters is not swept up with it.</summary>
    [Theory]
    [InlineData(@"C:\repo\objects\file.exe")]
    [InlineData(@"C:\repo\binaries\file.exe")]
    [InlineData(@"C:\repo\.gitignore-backup\file.exe")]
    [InlineData(@"C:\my.git.stuff\file.exe")]
    public void Similarly_named_directories_are_not_skipped(string path)
    {
        Assert.False(ScanTargeting.IsNoiseDirectory(path));
    }

    // ---- Command-line parsing ----

    private static Func<string, bool> Filesystem(params string[] existing) =>
        candidate => existing.Contains(candidate, StringComparer.OrdinalIgnoreCase);

    [Fact]
    public void A_quoted_path_is_read_exactly()
    {
        Assert.Equal(
            @"C:\Program Files\App\app.exe",
            ScanTargeting.ExtractImagePath(@"""C:\Program Files\App\app.exe"" --silent", Filesystem()));
    }

    [Fact]
    public void A_quoted_path_needs_no_filesystem_probe()
    {
        // Nothing exists, and it still parses — quoting removes the ambiguity.
        Assert.NotNull(ScanTargeting.ExtractImagePath(@"""C:\gone\app.exe""", _ => false));
    }

    [Fact]
    public void An_unquoted_path_without_spaces_resolves()
    {
        Assert.Equal(
            @"C:\Tools\app.exe",
            ScanTargeting.ExtractImagePath(@"C:\Tools\app.exe -x", Filesystem(@"C:\Tools\app.exe")));
    }

    [Fact]
    public void An_unquoted_path_with_spaces_resolves_to_the_real_executable()
    {
        Assert.Equal(
            @"C:\Program Files\App\app.exe",
            ScanTargeting.ExtractImagePath(
                @"C:\Program Files\App\app.exe --flag",
                Filesystem(@"C:\Program Files\App\app.exe")));
    }

    /// <summary>
    /// The unquoted service path hijack. The loader probes shortest prefix first, so
    /// a planted C:\Program.exe pre-empts the intended target — and the audit has to
    /// report the binary that will actually run, not the one the entry meant.
    /// </summary>
    [Fact]
    public void A_planted_shorter_prefix_wins_the_way_the_loader_resolves_it()
    {
        var resolved = ScanTargeting.ExtractImagePath(
            @"C:\Program Files\App\app.exe --flag",
            Filesystem(@"C:\Program", @"C:\Program Files\App\app.exe"));

        Assert.Equal(@"C:\Program", resolved);
    }

    [Fact]
    public void A_command_pointing_nowhere_returns_null()
    {
        Assert.Null(ScanTargeting.ExtractImagePath(@"C:\gone\app.exe -x", Filesystem()));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\"")]
    [InlineData("\"\"")]
    public void Malformed_command_lines_return_null_rather_than_throwing(string command)
    {
        Assert.Null(ScanTargeting.ExtractImagePath(command, Filesystem()));
    }

    // ---- Defender exclusion breadth ----

    [Theory]
    [InlineData(@"C:\", true)]
    [InlineData(@"C:", true)]
    [InlineData(@"C:\Users", true)]
    [InlineData(@"c:\users\", true)]
    [InlineData(@"C:\Users\*", true)]
    [InlineData(@"%USERPROFILE%", true)]
    [InlineData(@"%TEMP%", true)]
    [InlineData(@"C:\Users\fadi\Projects\build", false)]
    [InlineData(@"C:\Program Files\Vendor\App", false)]
    [InlineData("", false)]
    public void Exclusions_broad_enough_to_be_holes_are_recognised(string path, bool expected)
    {
        Assert.Equal(expected, ScanTargeting.IsOverlyBroadExclusion(path));
    }
}
