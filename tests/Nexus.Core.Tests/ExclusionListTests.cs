using Nexus.Core.Security;
using Xunit;

namespace Nexus.Core.Tests;

public class ExclusionListTests
{
    private static ExclusionList For(params string[] patterns) =>
        new(patterns.Select(p => new Exclusion(p)));

    [Fact]
    public void An_empty_list_excludes_nothing()
    {
        Assert.False(new ExclusionList().IsExcluded(@"C:\anything\at\all.exe"));
    }

    [Fact]
    public void A_folder_excludes_everything_beneath_it()
    {
        var list = For(@"C:\repo\build");

        Assert.True(list.IsExcluded(@"C:\repo\build\out.exe"));
        Assert.True(list.IsExcluded(@"C:\repo\build\nested\deep\out.dll"));
        Assert.True(list.IsExcluded(@"C:\repo\build"));
    }

    /// <summary>Bounded by a separator, so a folder that merely starts with the same
    /// letters is not swept up with it.</summary>
    [Fact]
    public void A_similarly_named_folder_is_not_excluded()
    {
        var list = For(@"C:\Data");

        Assert.False(list.IsExcluded(@"C:\DataSecret\payload.exe"));
        Assert.False(list.IsExcluded(@"C:\Database\thing.exe"));
    }

    [Fact]
    public void A_trailing_separator_does_not_change_the_meaning()
    {
        Assert.True(For(@"C:\repo\build\").IsExcluded(@"C:\repo\build\out.exe"));
    }

    [Fact]
    public void Forward_slashes_are_treated_the_same_as_backslashes()
    {
        Assert.True(For("C:/repo/build").IsExcluded(@"C:\repo\build\out.exe"));
    }

    [Fact]
    public void Matching_ignores_case_like_the_filesystem()
    {
        Assert.True(For(@"C:\Repo\Build").IsExcluded(@"c:\repo\build\out.exe"));
    }

    [Fact]
    public void A_single_file_can_be_excluded()
    {
        var list = For(@"C:\tools\flagged.exe");

        Assert.True(list.IsExcluded(@"C:\tools\flagged.exe"));
        Assert.False(list.IsExcluded(@"C:\tools\other.exe"));
    }

    [Fact]
    public void An_extension_excludes_that_file_type_anywhere()
    {
        var list = For(".iso");

        Assert.True(list.IsExcluded(@"C:\downloads\ubuntu.iso"));
        Assert.True(list.IsExcluded(@"D:\elsewhere\other.ISO"));
        Assert.False(list.IsExcluded(@"C:\downloads\setup.exe"));
    }

    [Theory]
    [InlineData(".iso", true)]
    [InlineData(@"C:\folder", false)]
    [InlineData("C:/folder", false)]
    public void Extensions_are_distinguished_from_paths(string pattern, bool isExtension)
    {
        Assert.Equal(isExtension, new Exclusion(pattern).IsExtension);
    }

    [Fact]
    public void Blank_patterns_are_discarded_rather_than_matching_everything()
    {
        var list = new ExclusionList([new Exclusion("   "), new Exclusion("")]);

        Assert.Equal(0, list.Count);
        Assert.False(list.IsExcluded(@"C:\anything.exe"));
    }

    // ---- Auditing the user's own holes ----

    /// <summary>Nexus flags Defender's overly broad exclusions; applying a gentler
    /// standard to its own would be incoherent.</summary>
    [Theory]
    [InlineData(@"C:\")]
    [InlineData(@"C:\Users")]
    [InlineData("%USERPROFILE%")]
    public void An_exclusion_broad_enough_to_be_a_hole_is_reported(string pattern)
    {
        Assert.Single(For(pattern).Audit(), s => s.Code == "exclusion-too-broad");
    }

    [Fact]
    public void Excluding_every_executable_is_reported()
    {
        Assert.Single(For(".exe").Audit(), s => s.Code == "exclusion-executable-type");
    }

    [Fact]
    public void An_ordinary_exclusion_is_not_reported()
    {
        Assert.Empty(For(@"C:\repo\build", ".iso", @"D:\Games").Audit());
    }
}
