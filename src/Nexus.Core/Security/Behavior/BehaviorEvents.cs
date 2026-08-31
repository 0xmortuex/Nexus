namespace Nexus.Core.Security.Behavior;

/// <summary>
/// A process launch, as reconstructed from ETW. Everything is a plain string so this
/// layer stays free of Windows types and the tests run on any OS.
/// </summary>
public sealed record ProcessStartEvent
{
    public required int Pid { get; init; }
    public int ParentPid { get; init; }

    /// <summary>Full path to the image, e.g. C:\Windows\System32\cmd.exe.</summary>
    public required string ImagePath { get; init; }

    public string CommandLine { get; init; } = "";

    /// <summary>Full path to the parent's image, when it was still resolvable.</summary>
    public string ParentImagePath { get; init; } = "";

    public required DateTimeOffset At { get; init; }

    /// <summary>
    /// The image's file name when the source knows it without knowing the path.
    ///
    /// ETW is exactly that case: its process events carry the short image name and no
    /// directory at all. Without somewhere to put the name, an ETW event would have to
    /// smuggle it through <see cref="ImagePath"/>, and then every path-based rule would
    /// read "conhost.exe" as a path and conclude the file is not in System32 -- which
    /// is what happened.
    /// </summary>
    public string? ImageFileName { get; init; }

    public string ImageName =>
        ImageFileName is { Length: > 0 } name ? name : PathHelpers.FileName(ImagePath);
    public string ParentImageName => PathHelpers.FileName(ParentImagePath);
}

/// <summary>An outbound connection attributed to a process.</summary>
public sealed record NetworkEvent
{
    public required int Pid { get; init; }
    public required string ImagePath { get; init; }
    public required string RemoteAddress { get; init; }
    public int RemotePort { get; init; }
    public required DateTimeOffset At { get; init; }

    public string ImageName => PathHelpers.FileName(ImagePath);
}

/// <summary>
/// Path handling that does not depend on the host OS's separator, because Core is
/// built and tested on Linux as well as Windows (see README).
/// </summary>
public static class PathHelpers
{
    private const char Separator = '\u005C'; // backslash

    public static string Normalize(string path) =>
        path.Replace('/', Separator).Trim();

    public static string FileName(string path)
    {
        var normalized = Normalize(path);
        int slash = normalized.LastIndexOf(Separator);
        return slash >= 0 ? normalized[(slash + 1)..] : normalized;
    }

    public static string DirectoryOf(string path)
    {
        var normalized = Normalize(path);
        int slash = normalized.LastIndexOf(Separator);
        return slash >= 0 ? normalized[..slash] : "";
    }

    /// <summary>True when <paramref name="path"/> sits under <paramref name="directory"/>.</summary>
    /// <summary>
    /// True when this is an actual path rather than a bare file name.
    ///
    /// The distinction matters because not every event source supplies a path. ETW
    /// carries the image name alone, and a rule that asks "is this under System32?"
    /// about the string "conhost.exe" gets "no" and reaches exactly the wrong
    /// conclusion. Absence of a path is not evidence about where the file lives.
    /// </summary>
    public static bool IsRooted(string path)
    {
        var normalized = Normalize(path);

        if (normalized.Length == 0)
            return false;

        // C:\..., UNC paths, and the NT forms ETW and the registry use.
        return (normalized.Length >= 2 && normalized[1] == ':')
               || normalized.StartsWith(@"\\", StringComparison.Ordinal)
               || normalized.StartsWith(@"\??\", StringComparison.Ordinal)
               || normalized.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsUnder(string path, string directory)
    {
        var p = Normalize(path);
        var d = Normalize(directory).TrimEnd(Separator);
        return d.Length > 0
               && p.StartsWith(d + Separator, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>True when the path contains this directory segment anywhere
    /// (used for user-profile-relative folders whose full path varies per machine).</summary>
    public static bool ContainsSegment(string path, string segment) =>
        Normalize(path).Contains(
            Separator + Normalize(segment).Trim(Separator) + Separator,
            StringComparison.OrdinalIgnoreCase);
}
