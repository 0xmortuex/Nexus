namespace Nexus.Core.Tweaks;

public sealed record CleanTarget(string Id, string Name, IReadOnlyList<string> Directories, string? FilePattern = null);

/// <summary>
/// Pure definitions + safety filter for the cleaner. Deletion is only ever allowed
/// for paths under one of the target directories — no exceptions, no following of
/// junctions out of them.
/// </summary>
public static class CleanerTargets
{
    /// <summary>Build the target list from environment roots (injectable for tests).</summary>
    public static IReadOnlyList<CleanTarget> Build(
        string userTemp, string windowsDir, string localAppData)
    {
        return
        [
            new("user-temp", "User temp files", [userTemp]),
            new("windows-temp", "Windows temp files", [Path.Combine(windowsDir, "Temp")]),
            new("dx-shader-cache", "DirectX shader cache", [Path.Combine(localAppData, "D3DSCache")]),
            new("nvidia-shader-cache", "NVIDIA shader caches",
            [
                Path.Combine(localAppData, "NVIDIA", "DXCache"),
                Path.Combine(localAppData, "NVIDIA", "GLCache"),
                Path.Combine(localAppData, "NVIDIA Corporation", "NV_Cache"),
            ]),
            new("amd-shader-cache", "AMD shader caches",
            [
                Path.Combine(localAppData, "AMD", "DxCache"),
                Path.Combine(localAppData, "AMD", "DxcCache"),
                Path.Combine(localAppData, "AMD", "GLCache"),
            ]),
            new("wu-cache", "Windows Update download cache",
                [Path.Combine(windowsDir, "SoftwareDistribution", "Download")]),
            new("thumbnail-cache", "Thumbnail cache",
                [Path.Combine(localAppData, "Microsoft", "Windows", "Explorer")],
                FilePattern: "thumbcache_*.db"),
        ];
    }

    /// <summary>A file may be deleted only if it truly lives under one of the given
    /// roots after full path normalization (blocks traversal and absolute surprises).</summary>
    public static bool IsSafeToDelete(string filePath, IEnumerable<string> allowedRoots)
    {
        string full;
        try
        {
            full = Path.GetFullPath(filePath);
        }
        catch (Exception)
        {
            return false;
        }

        foreach (var root in allowedRoots)
        {
            string fullRoot;
            try
            {
                fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
            }
            catch (Exception)
            {
                continue;
            }

            if (full.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || full.StartsWith(fullRoot + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
