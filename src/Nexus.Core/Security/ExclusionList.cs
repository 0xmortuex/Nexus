namespace Nexus.Core.Security;

/// <summary>One thing the user has told Nexus to leave alone.</summary>
/// <param name="Pattern">A folder path, a full file path, or an extension like ".iso".</param>
public sealed record Exclusion(string Pattern, string? Note = null)
{
    public bool IsExtension => Pattern.StartsWith('.') && !Pattern.Contains('\\') && !Pattern.Contains('/');
}

/// <summary>
/// Paths and file types the user has asked Nexus to skip.
///
/// Every antivirus has this, and every antivirus is right to: a developer whose build
/// output is rescanned on every compile, or someone with a 200 GB game library on a
/// slow drive, will otherwise turn the whole product off. An exclusion list is what
/// stops "too noisy" becoming "uninstalled".
///
/// It is also, unavoidably, a set of holes. Nexus already flags Microsoft Defender's
/// overly broad exclusions as suspicious, and it would be incoherent to apply a
/// gentler standard to its own — so the same breadth check runs here, and an
/// exclusion wide enough to matter is reported rather than silently honoured.
/// </summary>
public sealed class ExclusionList
{
    private readonly List<Exclusion> _exclusions;

    public ExclusionList(IEnumerable<Exclusion>? exclusions = null)
    {
        _exclusions = exclusions?.Where(e => e.Pattern.Trim().Length > 0).ToList() ?? [];
    }

    public IReadOnlyList<Exclusion> All => _exclusions;

    public int Count => _exclusions.Count;

    /// <summary>True when this path should not be scanned.</summary>
    public bool IsExcluded(string path)
    {
        if (path.Length == 0 || _exclusions.Count == 0)
            return false;

        var normalized = Normalize(path);
        var extension = System.IO.Path.GetExtension(path);

        foreach (var exclusion in _exclusions)
        {
            var pattern = Normalize(exclusion.Pattern);
            if (pattern.Length == 0)
                continue;

            if (exclusion.IsExtension)
            {
                if (string.Equals(extension, exclusion.Pattern, StringComparison.OrdinalIgnoreCase))
                    return true;

                continue;
            }

            // An exact file match, or anything beneath an excluded folder. Bounded by a
            // separator so that excluding C:\Data does not also exclude C:\DataSecret.
            if (string.Equals(normalized, pattern, StringComparison.OrdinalIgnoreCase))
                return true;

            if (normalized.StartsWith(pattern.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Exclusions broad enough that honouring them defeats the point, reported so the
    /// user can see what they have actually switched off. Nexus holds its own
    /// exclusions to the standard it holds Defender's.
    /// </summary>
    public IReadOnlyList<SecuritySignal> Audit()
    {
        var signals = new List<SecuritySignal>();

        foreach (var exclusion in _exclusions)
        {
            if (ScanTargeting.IsOverlyBroadExclusion(exclusion.Pattern))
            {
                signals.Add(new SecuritySignal(
                    SignalSource.Persistence,
                    SignalWeight.Moderate,
                    "exclusion-too-broad",
                    $"You have told Nexus to ignore {exclusion.Pattern} entirely. That covers so much " +
                    "that scanning is effectively off for everything inside it."));

                continue;
            }

            if (exclusion.IsExtension && IsExecutableExtension(exclusion.Pattern))
            {
                signals.Add(new SecuritySignal(
                    SignalSource.Persistence,
                    SignalWeight.Moderate,
                    "exclusion-executable-type",
                    $"You have told Nexus to ignore every {exclusion.Pattern} file. That is the file " +
                    "type most worth looking at."));
            }
        }

        return signals;
    }

    private static bool IsExecutableExtension(string extension) =>
        extension.ToLowerInvariant() is ".exe" or ".dll" or ".scr" or ".com" or ".bat" or ".cmd"
            or ".ps1" or ".vbs" or ".js" or ".msi" or ".sys";

    private static string Normalize(string path) =>
        path.Trim().Replace('/', '\\').TrimEnd('\\');
}
