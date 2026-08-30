namespace Nexus.Core.Security;

/// <summary>
/// Decides what is worth scanning and how to read a command line.
///
/// This is pure decision logic that was living in the App layer, where the test
/// project cannot reach it. All three of these have obvious failure modes — a filter
/// that is too broad turns a folder scan into an afternoon, one that is too narrow
/// silently skips the files that matter, and command-line parsing decides which
/// executable a startup entry actually points at.
/// </summary>
public static class ScanTargeting
{
    /// <summary>
    /// File types at least one engine has an opinion about.
    ///
    /// Scanning a photo library to conclude "unknown" forty thousand times wastes the
    /// user's disk and teaches them the report is noise. Extensionless files are
    /// included because a renamed payload is a real thing and the PE parser will
    /// recognise one.
    /// </summary>
    public static bool IsWorthScanning(string path)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();

        return extension is ".exe" or ".dll" or ".sys" or ".scr" or ".ocx" or ".cpl" or ".drv"
            or ".com" or ".pif" or ".bat" or ".cmd" or ".ps1" or ".psm1" or ".vbs" or ".vbe"
            or ".js" or ".jse" or ".wsf" or ".wsh" or ".hta" or ".msi" or ".msp" or ".jar"
            or ".lnk" or ".reg" or "";
    }

    /// <summary>
    /// Directories that are enormous, machine-generated, and not how anything gets
    /// executed.
    ///
    /// A repository's .git folder holds thousands of extensionless object files and
    /// node_modules holds hundreds of thousands of small ones. Hashing all of them
    /// and shipping each through the worker turns "scan this folder" into an
    /// afternoon. On a developer's machine this is the difference between a scan that
    /// finishes and one that gets cancelled.
    ///
    /// Each entry is bounded by separators on both sides so it matches a whole
    /// directory name — without that, "\obj\" would also hit "\objects\".
    /// </summary>
    public static bool IsNoiseDirectory(string path)
    {
        var normalized = path.Replace('/', '\\');

        string[] noise =
        [
            @"\.git\", @"\node_modules\", @"\.svn\", @"\.hg\",
            @"\obj\", @"\bin\Debug\", @"\bin\Release\",
            @"\.vs\", @"\.gradle\", @"\__pycache__\", @"\.venv\",
            @"\Package Cache\", @"\WinSxS\",
        ];

        return noise.Any(segment => normalized.Contains(segment, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Pull the executable out of a command line.
    ///
    /// Handles the quoted form and the unquoted-with-spaces form that Windows itself
    /// resolves by probing each prefix. That second case is not a curiosity: it is the
    /// same ambiguity behind unquoted service path hijacking, where
    /// <c>C:\Program Files\App\app.exe</c> can be pre-empted by a
    /// <c>C:\Program.exe</c>. Reading it the way the loader does is the only way to
    /// report the binary that will actually run.
    /// </summary>
    /// <param name="exists">Existence probe, injected so the parsing is testable
    /// without a filesystem.</param>
    public static string? ExtractImagePath(string command, Func<string, bool> exists)
    {
        var trimmed = command.Trim();
        if (trimmed.Length == 0)
            return null;

        if (trimmed[0] == '"')
        {
            int closing = trimmed.IndexOf('"', 1);
            return closing > 1 ? trimmed[1..closing] : null;
        }

        // Unquoted: try progressively longer prefixes at each space, so
        // "C:\Program Files\App\app.exe -x" resolves rather than stopping at
        // "C:\Program". The loader probes in this same order, shortest first, which
        // is precisely why a stray C:\Program.exe wins over the intended target.
        for (int i = trimmed.IndexOf(' '); i >= 0; i = trimmed.IndexOf(' ', i + 1))
        {
            var candidate = trimmed[..i];
            if (exists(candidate))
                return candidate;
        }

        return exists(trimmed) ? trimmed : null;
    }

    /// <summary>
    /// True when a Microsoft Defender exclusion covers so much that it defeats the
    /// point of having Defender on.
    ///
    /// Excluding a whole drive, the users tree, or a temp folder is not a tuning
    /// decision — it is a hole, and adding one is a standard early step for malware
    /// that intends to stay.
    /// </summary>
    public static bool IsOverlyBroadExclusion(string path)
    {
        var normalized = path.Trim().TrimEnd('\\', '*', '/').ToLowerInvariant();
        if (normalized.Length == 0)
            return false;

        string[] broad =
        [
            @"c:", @"d:", @"e:",
            @"c:\users", @"c:\windows", @"c:\program files", @"c:\program files (x86)",
            @"c:\programdata", @"c:\temp", @"%userprofile%", @"%temp%", @"%appdata%",
            @"%systemdrive%", @"%windir%",
        ];

        return broad.Any(entry => string.Equals(normalized, entry, StringComparison.OrdinalIgnoreCase));
    }
}
