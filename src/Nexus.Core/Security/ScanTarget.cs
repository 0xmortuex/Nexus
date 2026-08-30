namespace Nexus.Core.Security;

/// <summary>
/// The identity of something Sentinel evaluated.
///
/// Note what this deliberately is NOT keyed on: the image name. Nexus's optimizer
/// side matches rules by exe name (see <see cref="ProcessSafety"/>), which is a fine
/// shortcut when the worst case is mis-prioritising a process. It is not fine here —
/// malware named "csrss.exe" would inherit the trust of the real one. Security
/// identity is the full path plus the content hash, and trust decisions are keyed on
/// the hash alone so that replacing a trusted file's bytes revokes its trust.
/// </summary>
public sealed record ScanTarget
{
    /// <summary>Full path on disk. May be null for in-memory-only targets (e.g. a
    /// behavioural finding about a process whose image has already been deleted).</summary>
    public string? Path { get; init; }

    /// <summary>Lowercase hex SHA-256 of the file's bytes, or null if it could not be read.</summary>
    public string? Sha256 { get; init; }

    public long SizeBytes { get; init; }

    /// <summary>PID when the target was observed as a running process.</summary>
    public int? Pid { get; init; }

    /// <summary>Display name: the file name, falling back to the path, then to the hash.</summary>
    public string FileName =>
        Path is { Length: > 0 } p ? System.IO.Path.GetFileName(p)
        : Sha256 is { Length: > 0 } h ? h[..Math.Min(12, h.Length)]
        : "(unknown)";

    /// <summary>The stable key for user trust decisions and verdict caching.
    /// Hash first: bytes are the identity, paths are just where they happened to be.</summary>
    public string IdentityKey =>
        Sha256 is { Length: > 0 } h ? "sha256:" + h
        : Path is { Length: > 0 } p ? "path:" + p.ToLowerInvariant()
        : "pid:" + (Pid?.ToString() ?? "?");

    public static ScanTarget ForFile(string path, string? sha256 = null, long sizeBytes = 0) =>
        new() { Path = path, Sha256 = sha256, SizeBytes = sizeBytes };

    public static ScanTarget ForProcess(int pid, string? path, string? sha256 = null) =>
        new() { Pid = pid, Path = path, Sha256 = sha256 };
}
