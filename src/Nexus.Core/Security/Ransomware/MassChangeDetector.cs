using Nexus.Core.Security.Behavior;

namespace Nexus.Core.Security.Ransomware;

public enum FileChangeKind
{
    Created,
    Modified,
    Renamed,
    Deleted,
}

/// <summary>One filesystem change, as seen by the watcher.</summary>
public sealed record FileChangeEvent
{
    public required string Path { get; init; }
    public required FileChangeKind Kind { get; init; }
    public required DateTimeOffset At { get; init; }

    /// <summary>For renames, where it came from.</summary>
    public string? OldPath { get; init; }

    /// <summary>True when this path is one of the canary files Nexus planted.</summary>
    public bool IsCanary { get; init; }
}

/// <summary>What the detector concluded, and the evidence behind it.</summary>
public sealed record RansomwareFinding
{
    public required IReadOnlyList<SecuritySignal> Signals { get; init; }
    public required DateTimeOffset DetectedAt { get; init; }

    /// <summary>Distinct files touched inside the detection window.</summary>
    public required int FilesAffected { get; init; }

    /// <summary>A sample of the paths, for the alert.</summary>
    public required IReadOnlyList<string> ExamplePaths { get; init; }

    /// <summary>The extension everything is being renamed to, when there is one.</summary>
    public string? SuspiciousExtension { get; init; }
}

/// <summary>
/// Watches the shape of filesystem activity for the pattern ransomware makes:
/// a large number of documents rewritten or renamed in a very short time.
///
/// This is the one detection in Sentinel where reporting quickly genuinely matters,
/// because the damage accumulates while you decide. It is also the one where a false
/// positive is most annoying — a backup tool, a sync client, a game updater, or an
/// unzip all produce bursts of file changes. So the ordinary burst rule is
/// deliberately conservative, and the sharp evidence comes from things a normal
/// program has no reason to do:
///
/// - <b>Canary files.</b> Nexus plants hidden files in the user's document folders.
///   Nothing legitimate reads them, because nothing legitimate knows they exist.
///   Something that rewrites them is walking the filesystem indiscriminately.
/// - <b>Uniform new extensions.</b> Ransomware renames what it encrypts, and it
///   renames everything to the same thing. A sync client does not.
/// - <b>Ransom notes.</b> Dropping the same README into many folders is not a
///   behaviour with an innocent version.
///
/// Pure and time-injected, so the whole thing is testable without waiting.
/// </summary>
public sealed class MassChangeDetector
{
    /// <summary>How far back the sliding window looks.</summary>
    public static readonly TimeSpan Window = TimeSpan.FromSeconds(60);

    /// <summary>Distinct documents changed inside the window before the burst alone
    /// is worth mentioning. Set high because backup and sync tools are noisy.</summary>
    public const int BurstThreshold = 40;

    /// <summary>Files sharing one new extension before that pattern is called out.</summary>
    public const int UniformExtensionThreshold = 8;

    /// <summary>After a finding, stay quiet this long. An encryption run generates
    /// thousands of events and the user needs one alert, not thousands.</summary>
    public static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(5);

    /// <summary>Upper bound on tracked events, so a runaway process cannot turn the
    /// detector into the memory problem.</summary>
    public const int MaxTrackedEvents = 20_000;

    /// <summary>File types worth counting: documents and media, the things people
    /// lose. Counting temp and build output would make every compile look like an
    /// attack.</summary>
    private static readonly HashSet<string> DocumentExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".odt", ".ods",
        ".txt", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".raw",
        ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav", ".flac",
        ".zip", ".rar", ".7z", ".psd", ".ai", ".sql", ".mdb", ".accdb", ".pst", ".ost",
    };

    /// <summary>Names dropped into folders to tell the victim how to pay.</summary>
    private static readonly string[] RansomNoteMarkers =
    [
        "how_to_decrypt", "how-to-decrypt", "howtodecrypt",
        "how_to_restore", "how-to-restore",
        "recover_files", "recover-files", "recovery_key",
        "your_files", "yourfiles", "readme_to_decrypt",
        "decrypt_instruction", "restore_my_files", "!!!readme",
        "unlock_files", "ransom",
    ];

    /// <param name="TallyExtension">The extension counted toward the uniform-rename
    /// rule, or empty when this change should not count toward it.</param>
    private readonly record struct TrackedChange(
        string Path, string TallyExtension, DateTimeOffset At);

    private readonly Queue<TrackedChange> _window = new();

    // Reference-counted rather than a set: a path can appear many times in the window,
    // and the count is what makes eviction O(1). The obvious alternative — scanning the
    // window to see whether a dropped path still occurs — is O(n) per eviction, which
    // is quadratic exactly when it matters most, during the flood of events an
    // encryption run produces.
    private readonly Dictionary<string, int> _pathCounts = new(StringComparer.OrdinalIgnoreCase);

    // Extension tallies are maintained incrementally for the same reason. Recomputing
    // them by walking the window on every event is O(n) per event, and this method is
    // called once per filesystem change on the whole machine.
    private readonly Dictionary<string, int> _extensionCounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    private DateTimeOffset? _lastFinding;

    /// <summary>Distinct documents changed inside the current window.</summary>
    public int TrackedFileCount
    {
        get
        {
            lock (_gate)
            {
                return _pathCounts.Count;
            }
        }
    }

    /// <summary>
    /// Record a change and report if the pattern has become alarming.
    /// Returns null on every ordinary event, which is almost all of them.
    /// </summary>
    public RansomwareFinding? Observe(FileChangeEvent change)
    {
        lock (_gate)
        {
            Prune(change.At);

            var signals = new List<SecuritySignal>();

            // A canary touch is worth reporting on its own and immediately.
            if (change.IsCanary && change.Kind != FileChangeKind.Created)
            {
                signals.Add(new SecuritySignal(
                    SignalSource.Behavior,
                    SignalWeight.Strong,
                    "ransom-canary-touched",
                    $"A file Nexus planted specifically to be left alone was {Describe(change.Kind)}. " +
                    "Nothing on this machine has a legitimate reason to touch it, which means something " +
                    "is working through your files indiscriminately."));
            }

            if (IsRansomNote(change.Path) && change.Kind == FileChangeKind.Created)
            {
                signals.Add(new SecuritySignal(
                    SignalSource.Behavior,
                    SignalWeight.Strong,
                    "ransom-note-created",
                    $"A file named {PathHelpers.FileName(change.Path)} was just created. That name " +
                    "matches the ransom notes attackers leave behind after encrypting files."));
            }

            Track(change);

            var uniformExtension = FindUniformNewExtension();
            if (uniformExtension is not null)
            {
                signals.Add(new SecuritySignal(
                    SignalSource.Behavior,
                    SignalWeight.Strong,
                    "ransom-uniform-extension",
                    $"Many of your files have just been renamed to end in {uniformExtension}. " +
                    "Renaming everything to one new extension is what encryption does; sync and " +
                    "backup tools do not."));
            }

            if (_pathCounts.Count >= BurstThreshold)
            {
                signals.Add(new SecuritySignal(
                    SignalSource.Behavior,
                    SignalWeight.Moderate,
                    "ransom-mass-change",
                    $"{_pathCounts.Count} documents changed in under {Window.TotalSeconds:F0} seconds. " +
                    "Backup tools, sync clients and unzipping all do this too, so on its own it is not " +
                    "proof of anything."));
            }

            if (signals.Count == 0)
                return null;

            // Only the burst rule fired, and it is the noisy one — stay quiet unless
            // something sharper corroborates it.
            if (signals.All(s => s.Code == "ransom-mass-change"))
                return null;

            if (_lastFinding is { } last && change.At - last < Cooldown)
                return null;

            _lastFinding = change.At;

            return new RansomwareFinding
            {
                Signals = signals,
                DetectedAt = change.At,
                FilesAffected = _pathCounts.Count,
                ExamplePaths = _pathCounts.Keys.Take(5).ToArray(),
                SuspiciousExtension = uniformExtension,
            };
        }
    }

    /// <summary>Clear state, e.g. after the user says a burst was expected.</summary>
    public void Reset()
    {
        lock (_gate)
        {
            _window.Clear();
            _pathCounts.Clear();
            _extensionCounts.Clear();
            _lastFinding = null;
        }
    }

    private void Track(FileChangeEvent change)
    {
        if (change.Kind == FileChangeKind.Created && !IsRenameTarget(change))
            return;

        var extension = Path.GetExtension(change.Path);

        // Count documents, plus anything renamed — a rename to an unknown extension is
        // exactly the case that matters, and filtering by extension would miss it.
        bool counts = DocumentExtensions.Contains(extension)
                      || change.Kind == FileChangeKind.Renamed;

        if (!counts)
            return;

        var tallyExtension = ExtensionForUniformRule(change, extension);

        _window.Enqueue(new TrackedChange(change.Path, tallyExtension, change.At));
        Retain(change.Path);
        RetainExtension(tallyExtension);

        while (_window.Count > MaxTrackedEvents)
            Evict();
    }

    private static bool IsRenameTarget(FileChangeEvent change) =>
        change.OldPath is { Length: > 0 };

    /// <summary>
    /// The extension this change contributes to the uniform-rename rule, or empty if
    /// it contributes nothing.
    ///
    /// Ransomware renames <i>documents</i> into a new extension: report.docx becomes
    /// report.docx.locked. Counting every rename to an unfamiliar extension looked
    /// equivalent and is not — plenty of ordinary software renames working files into
    /// its own format, and games in particular save atomically by writing a temporary
    /// file and renaming it to something like .sav. Eight of those inside a minute
    /// used to be enough to raise a ransomware alarm, in the middle of a game, which
    /// is both wrong and the worst possible moment to be wrong.
    ///
    /// Requiring the file to have been a document immediately before the rename keeps
    /// the encryption pattern and drops that entire class of false positive.
    /// </summary>
    private static string ExtensionForUniformRule(FileChangeEvent change, string newExtension)
    {
        if (change.Kind != FileChangeKind.Renamed || change.OldPath is not { Length: > 0 } oldPath)
            return "";

        var oldExtension = Path.GetExtension(oldPath);

        if (!DocumentExtensions.Contains(oldExtension))
            return "";

        // A document keeping its own extension is just a move, not an encryption.
        return DocumentExtensions.Contains(newExtension) ? "" : newExtension;
    }

    private void Prune(DateTimeOffset now)
    {
        var cutoff = now - Window;

        while (_window.Count > 0 && _window.Peek().At < cutoff)
            Evict();
    }

    private void Evict()
    {
        var dropped = _window.Dequeue();
        Release(dropped.Path);
        ReleaseExtension(dropped.TallyExtension);
    }

    private void Retain(string path)
    {
        _pathCounts.TryGetValue(path, out int count);
        _pathCounts[path] = count + 1;
    }

    /// <summary>Forget a path only once the last event referring to it has aged out.</summary>
    private void Release(string path)
    {
        if (!_pathCounts.TryGetValue(path, out int count))
            return;

        if (count <= 1)
            _pathCounts.Remove(path);
        else
            _pathCounts[path] = count - 1;
    }

    /// <summary>
    /// The extension that many files have just acquired, if there is one. Ignores
    /// ordinary document extensions: a folder full of .docx is a Tuesday, a folder
    /// full of .locked is not.
    /// </summary>
    private string? FindUniformNewExtension()
    {
        foreach (var (extension, count) in _extensionCounts)
        {
            if (count >= UniformExtensionThreshold)
                return extension;
        }

        return null;
    }

    /// <summary>Only extensions that could indicate encryption are tallied — an
    /// ordinary document extension can never trip the uniform-extension rule.</summary>
    private static bool IsTallyableExtension(string extension) =>
        extension.Length is > 0 and <= 12 && !DocumentExtensions.Contains(extension);

    private void RetainExtension(string extension)
    {
        if (!IsTallyableExtension(extension))
            return;

        _extensionCounts.TryGetValue(extension, out int count);
        _extensionCounts[extension] = count + 1;
    }

    private void ReleaseExtension(string extension)
    {
        if (!IsTallyableExtension(extension) || !_extensionCounts.TryGetValue(extension, out int count))
            return;

        if (count <= 1)
            _extensionCounts.Remove(extension);
        else
            _extensionCounts[extension] = count - 1;
    }

    private static bool IsRansomNote(string path)
    {
        var name = PathHelpers.FileName(path).ToLowerInvariant();

        return RansomNoteMarkers.Any(marker => name.Contains(marker, StringComparison.Ordinal));
    }

    private static string Describe(FileChangeKind kind) => kind switch
    {
        FileChangeKind.Modified => "rewritten",
        FileChangeKind.Renamed => "renamed",
        FileChangeKind.Deleted => "deleted",
        _ => "changed",
    };
}
