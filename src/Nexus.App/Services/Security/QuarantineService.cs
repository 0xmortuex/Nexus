using System.IO;
using Nexus.Core;
using Nexus.Core.Logging;
using Nexus.Core.Persistence;
using Nexus.Core.Security;

namespace Nexus.App.Services.Security;

/// <summary>The outcome of a quarantine or restore attempt, for the UI to report.</summary>
public sealed record QuarantineResult(bool Succeeded, string Message);

/// <summary>
/// The one part of Sentinel that touches files.
///
/// Everything here is gated three ways: a <see cref="UserConsent"/> token bound to
/// the exact file, a write-ahead journal entry flushed before the move, and a set of
/// refusals that no consent can override. The refusals matter — a security tool that
/// can be talked into moving a file out of System32 is a more effective wrecking ball
/// than most malware, and "the user clicked yes" is not a good enough reason to
/// break someone's Windows install.
/// </summary>
public sealed class QuarantineService
{
    private readonly QuarantineJournal _journal;
    private readonly NexusPaths _paths;
    private readonly ActivityLog _log;

    public QuarantineService(QuarantineJournal journal, NexusPaths paths, ActivityLog log)
    {
        _journal = journal;
        _paths = paths;
        _log = log;
    }

    /// <summary>
    /// Directories Sentinel will never move a file out of, whatever the verdict says.
    /// Removing a live system binary breaks the machine in ways the user cannot undo
    /// from a broken machine; Sentinel reports on these and leaves them alone.
    /// </summary>
    private static readonly string[] ProtectedDirectories =
    [
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
    ];

    /// <summary>Explains why a file cannot be quarantined, or null if it can be.</summary>
    public static string? RefusalReason(Verdict verdict)
    {
        if (verdict.Target.Path is not { Length: > 0 } path)
            return "This finding is about a running process, not a file on disk.";

        if (ProcessSafety.IsProtected(Path.GetFileName(path)))
            return $"{Path.GetFileName(path)} is on the never-touch list. Nexus will report on it but will not move it.";

        foreach (var directory in ProtectedDirectories)
        {
            if (directory.Length == 0)
                continue;

            if (path.StartsWith(directory.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase))
            {
                return $"This file is inside {directory}. Nexus does not move files out of Windows or " +
                       "Program Files, because a wrong call there can leave the machine unbootable.";
            }
        }

        if (!File.Exists(path))
            return "The file is no longer there.";

        return null;
    }

    /// <summary>
    /// Move a file into quarantine. Requires a consent token minted by a user gesture
    /// for this exact file.
    /// </summary>
    public QuarantineResult Quarantine(Verdict verdict, UserConsent consent)
    {
        if (RefusalReason(verdict) is { } refusal)
        {
            _log.Info("Sentinel", $"Did not quarantine {verdict.Target.FileName}: {refusal}");
            return new QuarantineResult(false, refusal);
        }

        Directory.CreateDirectory(_paths.QuarantineDirectory);

        // Journal first: after this line a crash is recoverable, before it there is
        // nothing to recover because nothing has moved.
        var entry = _journal.BeginQuarantine(verdict, _paths.QuarantineDirectory, consent, DateTimeOffset.Now);
        if (entry is null)
        {
            return new QuarantineResult(false,
                "That confirmation was for a different file, or it has already been used. Please try again.");
        }

        try
        {
            File.Move(entry.OriginalPath, entry.QuarantinePath, overwrite: false);
            _journal.MarkHeld(entry.Id);

            _log.Warn("Sentinel",
                $"Quarantined {verdict.Target.FileName} — {verdict.Headline} " +
                "The original is kept and can be restored from the Security tab.");

            return new QuarantineResult(true,
                $"{verdict.Target.FileName} was moved to quarantine. You can put it back at any time.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _journal.MarkFailed(entry.Id, ex.Message);
            _log.Warn("Sentinel", $"Could not quarantine {verdict.Target.FileName}: {ex.Message}");

            return new QuarantineResult(false,
                $"Could not move the file: {ex.Message}. It was left exactly where it was.");
        }
    }

    /// <summary>Put a quarantined file back. No consent needed — this only undoes
    /// something Sentinel did.</summary>
    public QuarantineResult Restore(string entryId)
    {
        var entry = _journal.BeginRestore(entryId);
        if (entry is null)
            return new QuarantineResult(false, "That quarantine entry is not available to restore.");

        try
        {
            var directory = Path.GetDirectoryName(entry.OriginalPath);
            if (directory is { Length: > 0 })
                Directory.CreateDirectory(directory);

            File.Move(entry.QuarantinePath, entry.OriginalPath, overwrite: false);
            _journal.MarkRestored(entry.Id);

            _log.Info("Sentinel", $"Restored {Path.GetFileName(entry.OriginalPath)} to {entry.OriginalPath}.");
            return new QuarantineResult(true, $"Restored to {entry.OriginalPath}.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _journal.MarkFailed(entry.Id, ex.Message);
            _log.Warn("Sentinel", $"Could not restore {entry.OriginalPath}: {ex.Message}");
            return new QuarantineResult(false, $"Could not restore the file: {ex.Message}");
        }
    }

    /// <summary>
    /// Reconcile entries a crash left mid-move. Called at startup, before anything
    /// else in Sentinel runs, in the same spirit as the Game Mode crash recovery.
    /// </summary>
    public void ReconcileOnStartup()
    {
        var unresolved = _journal.Unresolved();
        if (unresolved.Count == 0)
            return;

        _log.Info("Sentinel", $"Checking {unresolved.Count} quarantine entries left over from a previous run.");

        foreach (var entry in unresolved)
        {
            bool atOrigin = File.Exists(entry.OriginalPath);
            bool inQuarantine = File.Exists(entry.QuarantinePath);

            switch (atOrigin, inQuarantine)
            {
                case (false, true):
                    // The move completed but the status was never written.
                    _journal.MarkHeld(entry.Id);
                    _log.Info("Sentinel", $"{Path.GetFileName(entry.OriginalPath)} is in quarantine.");
                    break;

                case (true, false):
                    // The move never happened. The file is untouched, which is the
                    // outcome to prefer whenever it is ambiguous.
                    _journal.MarkFailed(entry.Id, "interrupted before the file was moved");
                    _log.Info("Sentinel",
                        $"{Path.GetFileName(entry.OriginalPath)} was never moved and is where it always was.");
                    break;

                case (true, true):
                    // Both exist: a copy survived on each side. Keep the original and
                    // drop the duplicate rather than guessing which one is wanted.
                    TryDelete(entry.QuarantinePath);
                    _journal.MarkFailed(entry.Id, "interrupted mid-move; the original was kept");
                    _log.Warn("Sentinel",
                        $"{Path.GetFileName(entry.OriginalPath)} existed in both places after an interrupted " +
                        "move. The original was kept.");
                    break;

                case (false, false):
                    _journal.MarkFailed(entry.Id, "the file is in neither location");
                    _log.Warn("Sentinel",
                        $"{Path.GetFileName(entry.OriginalPath)} is in neither its original location nor " +
                        "quarantine. Something else moved or deleted it.");
                    break;
            }
        }
    }

    private void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.Warn("Sentinel", $"Could not remove the duplicate at {path}: {ex.Message}");
        }
    }
}
