using System.IO;
using Nexus.Core.Logging;
using Nexus.Core.Performance;
using Nexus.Core.Security;

namespace Nexus.App.Services.Security;

/// <summary>
/// Undoes everything Sentinel and the measurement layer have left on the machine,
/// for the "Restore all defaults" button.
///
/// This exists because Nexus's README makes a specific promise — that one button
/// undoes everything Nexus ever changed — and Sentinel quietly broke it. Sentinel
/// writes real files to the user's own folders (the ransomware tripwires) and, worse,
/// it can be holding the user's files in quarantine. A "restore defaults" that
/// forgets about those either litters the machine or, if it just deleted the
/// quarantine folder, destroys data the user asked to be kept safe.
///
/// So the order here matters, and one step is not optional: quarantined files are
/// put back FIRST, before any bookkeeping is cleared. Losing the journal while files
/// are still in quarantine would strand them under meaningless names with no record
/// of where they came from.
/// </summary>
public sealed class SentinelResetService
{
    private readonly QuarantineService _quarantine;
    private readonly QuarantineJournal _journal;
    private readonly TrustStore _trust;
    private readonly VerdictCache _cache;
    private readonly BaselineStore _baselines;
    private readonly RansomwareGuardService _ransomware;
    private readonly ActivityLog _log;

    public SentinelResetService(
        QuarantineService quarantine,
        QuarantineJournal journal,
        TrustStore trust,
        VerdictCache cache,
        BaselineStore baselines,
        RansomwareGuardService ransomware,
        ActivityLog log)
    {
        _quarantine = quarantine;
        _journal = journal;
        _trust = trust;
        _cache = cache;
        _baselines = baselines;
        _ransomware = ransomware;
        _log = log;
    }

    /// <summary>Undo Sentinel's footprint. Returns anything that could not be undone.</summary>
    public IReadOnlyList<string> ResetEverything()
    {
        var failures = new List<string>();

        // 1. Files first. Everything else is bookkeeping and can be recreated; a
        //    quarantined file cannot.
        failures.AddRange(RestoreQuarantinedFiles());

        // 2. The tripwires are real files in the user's own folders.
        failures.AddRange(_ransomware.RemoveCanaries());

        // 3. Bookkeeping.
        _trust.Clear();
        _cache.Invalidate("reset");
        _baselines.Clear();

        _log.Info("Restore",
            failures.Count == 0
                ? "Security module reset: quarantined files restored, tripwire files removed, " +
                  "trusted-file list and saved measurements cleared."
                : $"Security module reset with {failures.Count} item(s) needing attention.");

        return failures;
    }

    private IReadOnlyList<string> RestoreQuarantinedFiles()
    {
        var held = _journal.Held();
        if (held.Count == 0)
            return [];

        _log.Info("Restore", $"Putting {held.Count} quarantined file(s) back before clearing the record.");

        var failures = new List<string>();

        foreach (var entry in held)
        {
            var result = _quarantine.Restore(entry.Id);
            if (result.Succeeded)
                continue;

            // Deliberately keep the journal entry: a file that could not be put back
            // must stay findable, and the record of where it belongs is the only way
            // to find it.
            failures.Add($"Quarantine: could not restore {Path.GetFileName(entry.OriginalPath)} — {result.Message}");
        }

        return failures;
    }
}
