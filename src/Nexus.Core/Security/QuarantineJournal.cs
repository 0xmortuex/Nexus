using Nexus.Core.Persistence;

namespace Nexus.Core.Security;

/// <summary>Where an entry is in its lifecycle. The intermediate states exist so a
/// crash halfway through a file move is recoverable rather than a lost file.</summary>
public enum QuarantineStatus
{
    /// <summary>Written to the journal; the file has not been moved yet.</summary>
    Pending,

    /// <summary>The file is in the quarantine folder.</summary>
    Held,

    /// <summary>A restore was journalled; the file may be in either location.</summary>
    Restoring,

    /// <summary>Put back where it came from.</summary>
    Restored,

    /// <summary>The move failed and the file was left alone. Nothing was lost.</summary>
    Failed,
}

/// <summary>One quarantined file and everything needed to put it back exactly.</summary>
public sealed record QuarantineEntry
{
    public required string Id { get; set; }
    public required string OriginalPath { get; set; }
    public required string QuarantinePath { get; set; }
    public string? Sha256 { get; set; }
    public long SizeBytes { get; set; }
    public required DateTimeOffset QuarantinedAt { get; set; }
    public required ThreatLevel Level { get; set; }

    /// <summary>Plain-language reason, shown in the UI and preserved for restores.</summary>
    public required string Reason { get; set; }

    public QuarantineStatus Status { get; set; } = QuarantineStatus.Pending;

    /// <summary>Why a Failed entry failed, for the log.</summary>
    public string? Error { get; set; }
}

public sealed record QuarantineState
{
    public IReadOnlyList<QuarantineEntry> Entries { get; set; } = [];
}

/// <summary>
/// The quarantine ledger — a write-ahead journal, exactly like
/// <see cref="GameMode.IntendedStateJournal"/>: the intent to move a file is flushed
/// to disk before the move happens, so a crash always leaves a record pointing at
/// both possible locations.
///
/// This type moves no files. It records intent and hands back entries; the file
/// operations live in the App layer. Consent is required to open an entry, so
/// nothing can be quarantined without a user gesture.
/// </summary>
public sealed class QuarantineJournal
{
    private readonly JsonStore<QuarantineState> _store;
    private readonly object _gate = new();
    private QuarantineState _state;

    public event Action? Changed;

    public QuarantineJournal(NexusPaths paths)
        : this(new JsonStore<QuarantineState>(
            paths.QuarantineJournalFile, NexusJsonContext.Default.QuarantineState, static () => new QuarantineState()))
    {
    }

    public QuarantineJournal(JsonStore<QuarantineState> store)
    {
        _store = store;
        _state = _store.Load();
    }

    public IReadOnlyList<QuarantineEntry> All()
    {
        lock (_gate)
        {
            return _state.Entries.OrderByDescending(e => e.QuarantinedAt).ToArray();
        }
    }

    public IReadOnlyList<QuarantineEntry> Held() =>
        All().Where(e => e.Status == QuarantineStatus.Held).ToArray();

    /// <summary>Entries a crash left mid-flight, to reconcile on the next start.</summary>
    public IReadOnlyList<QuarantineEntry> Unresolved() =>
        All().Where(e => e.Status is QuarantineStatus.Pending or QuarantineStatus.Restoring).ToArray();

    /// <summary>
    /// Journal the intent to quarantine, returning the entry the caller should then
    /// act on — or null if the consent does not cover this exact file.
    /// </summary>
    public QuarantineEntry? BeginQuarantine(
        Verdict verdict, string quarantineDirectory, UserConsent consent, DateTimeOffset now)
    {
        if (verdict.Target.Path is not { Length: > 0 } originalPath)
            return null;
        if (!consent.TryRedeem("quarantine", verdict.Target.IdentityKey, now))
            return null;

        var id = Guid.NewGuid().ToString("n");
        var entry = new QuarantineEntry
        {
            Id = id,
            OriginalPath = originalPath,
            // The stored copy keeps no executable extension, so nothing can launch it
            // by accident and no shell preview handler will parse it.
            QuarantinePath = Path.Combine(quarantineDirectory, id + ".quarantined"),
            Sha256 = verdict.Target.Sha256,
            SizeBytes = verdict.Target.SizeBytes,
            QuarantinedAt = now,
            Level = verdict.Level,
            Reason = verdict.Headline,
            Status = QuarantineStatus.Pending,
        };

        Upsert(entry); // flushed before the caller touches the file
        return entry;
    }

    /// <summary>Journal the intent to restore. Restoring needs no consent — it only
    /// ever undoes something Sentinel did.</summary>
    public QuarantineEntry? BeginRestore(string id)
    {
        var entry = Find(id);
        if (entry is null || entry.Status != QuarantineStatus.Held)
            return null;

        var updated = entry with { Status = QuarantineStatus.Restoring };
        Upsert(updated);
        return updated;
    }

    public void MarkHeld(string id) => Transition(id, QuarantineStatus.Held);
    public void MarkRestored(string id) => Transition(id, QuarantineStatus.Restored);

    /// <summary>
    /// A restore was attempted and did not happen, so the file is still in
    /// quarantine.
    ///
    /// This is deliberately NOT <see cref="MarkFailed"/>. Failed means "the move
    /// never happened and the file is where it always was", which is true for a
    /// failed quarantine and false for a failed restore — there the file really is
    /// in the quarantine folder. Marking it Failed drops it out of
    /// <see cref="Held"/>, so it vanishes from the list the user restores from and
    /// sits in quarantine forever under a meaningless name with no way to ask for it
    /// back. It goes back to Held, carrying the reason it did not work.
    /// </summary>
    public void MarkRestoreFailed(string id, string error)
    {
        var entry = Find(id);
        if (entry is null)
            return;

        Upsert(entry with { Status = QuarantineStatus.Held, Error = error });
    }

    public void MarkFailed(string id, string error)
    {
        var entry = Find(id);
        if (entry is null)
            return;
        Upsert(entry with { Status = QuarantineStatus.Failed, Error = error });
    }

    public QuarantineEntry? Find(string id)
    {
        lock (_gate)
        {
            return _state.Entries.FirstOrDefault(e => e.Id == id);
        }
    }

    /// <summary>Drop the ledger record. The caller is responsible for the file itself.</summary>
    public bool Forget(string id)
    {
        bool removed;
        lock (_gate)
        {
            var remaining = _state.Entries.Where(e => e.Id != id).ToArray();
            removed = remaining.Length != _state.Entries.Count;
            if (removed)
            {
                _state = _state with { Entries = remaining };
                _store.Save(_state);
            }
        }
        if (removed)
            Changed?.Invoke();
        return removed;
    }

    private void Transition(string id, QuarantineStatus status)
    {
        var entry = Find(id);
        if (entry is null)
            return;
        Upsert(entry with { Status = status, Error = null });
    }

    private void Upsert(QuarantineEntry entry)
    {
        lock (_gate)
        {
            var entries = _state.Entries.Where(e => e.Id != entry.Id).Append(entry).ToArray();
            _state = _state with { Entries = entries };
            _store.Save(_state);
        }
        Changed?.Invoke();
    }
}
