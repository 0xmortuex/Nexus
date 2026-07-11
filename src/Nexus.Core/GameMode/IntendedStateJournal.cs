using Nexus.Core.Models;
using Nexus.Core.Persistence;

namespace Nexus.Core.GameMode;

/// <summary>Everything needed to undo one process mutation.</summary>
public sealed record ProcessMutationRecord(
    int Pid,
    string ExeName,
    ProcessPriority? OriginalPriority,
    ulong? OriginalAffinityMask,
    bool ClearCpuSets,
    bool ResetEfficiencyMode);

/// <summary>The on-disk crash-recovery ledger: system-wide state Nexus has changed
/// and how to put it back.</summary>
public sealed record IntendedState
{
    public string? ActiveGameExe { get; init; }
    public string? PreviousPowerPlanGuid { get; init; }
    public bool WindowsUpdatePaused { get; init; }
    public IReadOnlyList<ProcessMutationRecord> Mutations { get; init; } = [];

    public bool IsEmpty => ActiveGameExe is null
        && PreviousPowerPlanGuid is null
        && !WindowsUpdatePaused
        && Mutations.Count == 0;
}

/// <summary>
/// Write-ahead journal for Game Mode: every entry is flushed to disk BEFORE the
/// corresponding mutation is applied, so a crash (or power loss) can always be
/// rolled back on the next start.
/// </summary>
public sealed class IntendedStateJournal
{
    private readonly JsonStore<IntendedState> _store;
    private readonly object _gate = new();
    private IntendedState _state;

    public IntendedStateJournal(NexusPaths paths)
        : this(new JsonStore<IntendedState>(
            paths.IntendedStateFile, NexusJsonContext.Default.IntendedState, static () => new IntendedState()))
    {
    }

    public IntendedStateJournal(JsonStore<IntendedState> store)
    {
        _store = store;
        _state = _store.Load();
    }

    public IntendedState Current
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
    }

    /// <summary>Non-empty state left over from a previous run (crash), or null.</summary>
    public IntendedState? LoadPending()
    {
        var state = _store.Load();
        return state.IsEmpty ? null : state;
    }

    public void SetActiveGame(string exeName) =>
        Mutate(s => s with { ActiveGameExe = exeName });

    public void RecordPreviousPowerPlan(string guid) =>
        Mutate(s => s.PreviousPowerPlanGuid is null ? s with { PreviousPowerPlanGuid = guid } : s);

    public void RecordWindowsUpdatePaused() =>
        Mutate(s => s with { WindowsUpdatePaused = true });

    public void RecordMutation(ProcessMutationRecord record) =>
        Mutate(s => s.Mutations.Any(m => m.Pid == record.Pid)
            ? s // first record per PID wins: it holds the true original values
            : s with { Mutations = [.. s.Mutations, record] });

    public void Clear() => Mutate(_ => new IntendedState());

    private void Mutate(Func<IntendedState, IntendedState> mutate)
    {
        lock (_gate)
        {
            var updated = mutate(_state);
            if (ReferenceEquals(updated, _state))
                return;
            _state = updated;
            _store.Save(updated); // flush before the caller performs the mutation
        }
    }
}
