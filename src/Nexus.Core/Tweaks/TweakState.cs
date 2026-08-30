using Nexus.Core.Persistence;

namespace Nexus.Core.Tweaks;

/// <summary>The original value of one registry location, captured before a tweak
/// modified it. Existed=false means the value was absent (undo deletes it).</summary>
public sealed record CapturedValue(string KeyPath, string ValueName, string? Kind, string? Value, bool Existed);

public sealed record AppliedTweak(
    string TweakId,
    DateTimeOffset AppliedAt,
    IReadOnlyList<CapturedValue> Originals,
    string? BackupDirectory);

public sealed record TweaksState
{
    public IReadOnlyList<AppliedTweak> Applied { get; set; } = [];
    /// <summary>Service start values captured by the debloat page (undo data).</summary>
    public IReadOnlyList<CapturedValue> ServiceOriginals { get; set; } = [];
    /// <summary>Scheduled tasks Nexus disabled (undo = re-enable).</summary>
    public IReadOnlyList<string> DisabledTasks { get; set; } = [];
}

/// <summary>Persists which tweaks are applied and everything needed to undo them.</summary>
public sealed class TweakStateStore
{
    private readonly JsonStore<TweaksState> _store;
    private readonly object _gate = new();
    private TweaksState _state;

    public TweakStateStore(NexusPaths paths)
        : this(new JsonStore<TweaksState>(paths.TweaksStateFile, NexusJsonContext.Default.TweaksState, static () => new TweaksState()))
    {
    }

    public TweakStateStore(JsonStore<TweaksState> store)
    {
        _store = store;
        _state = _store.Load();
    }

    public TweaksState Current
    {
        get
        {
            lock (_gate)
            {
                return _state;
            }
        }
    }

    public AppliedTweak? FindApplied(string tweakId)
        => Current.Applied.FirstOrDefault(a => a.TweakId == tweakId);

    public void RecordApplied(AppliedTweak applied) => Mutate(s => s with
    {
        Applied = [.. s.Applied.Where(a => a.TweakId != applied.TweakId), applied],
    });

    public void RemoveApplied(string tweakId) => Mutate(s => s with
    {
        Applied = s.Applied.Where(a => a.TweakId != tweakId).ToArray(),
    });

    public void RecordServiceOriginal(CapturedValue value) => Mutate(s =>
        s.ServiceOriginals.Any(v => v.KeyPath.Equals(value.KeyPath, StringComparison.OrdinalIgnoreCase))
            ? s // keep the first (true) original
            : s with { ServiceOriginals = [.. s.ServiceOriginals, value] });

    public void RemoveServiceOriginal(string keyPath) => Mutate(s => s with
    {
        ServiceOriginals = s.ServiceOriginals
            .Where(v => !v.KeyPath.Equals(keyPath, StringComparison.OrdinalIgnoreCase)).ToArray(),
    });

    public void RecordDisabledTask(string taskPath) => Mutate(s =>
        s.DisabledTasks.Contains(taskPath, StringComparer.OrdinalIgnoreCase)
            ? s
            : s with { DisabledTasks = [.. s.DisabledTasks, taskPath] });

    public void RemoveDisabledTask(string taskPath) => Mutate(s => s with
    {
        DisabledTasks = s.DisabledTasks.Where(t => !t.Equals(taskPath, StringComparison.OrdinalIgnoreCase)).ToArray(),
    });

    private void Mutate(Func<TweaksState, TweaksState> mutate)
    {
        lock (_gate)
        {
            var updated = mutate(_state);
            if (ReferenceEquals(updated, _state))
                return;
            _state = updated;
            _store.Save(updated);
        }
    }
}
