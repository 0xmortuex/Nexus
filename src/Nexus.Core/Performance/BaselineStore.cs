using Nexus.Core.Persistence;

namespace Nexus.Core.Performance;

/// <summary>A saved measurement run, kept so a change can be compared against it later.</summary>
public sealed record StoredBaseline
{
    public required string Label { get; init; }
    public required DateTimeOffset CapturedAt { get; init; }
    public required LatencySummary Summary { get; init; }

    /// <summary>The raw samples. Kept because the comparison is a bootstrap over the
    /// actual distribution — summary statistics alone cannot produce a confidence
    /// interval, and without one there is no way to say "no measurable difference"
    /// with a straight face.</summary>
    public required IReadOnlyList<double> Samples { get; init; }

    /// <summary>What the machine was doing, recorded so a user can tell whether two
    /// runs are actually comparable.</summary>
    public string? Notes { get; init; }
}

public sealed record BaselineState
{
    public IReadOnlyList<StoredBaseline> Baselines { get; init; } = [];
}

/// <summary>
/// Keeps saved measurement runs so "did that tweak help?" has an answer that
/// survives a restart.
///
/// Bounded hard: raw samples are the whole point but they are also the bulk of the
/// file, so only the most recent runs are kept.
/// </summary>
public sealed class BaselineStore
{
    /// <summary>Runs kept per label. Enough to see a trend, few enough that the file
    /// stays small.</summary>
    public const int MaxRunsPerLabel = 5;

    /// <summary>Samples kept per run. Well above the bootstrap's needs, and about
    /// 60 KB of JSON at worst.</summary>
    public const int MaxSamplesPerRun = 4000;

    private readonly JsonStore<BaselineState> _store;
    private readonly object _gate = new();
    private BaselineState _state;

    public event Action? Changed;

    public BaselineStore(NexusPaths paths)
        : this(new JsonStore<BaselineState>(
            paths.BaselinesFile, NexusJsonContext.Default.BaselineState, static () => new BaselineState()))
    {
    }

    public BaselineStore(JsonStore<BaselineState> store)
    {
        _store = store;
        _state = _store.Load();
    }

    public IReadOnlyList<StoredBaseline> All()
    {
        lock (_gate)
        {
            return _state.Baselines.OrderByDescending(b => b.CapturedAt).ToArray();
        }
    }

    /// <summary>The most recent run recorded under this label, or null.</summary>
    public StoredBaseline? Latest(string label)
    {
        lock (_gate)
        {
            return _state.Baselines
                .Where(b => string.Equals(b.Label, label, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(b => b.CapturedAt)
                .FirstOrDefault();
        }
    }

    public void Save(StoredBaseline baseline)
    {
        var trimmed = baseline.Samples.Count > MaxSamplesPerRun
            ? baseline with { Samples = baseline.Samples.Take(MaxSamplesPerRun).ToArray() }
            : baseline;

        lock (_gate)
        {
            var kept = _state.Baselines
                .Concat([trimmed])
                .GroupBy(b => b.Label, StringComparer.OrdinalIgnoreCase)
                .SelectMany(group => group.OrderByDescending(b => b.CapturedAt).Take(MaxRunsPerLabel))
                .ToArray();

            _state = _state with { Baselines = kept };
            _store.Save(_state);
        }

        Changed?.Invoke();
    }

    public void Clear()
    {
        lock (_gate)
        {
            _state = new BaselineState();
            _store.Save(_state);
        }

        Changed?.Invoke();
    }
}
