using Nexus.Core.Persistence;

namespace Nexus.Core.Security;

/// <summary>A previous conclusion, small enough to keep thousands of.</summary>
public sealed record CachedVerdict
{
    public required string IdentityKey { get; init; }
    public required string FileName { get; init; }
    public required ThreatLevel Level { get; init; }
    public required int Score { get; init; }
    public required DateTimeOffset EvaluatedAt { get; init; }
    public required string Headline { get; init; }
}

public sealed record VerdictCacheState
{
    /// <summary>Stamp of the detection content that produced these verdicts. When it
    /// changes, every entry is discarded — a cached "clean" from an older ruleset is
    /// worse than no answer, because it silently suppresses a new detection.</summary>
    public string RulesVersion { get; init; } = "";

    public IReadOnlyList<CachedVerdict> Entries { get; init; } = [];
}

/// <summary>
/// Remembers what Sentinel concluded about a hash, so re-scanning an unchanged file
/// is free. Bounded and time-limited: a verdict is a snapshot of what was knowable
/// at a moment, and reputation feeds move.
/// </summary>
public sealed class VerdictCache
{
    public const int MaxEntries = 5000;
    public static readonly TimeSpan DefaultTtl = TimeSpan.FromDays(14);

    private readonly JsonStore<VerdictCacheState> _store;
    private readonly TimeSpan _ttl;
    private readonly object _gate = new();
    private Dictionary<string, CachedVerdict> _byKey;
    private string _rulesVersion;

    public VerdictCache(NexusPaths paths, string rulesVersion, TimeSpan? ttl = null)
        : this(new JsonStore<VerdictCacheState>(
                paths.VerdictCacheFile, NexusJsonContext.Default.VerdictCacheState, static () => new VerdictCacheState()),
            rulesVersion, ttl)
    {
    }

    public VerdictCache(JsonStore<VerdictCacheState> store, string rulesVersion, TimeSpan? ttl = null)
    {
        _store = store;
        _rulesVersion = rulesVersion;
        _ttl = ttl ?? DefaultTtl;

        var state = _store.Load();
        _byKey = state.RulesVersion == rulesVersion
            ? state.Entries.ToDictionary(e => e.IdentityKey, StringComparer.Ordinal)
            : new Dictionary<string, CachedVerdict>(StringComparer.Ordinal);
    }

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _byKey.Count;
            }
        }
    }

    public CachedVerdict? TryGet(ScanTarget target, DateTimeOffset now)
    {
        // A target with no hash has no stable identity to cache against.
        if (target.Sha256 is not { Length: > 0 })
            return null;

        lock (_gate)
        {
            if (!_byKey.TryGetValue(target.IdentityKey, out var entry))
                return null;

            if (now - entry.EvaluatedAt > _ttl)
            {
                _byKey.Remove(target.IdentityKey);
                return null;
            }

            return entry;
        }
    }

    public void Store(Verdict verdict)
    {
        if (verdict.Target.Sha256 is not { Length: > 0 })
            return;

        lock (_gate)
        {
            _byKey[verdict.Target.IdentityKey] = new CachedVerdict
            {
                IdentityKey = verdict.Target.IdentityKey,
                FileName = verdict.Target.FileName,
                Level = verdict.Level,
                Score = verdict.Score,
                EvaluatedAt = verdict.EvaluatedAt,
                Headline = verdict.Headline,
            };

            if (_byKey.Count > MaxEntries)
                Evict();

            Save();
        }
    }

    /// <summary>Discard everything: called when the rule set or model is updated.</summary>
    public void Invalidate(string newRulesVersion)
    {
        lock (_gate)
        {
            _rulesVersion = newRulesVersion;
            _byKey = new Dictionary<string, CachedVerdict>(StringComparer.Ordinal);
            Save();
        }
    }

    /// <summary>Drop the oldest quarter, so eviction is not a per-insert cost.</summary>
    private void Evict()
    {
        var survivors = _byKey.Values
            .OrderByDescending(e => e.EvaluatedAt)
            .Take(MaxEntries * 3 / 4)
            .ToDictionary(e => e.IdentityKey, StringComparer.Ordinal);
        _byKey = survivors;
    }

    private void Save() =>
        _store.Save(new VerdictCacheState { RulesVersion = _rulesVersion, Entries = _byKey.Values.ToArray() });
}
