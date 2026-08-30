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

    // ---- Fast-path identity ----
    //
    // Hashing is the dominant cost of a scan, and hashing a file just to discover it
    // has not changed is the work the cache exists to avoid. So an entry also records
    // where the file was and what its size and timestamp were: if all three still
    // match, the contents almost certainly have not changed and the cached verdict
    // stands without reading a byte.
    //
    // "Almost certainly" is the honest word. A file rewritten in place, at the same
    // size, with its timestamp restored would slip through — which is why this is a
    // cache for skipping repeat work, not a trust decision. Trust is keyed on the
    // hash alone (see TrustStore) and is never served from here.

    public string? Path { get; init; }
    public long SizeBytes { get; init; }
    public long LastWriteUtcTicks { get; init; }
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

    /// <summary>
    /// Entries buffered before the file is rewritten.
    ///
    /// This is a cache, and it was rewriting the whole document on every single
    /// insert — so scanning a folder of ten thousand files meant ten thousand full
    /// serialise-and-write cycles, which cost far more than the work being cached.
    /// Losing the last few entries to a crash costs nothing: they get recomputed.
    /// </summary>
    public const int WritesBetweenSaves = 250;

    private readonly JsonStore<VerdictCacheState> _store;
    private readonly TimeSpan _ttl;
    private readonly object _gate = new();
    private int _pendingWrites;
    private Dictionary<string, CachedVerdict> _byKey;
    private Dictionary<string, CachedVerdict> _byStamp;
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

        _byStamp = BuildStampIndex(_byKey.Values);
    }

    private static Dictionary<string, CachedVerdict> BuildStampIndex(IEnumerable<CachedVerdict> entries)
    {
        var index = new Dictionary<string, CachedVerdict>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries)
        {
            if (StampKey(entry.Path, entry.SizeBytes, entry.LastWriteUtcTicks) is { } stamp)
                index[stamp] = entry;
        }

        return index;
    }

    /// <summary>The fast-path key: path + size + last-write time.</summary>
    public static string? StampKey(string? path, long sizeBytes, long lastWriteUtcTicks)
    {
        if (path is not { Length: > 0 } || lastWriteUtcTicks <= 0)
            return null;

        return $"{path.ToLowerInvariant()}|{sizeBytes}|{lastWriteUtcTicks}";
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

    /// <summary>
    /// Look up a verdict without needing the file's hash, using path, size and
    /// timestamp. This is the lookup that actually saves work: it happens before
    /// the file is read at all.
    /// </summary>
    public CachedVerdict? TryGetByStamp(string path, long sizeBytes, long lastWriteUtcTicks, DateTimeOffset now)
    {
        if (StampKey(path, sizeBytes, lastWriteUtcTicks) is not { } stamp)
            return null;

        lock (_gate)
        {
            if (!_byStamp.TryGetValue(stamp, out var entry))
                return null;

            if (now - entry.EvaluatedAt > _ttl)
            {
                _byStamp.Remove(stamp);
                _byKey.Remove(entry.IdentityKey);
                return null;
            }

            return entry;
        }
    }

    public void Store(Verdict verdict, string? path = null, long lastWriteUtcTicks = 0)
    {
        if (verdict.Target.Sha256 is not { Length: > 0 })
            return;

        var entry = new CachedVerdict
        {
            IdentityKey = verdict.Target.IdentityKey,
            FileName = verdict.Target.FileName,
            Level = verdict.Level,
            Score = verdict.Score,
            EvaluatedAt = verdict.EvaluatedAt,
            Headline = verdict.Headline,
            Path = path ?? verdict.Target.Path,
            SizeBytes = verdict.Target.SizeBytes,
            LastWriteUtcTicks = lastWriteUtcTicks,
        };

        lock (_gate)
        {
            _byKey[entry.IdentityKey] = entry;

            if (StampKey(entry.Path, entry.SizeBytes, entry.LastWriteUtcTicks) is { } stamp)
                _byStamp[stamp] = entry;

            if (_byKey.Count > MaxEntries)
                Evict();

            if (++_pendingWrites >= WritesBetweenSaves)
                Save();
        }
    }

    /// <summary>Write anything buffered. Called when a scan finishes and at shutdown.</summary>
    public void Flush()
    {
        lock (_gate)
        {
            if (_pendingWrites > 0)
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
            _byStamp = new Dictionary<string, CachedVerdict>(StringComparer.OrdinalIgnoreCase);
            Save();
        }
    }

    /// <summary>Drop the oldest quarter, so eviction is not a per-insert cost.</summary>
    private void Evict()
    {
        var survivors = _byKey.Values
            .OrderByDescending(e => e.EvaluatedAt)
            .Take(MaxEntries * 3 / 4)
            .ToArray();

        _byKey = survivors.ToDictionary(e => e.IdentityKey, StringComparer.Ordinal);
        _byStamp = BuildStampIndex(survivors);
    }

    private void Save()
    {
        _pendingWrites = 0;
        _store.Save(new VerdictCacheState { RulesVersion = _rulesVersion, Entries = _byKey.Values.ToArray() });
    }
}
