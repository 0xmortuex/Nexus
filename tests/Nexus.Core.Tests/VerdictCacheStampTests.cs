using Nexus.Core.Persistence;
using Nexus.Core.Security;
using Xunit;

namespace Nexus.Core.Tests;

/// <summary>
/// The fast path that makes the cache worth having: looking a verdict up by path,
/// size and timestamp, so a rescan does not re-read and re-hash an unchanged file.
/// </summary>
public class VerdictCacheStampTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nexus-cache-tests-").FullName;
    private static readonly DateTimeOffset Now = new(2026, 8, 30, 12, 0, 0, TimeSpan.Zero);

    private const string Path = @"C:\Program Files\App\app.exe";
    private const long Size = 4096;
    private static readonly long Stamp = new DateTime(2026, 1, 1).Ticks;

    private JsonStore<VerdictCacheState> NewBackingStore(string name = "cache.json") => new(
        System.IO.Path.Combine(_dir, name), NexusJsonContext.Default.VerdictCacheState,
        static () => new VerdictCacheState());

    private static Verdict VerdictFor(string sha, ThreatLevel level = ThreatLevel.Clean) =>
        new()
        {
            Target = ScanTarget.ForFile(Path, sha, Size),
            Level = level,
            Score = level == ThreatLevel.Clean ? 0 : 80,
            Signals = [],
            EvaluatedAt = Now,
        };

    [Fact]
    public void A_stored_verdict_is_found_again_by_stamp()
    {
        var cache = new VerdictCache(NewBackingStore(), "rules-v1");
        cache.Store(VerdictFor("aaa"), Path, Stamp);

        var hit = cache.TryGetByStamp(Path, Size, Stamp, Now);

        Assert.NotNull(hit);
        Assert.Equal(ThreatLevel.Clean, hit.Level);
    }

    [Fact]
    public void The_stamp_index_survives_a_reload()
    {
        var store = NewBackingStore();
        var cache = new VerdictCache(store, "rules-v1");
        cache.Store(VerdictFor("aaa"), Path, Stamp);
        cache.Flush();

        Assert.NotNull(new VerdictCache(store, "rules-v1").TryGetByStamp(Path, Size, Stamp, Now));
    }

    /// <summary>Writes are buffered, so an unflushed cache legitimately loses recent
    /// entries — they are recomputed, which is what a cache is allowed to do.</summary>
    [Fact]
    public void Buffered_writes_reach_disk_once_flushed()
    {
        var store = NewBackingStore("buffered.json");
        var cache = new VerdictCache(store, "rules-v1");
        cache.Store(VerdictFor("aaa"), Path, Stamp);

        Assert.Empty(store.Load().Entries);

        cache.Flush();
        Assert.Single(store.Load().Entries);
    }

    [Fact]
    public void A_long_run_of_writes_saves_without_an_explicit_flush()
    {
        var store = NewBackingStore("autosave.json");
        var cache = new VerdictCache(store, "rules-v1");

        for (int i = 0; i <= VerdictCache.WritesBetweenSaves; i++)
        {
            var path = $@"C:iles\g{i}.exe";
            cache.Store(new Verdict
            {
                Target = ScanTarget.ForFile(path, $"h{i}", Size),
                Level = ThreatLevel.Clean,
                Score = 0,
                Signals = [],
                EvaluatedAt = Now,
            }, path, Stamp);
        }

        Assert.NotEmpty(store.Load().Entries);
    }

    [Theory]
    [InlineData(Size + 1, 0)]   // size changed
    [InlineData(Size, 1)]       // timestamp changed
    public void A_changed_file_misses_the_cache(long size, int stampOffsetDays)
    {
        var cache = new VerdictCache(NewBackingStore(), "rules-v1");
        cache.Store(VerdictFor("aaa"), Path, Stamp);

        long stamp = Stamp + TimeSpan.FromDays(stampOffsetDays).Ticks;

        Assert.Null(cache.TryGetByStamp(Path, size, stamp, Now));
    }

    [Fact]
    public void A_different_path_misses_the_cache()
    {
        var cache = new VerdictCache(NewBackingStore(), "rules-v1");
        cache.Store(VerdictFor("aaa"), Path, Stamp);

        Assert.Null(cache.TryGetByStamp(@"C:\elsewhere\app.exe", Size, Stamp, Now));
    }

    [Fact]
    public void Paths_are_matched_case_insensitively_like_the_filesystem()
    {
        var cache = new VerdictCache(NewBackingStore(), "rules-v1");
        cache.Store(VerdictFor("aaa"), Path, Stamp);

        Assert.NotNull(cache.TryGetByStamp(Path.ToUpperInvariant(), Size, Stamp, Now));
    }

    [Fact]
    public void A_missing_timestamp_never_produces_a_hit()
    {
        var cache = new VerdictCache(NewBackingStore(), "rules-v1");
        cache.Store(VerdictFor("aaa"), Path, lastWriteUtcTicks: 0);

        Assert.Null(cache.TryGetByStamp(Path, Size, 0, Now));
    }

    [Fact]
    public void Stamp_hits_expire_with_the_ttl()
    {
        var cache = new VerdictCache(NewBackingStore(), "rules-v1", TimeSpan.FromDays(1));
        cache.Store(VerdictFor("aaa"), Path, Stamp);

        Assert.NotNull(cache.TryGetByStamp(Path, Size, Stamp, Now));
        Assert.Null(cache.TryGetByStamp(Path, Size, Stamp, Now.AddDays(2)));
    }

    /// <summary>A ruleset change must invalidate the fast path too, or an old "clean"
    /// would keep suppressing a detection the new rules would make.</summary>
    [Fact]
    public void A_ruleset_change_invalidates_the_stamp_index()
    {
        var store = NewBackingStore();
        var cache = new VerdictCache(store, "rules-v1");
        cache.Store(VerdictFor("aaa"), Path, Stamp);
        cache.Flush();

        Assert.Null(new VerdictCache(store, "rules-v2").TryGetByStamp(Path, Size, Stamp, Now));
    }

    [Fact]
    public void Invalidate_clears_the_stamp_index()
    {
        var cache = new VerdictCache(NewBackingStore(), "rules-v1");
        cache.Store(VerdictFor("aaa"), Path, Stamp);
        cache.Invalidate("rules-v2");

        Assert.Null(cache.TryGetByStamp(Path, Size, Stamp, Now));
    }

    [Fact]
    public void Rewriting_the_same_path_replaces_rather_than_duplicates()
    {
        var cache = new VerdictCache(NewBackingStore(), "rules-v1");
        cache.Store(VerdictFor("aaa"), Path, Stamp);
        cache.Store(VerdictFor("bbb", ThreatLevel.Malicious), Path, Stamp);

        var hit = cache.TryGetByStamp(Path, Size, Stamp, Now);

        Assert.NotNull(hit);
        Assert.Equal(ThreatLevel.Malicious, hit.Level);
    }

    [Fact]
    public void Eviction_keeps_the_two_indexes_consistent()
    {
        var cache = new VerdictCache(NewBackingStore(), "rules-v1");

        for (int i = 0; i < VerdictCache.MaxEntries + 200; i++)
        {
            var path = $@"C:\files\f{i}.exe";
            var verdict = new Verdict
            {
                Target = ScanTarget.ForFile(path, $"hash{i}", Size),
                Level = ThreatLevel.Clean,
                Score = 0,
                Signals = [],
                EvaluatedAt = Now.AddSeconds(i),
            };
            cache.Store(verdict, path, Stamp);
        }

        Assert.True(cache.Count <= VerdictCache.MaxEntries);

        // The newest entry must still be reachable by BOTH lookups after eviction.
        int newest = VerdictCache.MaxEntries + 199;
        var newestPath = $@"C:\files\f{newest}.exe";

        Assert.NotNull(cache.TryGetByStamp(newestPath, Size, Stamp, Now.AddSeconds(newest)));
        Assert.NotNull(cache.TryGet(ScanTarget.ForFile(newestPath, $"hash{newest}"), Now.AddSeconds(newest)));
    }

    [Theory]
    [InlineData(null, 0L)]
    [InlineData("", 100L)]
    public void An_unusable_stamp_key_is_refused(string? path, long ticks)
    {
        Assert.Null(VerdictCache.StampKey(path, Size, ticks));
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup.
        }
    }
}
