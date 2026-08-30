using Nexus.Core.Persistence;
using Nexus.Core.Security;
using Xunit;

namespace Nexus.Core.Tests;

/// <summary>
/// Covers the promise that gives Sentinel its shape: nothing destructive happens
/// without a fresh, specific, single-use gesture from the user.
/// </summary>
public class SecurityConsentTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nexus-sentinel-tests-").FullName;
    private static readonly DateTimeOffset Now = new(2026, 8, 30, 12, 0, 0, TimeSpan.Zero);

    private static readonly ScanTarget Target = ScanTarget.ForFile(
        @"C:\Users\fadi\Downloads\thing.exe", "aaaa1111", 2048);

    private static readonly ScanTarget OtherTarget = ScanTarget.ForFile(
        @"C:\Users\fadi\Downloads\other.exe", "bbbb2222", 2048);

    private static Verdict MaliciousVerdict(ScanTarget target) => VerdictEngine.Evaluate(new VerdictInput
    {
        Target = target,
        Signals = [new SecuritySignal(SignalSource.Reputation, SignalWeight.Decisive, "known-bad", "test")],
    }, Now);

    private TrustStore NewTrustStore() => new(new JsonStore<TrustStoreState>(
        Path.Combine(_dir, "trusted.json"), NexusJsonContext.Default.TrustStoreState,
        static () => new TrustStoreState()));

    private QuarantineJournal NewJournal(string name = "quarantine.json") => new(new JsonStore<QuarantineState>(
        Path.Combine(_dir, name), NexusJsonContext.Default.QuarantineState,
        static () => new QuarantineState()));

    // ---- UserConsent ----

    [Fact]
    public void A_consent_redeems_once_and_only_once()
    {
        var consent = UserConsent.FromUserGesture("quarantine", Target.IdentityKey, Now);

        Assert.True(consent.TryRedeem("quarantine", Target.IdentityKey, Now));
        Assert.False(consent.TryRedeem("quarantine", Target.IdentityKey, Now));
        Assert.True(consent.IsRedeemed);
    }

    [Fact]
    public void A_consent_does_not_transfer_to_another_file()
    {
        var consent = UserConsent.FromUserGesture("quarantine", Target.IdentityKey, Now);
        Assert.False(consent.TryRedeem("quarantine", OtherTarget.IdentityKey, Now));
    }

    [Fact]
    public void A_consent_does_not_transfer_to_another_action()
    {
        var consent = UserConsent.FromUserGesture("quarantine", Target.IdentityKey, Now);
        Assert.False(consent.TryRedeem("delete", Target.IdentityKey, Now));
    }

    [Fact]
    public void A_stale_consent_is_refused()
    {
        var consent = UserConsent.FromUserGesture("quarantine", Target.IdentityKey, Now);
        Assert.False(consent.TryRedeem("quarantine", Target.IdentityKey, Now + UserConsent.Lifetime + TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public void A_consent_from_the_future_is_refused()
    {
        var consent = UserConsent.FromUserGesture("quarantine", Target.IdentityKey, Now);
        Assert.False(consent.TryRedeem("quarantine", Target.IdentityKey, Now - TimeSpan.FromMinutes(1)));
    }

    [Fact]
    public void Concurrent_redemption_still_only_succeeds_once()
    {
        var consent = UserConsent.FromUserGesture("quarantine", Target.IdentityKey, Now);
        int successes = 0;

        Parallel.For(0, 64, _ =>
        {
            if (consent.TryRedeem("quarantine", Target.IdentityKey, Now))
                Interlocked.Increment(ref successes);
        });

        Assert.Equal(1, successes);
    }

    // ---- TrustStore ----

    [Fact]
    public void Trust_requires_a_matching_consent()
    {
        var store = NewTrustStore();
        var wrongConsent = UserConsent.FromUserGesture("trust", OtherTarget.IdentityKey, Now);

        Assert.False(store.Trust(Target, wrongConsent, Now));
        Assert.False(store.IsTrusted(Target));
    }

    [Fact]
    public void Trust_persists_and_is_keyed_on_content_not_path()
    {
        var store = NewTrustStore();
        Assert.True(store.Trust(Target, UserConsent.FromUserGesture("trust", Target.IdentityKey, Now), Now));

        // Same bytes, different location: still trusted.
        var moved = ScanTarget.ForFile(@"D:\tools\renamed.exe", Target.Sha256);
        Assert.True(NewTrustStore().IsTrusted(moved));

        // Same location, different bytes: not trusted.
        var replaced = ScanTarget.ForFile(Target.Path!, "cccc3333");
        Assert.False(NewTrustStore().IsTrusted(replaced));
    }

    [Fact]
    public void Revoking_trust_needs_no_consent()
    {
        var store = NewTrustStore();
        store.Trust(Target, UserConsent.FromUserGesture("trust", Target.IdentityKey, Now), Now);

        Assert.True(store.Revoke(Target.IdentityKey));
        Assert.False(store.IsTrusted(Target));
    }

    // ---- QuarantineJournal ----

    [Fact]
    public void Quarantine_cannot_begin_without_consent_for_that_file()
    {
        var journal = NewJournal();
        var consent = UserConsent.FromUserGesture("quarantine", OtherTarget.IdentityKey, Now);

        Assert.Null(journal.BeginQuarantine(MaliciousVerdict(Target), _dir, consent, Now));
        Assert.Empty(journal.All());
    }

    [Fact]
    public void Quarantine_writes_the_intent_before_the_file_is_touched()
    {
        var journal = NewJournal();
        var entry = journal.BeginQuarantine(
            MaliciousVerdict(Target), _dir,
            UserConsent.FromUserGesture("quarantine", Target.IdentityKey, Now), Now);

        Assert.NotNull(entry);
        Assert.Equal(QuarantineStatus.Pending, entry.Status);

        // A crash right here must leave a recoverable record on disk.
        var reloaded = Assert.Single(NewJournal().Unresolved());
        Assert.Equal(entry.Id, reloaded.Id);
        Assert.Equal(Target.Path, reloaded.OriginalPath);
    }

    [Fact]
    public void The_quarantined_copy_never_keeps_an_executable_extension()
    {
        var journal = NewJournal();
        var entry = journal.BeginQuarantine(
            MaliciousVerdict(Target), _dir,
            UserConsent.FromUserGesture("quarantine", Target.IdentityKey, Now), Now);

        Assert.NotNull(entry);
        Assert.EndsWith(".quarantined", entry.QuarantinePath, StringComparison.Ordinal);
        Assert.DoesNotContain(".exe", entry.QuarantinePath, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_completed_quarantine_leaves_nothing_unresolved()
    {
        var journal = NewJournal();
        var entry = journal.BeginQuarantine(
            MaliciousVerdict(Target), _dir,
            UserConsent.FromUserGesture("quarantine", Target.IdentityKey, Now), Now)!;

        journal.MarkHeld(entry.Id);

        Assert.Empty(journal.Unresolved());
        Assert.Single(journal.Held());
    }

    [Fact]
    public void A_failed_move_is_recorded_and_holds_nothing()
    {
        var journal = NewJournal();
        var entry = journal.BeginQuarantine(
            MaliciousVerdict(Target), _dir,
            UserConsent.FromUserGesture("quarantine", Target.IdentityKey, Now), Now)!;

        journal.MarkFailed(entry.Id, "file was locked");

        Assert.Empty(journal.Held());
        Assert.Equal("file was locked", journal.Find(entry.Id)!.Error);
    }

    [Fact]
    public void Restore_is_journalled_and_needs_no_consent()
    {
        var journal = NewJournal();
        var entry = journal.BeginQuarantine(
            MaliciousVerdict(Target), _dir,
            UserConsent.FromUserGesture("quarantine", Target.IdentityKey, Now), Now)!;
        journal.MarkHeld(entry.Id);

        var restoring = journal.BeginRestore(entry.Id);
        Assert.NotNull(restoring);
        Assert.Equal(QuarantineStatus.Restoring, restoring.Status);
        Assert.Single(NewJournal().Unresolved());

        journal.MarkRestored(entry.Id);
        Assert.Empty(journal.Unresolved());
        Assert.Empty(journal.Held());
    }

    /// <summary>
    /// A restore that fails must leave the entry restorable. The file really is in
    /// quarantine at that point, and dropping it out of Held would strand it there
    /// under a meaningless name with no way for the user to ask for it back.
    /// </summary>
    [Fact]
    public void A_failed_restore_leaves_the_entry_still_held()
    {
        var journal = NewJournal("failed-restore.json");
        var entry = journal.BeginQuarantine(
            MaliciousVerdict(Target), _dir,
            UserConsent.FromUserGesture("quarantine", Target.IdentityKey, Now), Now)!;

        journal.MarkHeld(entry.Id);
        journal.BeginRestore(entry.Id);
        journal.MarkRestoreFailed(entry.Id, "the destination folder is read-only");

        var held = Assert.Single(journal.Held());
        Assert.Equal(entry.Id, held.Id);
        Assert.Equal("the destination folder is read-only", held.Error);

        // And it must be possible to try again.
        Assert.NotNull(journal.BeginRestore(entry.Id));
    }

    /// <summary>A failed restore is not the same as a failed quarantine: one leaves
    /// the file in quarantine, the other leaves it where it always was.</summary>
    [Fact]
    public void A_failed_quarantine_and_a_failed_restore_are_recorded_differently()
    {
        var journal = NewJournal("failure-modes.json");

        var failedQuarantine = journal.BeginQuarantine(
            MaliciousVerdict(Target), _dir,
            UserConsent.FromUserGesture("quarantine", Target.IdentityKey, Now), Now)!;
        journal.MarkFailed(failedQuarantine.Id, "locked");

        var failedRestore = journal.BeginQuarantine(
            MaliciousVerdict(OtherTarget), _dir,
            UserConsent.FromUserGesture("quarantine", OtherTarget.IdentityKey, Now), Now)!;
        journal.MarkHeld(failedRestore.Id);
        journal.MarkRestoreFailed(failedRestore.Id, "read-only");

        // The one that never moved is not held; the one still in quarantine is.
        var held = Assert.Single(journal.Held());
        Assert.Equal(failedRestore.Id, held.Id);
        Assert.Equal(QuarantineStatus.Failed, journal.Find(failedQuarantine.Id)!.Status);
    }

    [Fact]
    public void Marking_a_restore_failed_on_an_unknown_entry_is_harmless()
    {
        var journal = NewJournal("unknown-entry.json");
        journal.MarkRestoreFailed("no-such-id", "whatever");

        Assert.Empty(journal.All());
    }

    [Fact]
    public void Only_held_entries_can_be_restored()
    {
        var journal = NewJournal();
        var entry = journal.BeginQuarantine(
            MaliciousVerdict(Target), _dir,
            UserConsent.FromUserGesture("quarantine", Target.IdentityKey, Now), Now)!;

        // Still Pending — the file has not been moved yet, so there is nothing to put back.
        Assert.Null(journal.BeginRestore(entry.Id));
    }

    // ---- VerdictCache ----

    [Fact]
    public void Cached_verdicts_are_discarded_when_the_ruleset_changes()
    {
        var store = new JsonStore<VerdictCacheState>(
            Path.Combine(_dir, "cache.json"), NexusJsonContext.Default.VerdictCacheState,
            static () => new VerdictCacheState());

        var cache = new VerdictCache(store, "rules-v1");
        cache.Store(MaliciousVerdict(Target));
        cache.Flush(); // writes are buffered; a reload only sees what reached disk

        Assert.NotNull(new VerdictCache(store, "rules-v1").TryGet(Target, Now));
        Assert.Null(new VerdictCache(store, "rules-v2").TryGet(Target, Now));
    }

    [Fact]
    public void Cached_verdicts_expire()
    {
        var store = new JsonStore<VerdictCacheState>(
            Path.Combine(_dir, "cache-ttl.json"), NexusJsonContext.Default.VerdictCacheState,
            static () => new VerdictCacheState());
        var cache = new VerdictCache(store, "rules-v1", TimeSpan.FromDays(1));
        cache.Store(MaliciousVerdict(Target));

        Assert.NotNull(cache.TryGet(Target, Now));
        Assert.Null(cache.TryGet(Target, Now.AddDays(2)));
    }

    [Fact]
    public void Targets_without_a_hash_are_never_cached()
    {
        var store = new JsonStore<VerdictCacheState>(
            Path.Combine(_dir, "cache-nohash.json"), NexusJsonContext.Default.VerdictCacheState,
            static () => new VerdictCacheState());
        var cache = new VerdictCache(store, "rules-v1");

        var hashless = ScanTarget.ForProcess(1234, @"C:\gone.exe");
        cache.Store(MaliciousVerdict(hashless));

        Assert.Equal(0, cache.Count);
        Assert.Null(cache.TryGet(hashless, Now));
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
            // Test cleanup is best-effort.
        }
    }
}
