using Nexus.Core.Persistence;

namespace Nexus.Core.Security;

/// <summary>One "yes, I know what this is" from the user.</summary>
/// <param name="IdentityKey">A <see cref="ScanTarget.IdentityKey"/> — normally the
/// content hash, so editing or replacing the file silently revokes the trust.</param>
public sealed record TrustDecision(
    string IdentityKey,
    string DisplayName,
    DateTimeOffset DecidedAt,
    string? Note = null);

public sealed record TrustStoreState
{
    public IReadOnlyList<TrustDecision> Decisions { get; init; } = [];
}

/// <summary>
/// The user's own allowlist. Sentinel keeps reporting on trusted files — the verdict
/// still shows every signal — it just stops raising alerts about them.
///
/// Trust is keyed on content, never on path or file name, so dropping a different
/// binary at a trusted path does not inherit the trust.
/// </summary>
public sealed class TrustStore
{
    private readonly JsonStore<TrustStoreState> _store;
    private readonly Dictionary<string, TrustDecision> _byKey;
    private readonly object _gate = new();

    public event Action? Changed;

    public TrustStore(NexusPaths paths)
        : this(new JsonStore<TrustStoreState>(
            paths.SecurityTrustFile, NexusJsonContext.Default.TrustStoreState, static () => new TrustStoreState()))
    {
    }

    public TrustStore(JsonStore<TrustStoreState> store)
    {
        _store = store;
        _byKey = new Dictionary<string, TrustDecision>(StringComparer.Ordinal);
        foreach (var decision in _store.Load().Decisions)
            _byKey[decision.IdentityKey] = decision;
    }

    public bool IsTrusted(ScanTarget target)
    {
        lock (_gate)
        {
            return _byKey.ContainsKey(target.IdentityKey);
        }
    }

    public IReadOnlyList<TrustDecision> All()
    {
        lock (_gate)
        {
            return _byKey.Values.OrderByDescending(d => d.DecidedAt).ToArray();
        }
    }

    /// <summary>
    /// Record that the user vouched for this file. Requires consent because an
    /// allowlist entry is a security decision with lasting effect — it must come
    /// from a person, never from a scanning loop deciding something looked fine.
    /// </summary>
    public bool Trust(ScanTarget target, UserConsent consent, DateTimeOffset now, string? note = null)
    {
        if (!consent.TryRedeem("trust", target.IdentityKey, now))
            return false;

        lock (_gate)
        {
            _byKey[target.IdentityKey] = new TrustDecision(
                target.IdentityKey, target.FileName, now, note);
            Save();
        }
        Changed?.Invoke();
        return true;
    }

    /// <summary>Withdrawing trust needs no consent token: it only ever adds scrutiny.</summary>
    public bool Revoke(string identityKey)
    {
        bool removed;
        lock (_gate)
        {
            removed = _byKey.Remove(identityKey);
            if (removed)
                Save();
        }
        if (removed)
            Changed?.Invoke();
        return removed;
    }

    public void Clear()
    {
        lock (_gate)
        {
            _byKey.Clear();
            Save();
        }
        Changed?.Invoke();
    }

    private void Save() => _store.Save(new TrustStoreState { Decisions = _byKey.Values.ToArray() });
}
