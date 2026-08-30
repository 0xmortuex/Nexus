namespace Nexus.Core.Security;

/// <summary>
/// Proof that a human asked for one specific destructive action, right now.
///
/// This exists to make "Sentinel never acts on its own" a property of the code
/// rather than a promise in the README. Every API in Nexus that quarantines,
/// deletes or kills on security grounds takes one of these, and the only way to
/// obtain one is <see cref="FromUserGesture"/> — which must be called from a UI
/// event handler, never from a scanning or monitoring loop.
///
/// A consent is bound to one target, expires quickly, and is single-use, so it
/// cannot be minted during a scan and replayed against a later detection.
/// </summary>
public sealed class UserConsent
{
    /// <summary>A consent older than this is refused; the user's intent has gone stale.</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    private int _redeemed;

    private UserConsent(string action, string identityKey, DateTimeOffset grantedAt)
    {
        Action = action;
        IdentityKey = identityKey;
        GrantedAt = grantedAt;
    }

    /// <summary>What the user agreed to ("quarantine", "delete", "terminate").</summary>
    public string Action { get; }

    /// <summary>The <see cref="ScanTarget.IdentityKey"/> the user agreed to act on.</summary>
    public string IdentityKey { get; }

    public DateTimeOffset GrantedAt { get; }

    /// <summary>
    /// Mint a consent token. Call this ONLY from code running in direct response to
    /// a user gesture — a button click, a menu item, a notification action.
    /// </summary>
    public static UserConsent FromUserGesture(string action, string identityKey, DateTimeOffset now) =>
        new(action, identityKey, now);

    /// <summary>
    /// Consume the consent for one action against one target. Returns false — and
    /// the caller must then do nothing — if the consent is for a different target,
    /// a different action, has expired, or has already been used.
    /// </summary>
    public bool TryRedeem(string action, string identityKey, DateTimeOffset now)
    {
        if (!string.Equals(Action, action, StringComparison.Ordinal))
            return false;
        if (!string.Equals(IdentityKey, identityKey, StringComparison.Ordinal))
            return false;
        if (now - GrantedAt > Lifetime || now < GrantedAt)
            return false;

        // Single-use: the first redeemer wins, every later attempt is refused.
        return Interlocked.Exchange(ref _redeemed, 1) == 0;
    }

    public bool IsRedeemed => Volatile.Read(ref _redeemed) != 0;
}
