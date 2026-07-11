using Nexus.App.Interop;
using Nexus.App.TweaksImpl;
using Nexus.Core.Advisor;
using Nexus.Core.GameMode;
using Nexus.Core.Persistence;

namespace Nexus.App.Services;

/// <summary>
/// Turns live app/system state into the honest rating factors the rating engine
/// consumes, and rates each detected game. Only "recommended-direction"
/// optimizations count — A/B variants (e.g. the two HAGS toggles) are not double
/// counted, and per-process actions like the CPU limiter don't inflate a global score.
/// </summary>
public sealed class RatingService
{
    private readonly TweakService _tweaks;
    private readonly DebloatService _debloat;
    private readonly DnsService _dns;
    private readonly SettingsService _settings;
    private readonly GameProfileRepository _games;
    private readonly CpuTopologyProvider _topology;
    private readonly Func<bool> _keepAwakeEnabled;

    /// <summary>id → coarse category shown in the breakdown.</summary>
    private static readonly IReadOnlyList<(string Id, string Category)> RatedTweaks =
    [
        ("mouse-accel-off", "Latency"),
        ("gamedvr-off", "Gaming"),
        ("windows-game-mode-on", "Gaming"),
        ("power-throttling-off", "Gaming"),
        ("mmcss-gaming", "Gaming"),
        ("priosep-gaming-short", "Gaming"),
        ("nagle-off", "Network"),
        ("network-throttling-off", "Network"),
        ("sticky-keys-off", "Responsiveness"),
        ("animations-off", "Responsiveness"),
        ("hibernation-off", "System"),
    ];

    public RatingService(
        TweakService tweaks,
        DebloatService debloat,
        DnsService dns,
        SettingsService settings,
        GameProfileRepository games,
        CpuTopologyProvider topology,
        Func<bool> keepAwakeEnabled)
    {
        _tweaks = tweaks;
        _debloat = debloat;
        _dns = dns;
        _settings = settings;
        _games = games;
        _topology = topology;
        _keepAwakeEnabled = keepAwakeEnabled;
    }

    public SystemRating RateSystem()
    {
        var s = _settings.Current;
        var factors = new List<RatingFactor>
        {
            new("probalance", "Responsiveness", OptimizationCatalog.EffectivenessOf("probalance"), s.ProBalance.Enabled),
            new("gamemode", "Gaming", OptimizationCatalog.EffectivenessOf("gamemode"), s.GameMode.Enabled),
            new("performanceplan", "Gaming", OptimizationCatalog.EffectivenessOf("performanceplan"), s.Power.PerformancePlanGuid is not null),
            new("foregroundboost", "Responsiveness", OptimizationCatalog.EffectivenessOf("foregroundboost"), s.ForegroundBoost),
            new("dns", "Network", OptimizationCatalog.EffectivenessOf("dns"), _dns.HasAppliedCustomDns),
            new("diagtrack", "Privacy", Effectiveness.Moderate, _debloat.IsServiceDisabled("DiagTrack")),
        };

        foreach (var (id, category) in RatedTweaks)
            factors.Add(new RatingFactor(id, category, OptimizationCatalog.EffectivenessOf(id), _tweaks.IsApplied(id)));

        _ = _keepAwakeEnabled; // reserved; keep-awake is a convenience, not a rated optimization
        return SystemRatingEngine.Rate(factors);
    }

    public IReadOnlyList<GameRating> RateGames()
        => _games.All()
            .OrderBy(p => p.ExeName)
            .Select(p => GameRatingEngine.Rate(p, _topology.Topology.IsHybrid))
            .ToArray();

    public GameRating RateGame(GameProfile profile)
        => GameRatingEngine.Rate(profile, _topology.Topology.IsHybrid);
}
