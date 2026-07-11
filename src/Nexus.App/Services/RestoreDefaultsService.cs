using Nexus.App.TweaksImpl;
using Nexus.Core.GameMode;
using Nexus.Core.Logging;
using Nexus.Core.Rules;

namespace Nexus.App.Services;

/// <summary>
/// The "Restore all defaults" button: undoes every tweak from the state store,
/// re-enables debloated services/tasks, reverts any pending game-mode journal,
/// removes the Nexus power plan, clears all process rules, and disables autostart.
/// </summary>
public sealed class RestoreDefaultsService
{
    private readonly TweakService _tweaks;
    private readonly DebloatService _debloat;
    private readonly GameModeService _gameMode;
    private readonly CrashRecoveryService _recovery;
    private readonly PowerPlanService _power;
    private readonly RulesRepository _rules;
    private readonly GameProfileRepository _games;
    private readonly AutostartService _autostart;
    private readonly KeepAwakeService _keepAwake;
    private readonly DnsService _dns;
    private readonly ActivityLog _log;

    public RestoreDefaultsService(
        TweakService tweaks,
        DebloatService debloat,
        GameModeService gameMode,
        CrashRecoveryService recovery,
        PowerPlanService power,
        RulesRepository rules,
        GameProfileRepository games,
        AutostartService autostart,
        KeepAwakeService keepAwake,
        DnsService dns,
        ActivityLog log)
    {
        _tweaks = tweaks;
        _debloat = debloat;
        _gameMode = gameMode;
        _recovery = recovery;
        _power = power;
        _rules = rules;
        _games = games;
        _autostart = autostart;
        _keepAwake = keepAwake;
        _dns = dns;
        _log = log;
    }

    /// <summary>Returns a list of anything that could not be restored.</summary>
    public IReadOnlyList<string> RestoreEverything()
    {
        _log.Info("Restore", "Restoring all defaults…");
        var failures = new List<string>();

        _gameMode.EndManually();
        _recovery.RecoverIfNeeded();

        failures.AddRange(_tweaks.UndoAll());
        _debloat.RestoreAll();
        _power.DeletePerformancePlan();
        _keepAwake.SetEnabled(false);

        if (_dns.HasAppliedCustomDns && !_dns.Restore(out var dnsError) && dnsError is not null)
            failures.Add($"DNS: {dnsError}");

        _rules.Clear();
        foreach (var game in _games.All().ToArray())
            _games.Remove(game.ExeName);

        if (_autostart.IsEnabled())
            _autostart.SetEnabled(false);

        _log.Info("Restore",
            failures.Count == 0
                ? "All defaults restored: tweaks undone, services/tasks re-enabled, rules cleared, power plan removed."
                : $"Defaults restored with {failures.Count} item(s) needing attention.");
        return failures;
    }
}
