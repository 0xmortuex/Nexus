using Microsoft.Win32;
using Nexus.App.TweaksImpl;
using Nexus.Core.GameMode;
using Nexus.Core.Logging;
using Nexus.Core.Persistence;
using Nexus.Core.Suggestions;

namespace Nexus.App.Services;

/// <summary>
/// The Hone-style "suggested optimizations" panel: collects the machine's real
/// state into a SystemFacts, runs the pure SuggestionEngine, and applies a chosen
/// suggestion by routing it to the service that already owns that change (tweaks
/// back up + undo, debloat disables reversibly, features flip settings).
/// Nothing is applied without an explicit click.
/// </summary>
public sealed class SuggestionService
{
    private readonly TweakService _tweaks;
    private readonly DebloatService _debloat;
    private readonly SettingsService _settings;
    private readonly GameProfileRepository _games;
    private readonly PowerPlanService _power;
    private readonly Interop.CpuTopologyProvider _topology;
    private readonly ActivityLog _log;

    public SuggestionService(
        TweakService tweaks,
        DebloatService debloat,
        SettingsService settings,
        GameProfileRepository games,
        PowerPlanService power,
        Interop.CpuTopologyProvider topology,
        ActivityLog log)
    {
        _tweaks = tweaks;
        _debloat = debloat;
        _settings = settings;
        _games = games;
        _power = power;
        _topology = topology;
        _log = log;
    }

    public IReadOnlyList<Suggestion> GetSuggestions() => SuggestionEngine.Evaluate(CollectFacts());

    private SystemFacts CollectFacts()
    {
        var settings = _settings.Current;
        return new SystemFacts
        {
            GameDvrCaptureEnabled = !_tweaks.IsApplied("gamedvr-off"),
            MouseAccelerationEnabled = !_tweaks.IsApplied("mouse-accel-off"),
            WindowsGameModeEnabled = _tweaks.IsApplied("windows-game-mode-on")
                                     || ReadDword(Registry.CurrentUser, @"SOFTWARE\Microsoft\GameBar", "AutoGameModeEnabled") == 1,
            StickyKeysShortcutEnabled = !_tweaks.IsApplied("sticky-keys-off"),
            DiagTrackEnabled = !_debloat.IsServiceDisabled("DiagTrack"),
            CompatAppraiserTaskEnabled = !_debloat.IsTaskDisabledByNexus(
                @"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"),
            ProBalanceEnabled = settings.ProBalance.Enabled,
            GameModeEnabled = settings.GameMode.Enabled,
            IsHybridCpu = _topology.Topology.IsHybrid,
            GameProfileCount = _games.All().Count,
            NexusPerformancePlanExists = settings.Power.PerformancePlanGuid is not null,
        };
    }

    /// <summary>Apply one suggestion. Returns false + error for actionable kinds;
    /// Hint suggestions have no action and return true.</summary>
    public bool Apply(Suggestion suggestion, out string? error)
    {
        error = null;
        switch (suggestion.Kind)
        {
            case SuggestionKind.ApplyTweak:
                return _tweaks.Apply(suggestion.TargetId, out error);

            case SuggestionKind.DisableService:
                return _debloat.DisableService(suggestion.TargetId, out error);

            case SuggestionKind.DisableTask:
                return _debloat.DisableTask(suggestion.TargetId, out error);

            case SuggestionKind.EnableFeature:
                return ApplyFeature(suggestion.TargetId, out error);

            case SuggestionKind.Hint:
                return true; // guidance only

            default:
                error = "unknown suggestion kind";
                return false;
        }
    }

    private bool ApplyFeature(string feature, out string? error)
    {
        error = null;
        switch (feature)
        {
            case "probalance":
                _settings.Update(s => s with { ProBalance = s.ProBalance with { Enabled = true } });
                _log.Info("Suggestions", "Enabled ProBalance from a suggestion.");
                return true;
            case "gamemode":
                _settings.Update(s => s with { GameMode = s.GameMode with { Enabled = true } });
                _log.Info("Suggestions", "Enabled Game Mode from a suggestion.");
                return true;
            case "perfplan":
                if (_power.EnsurePerformancePlan() is not null)
                    return true;
                error = "could not create the performance power plan";
                return false;
            default:
                error = $"unknown feature {feature}";
                return false;
        }
    }

    private static int? ReadDword(RegistryKey root, string subKey, string name)
    {
        using var key = root.OpenSubKey(subKey);
        return key?.GetValue(name) as int?;
    }
}
