using Nexus.App.Interop;
using Nexus.Core.GameMode;
using Nexus.Core.Logging;

namespace Nexus.App.Services;

/// <summary>
/// Runs once at startup: if intended-state.json is non-empty, the previous session
/// died mid-Game-Mode (crash or power loss). Everything it journaled is reverted —
/// process mutations, power plan, Windows Update — then the journal is cleared.
/// </summary>
public sealed class CrashRecoveryService
{
    private readonly IntendedStateJournal _journal;
    private readonly ProcessApi _api;
    private readonly PowerPlanService _power;
    private readonly ActivityLog _log;

    public CrashRecoveryService(IntendedStateJournal journal, ProcessApi api, PowerPlanService power, ActivityLog log)
    {
        _journal = journal;
        _api = api;
        _power = power;
        _log = log;
    }

    public void RecoverIfNeeded()
    {
        var pending = _journal.LoadPending();
        if (pending is null)
            return;

        _log.Warn("Recovery",
            $"The previous session ended unexpectedly{(pending.ActiveGameExe is null ? "" : $" while {pending.ActiveGameExe} was boosted")}. Restoring defaults.");

        foreach (var mutation in pending.Mutations)
            GameModeService.RevertMutation(mutation, _api, _log);

        if (pending.PreviousPowerPlanGuid is not null)
            _power.RestorePreviousPlan();

        if (pending.WindowsUpdatePaused)
            GameModeService.ResumeWindowsUpdate(_log);

        _journal.Clear();
        _log.Info("Recovery", "Crash recovery complete; all journaled changes were reverted.");
    }
}
