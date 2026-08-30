namespace Nexus.Core.Security;

/// <summary>What to do about an entry a crash left mid-move.</summary>
public enum ReconcileAction
{
    /// <summary>The file is in quarantine; record that and leave it there.</summary>
    MarkHeld,

    /// <summary>The file is back at its original path; the restore completed.</summary>
    MarkRestored,

    /// <summary>Nothing moved; the file is where it always was.</summary>
    MarkNeverMoved,

    /// <summary>A copy exists in both places. Keep the original, drop the duplicate.</summary>
    KeepOriginalAndDeleteQuarantineCopy,

    /// <summary>The file is in neither place. Something else took it.</summary>
    MarkMissing,
}

/// <summary>
/// Decides what an interrupted quarantine or restore actually left behind.
///
/// Pure, because this is the code that runs after a crash or a power cut and its job
/// is to not lose the user's file. It has to know which direction the move was
/// going: a Pending entry was on its way INTO quarantine, a Restoring entry was on
/// its way OUT, and "the file is at its original path" means opposite things in
/// those two cases — nothing happened in the first, everything worked in the second.
/// Treating them the same is how a successful restore ends up recorded as a failure.
///
/// Where the evidence is ambiguous, the rule is always to prefer the outcome that
/// keeps the file the user can see.
/// </summary>
public static class QuarantineReconciler
{
    public static ReconcileAction Decide(QuarantineStatus status, bool atOriginalPath, bool inQuarantine) =>
        (status, atOriginalPath, inQuarantine) switch
        {
            // Both copies survived an interrupted move, in either direction. Keep the
            // one at the original path, because that is the one the user can find.
            (_, true, true) => ReconcileAction.KeepOriginalAndDeleteQuarantineCopy,

            // Nowhere to be found. Not something to paper over.
            (_, false, false) => ReconcileAction.MarkMissing,

            // On its way into quarantine.
            (QuarantineStatus.Pending, true, false) => ReconcileAction.MarkNeverMoved,
            (QuarantineStatus.Pending, false, true) => ReconcileAction.MarkHeld,

            // On its way out. The same observation means the opposite thing here.
            (QuarantineStatus.Restoring, true, false) => ReconcileAction.MarkRestored,
            (QuarantineStatus.Restoring, false, true) => ReconcileAction.MarkHeld,

            // Any other status was already settled; report what is actually there.
            (_, false, true) => ReconcileAction.MarkHeld,
            (_, true, false) => ReconcileAction.MarkNeverMoved,
        };

    /// <summary>A sentence for the log, written from the file's point of view.</summary>
    public static string Describe(ReconcileAction action, string fileName) => action switch
    {
        ReconcileAction.MarkHeld =>
            $"{fileName} is in quarantine. You can restore it from the Security tab.",

        ReconcileAction.MarkRestored =>
            $"{fileName} was already put back before the interruption; nothing more to do.",

        ReconcileAction.MarkNeverMoved =>
            $"{fileName} was never moved and is exactly where it always was.",

        ReconcileAction.KeepOriginalAndDeleteQuarantineCopy =>
            $"{fileName} existed in both places after an interrupted move. The original was kept and " +
            "the duplicate removed.",

        ReconcileAction.MarkMissing =>
            $"{fileName} is in neither its original location nor quarantine. Something else moved or " +
            "deleted it.",

        _ => fileName,
    };
}
