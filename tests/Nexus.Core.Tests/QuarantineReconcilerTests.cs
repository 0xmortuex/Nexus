using Nexus.Core.Security;
using Xunit;

namespace Nexus.Core.Tests;

/// <summary>
/// This is the code that runs after a crash or a power cut, deciding what happened
/// to a file that was being moved. Getting it wrong either loses the file or lies
/// about where it is, so every combination is enumerated.
/// </summary>
public class QuarantineReconcilerTests
{
    // ---- Interrupted on the way INTO quarantine ----

    [Fact]
    public void A_pending_quarantine_whose_file_never_moved_is_recorded_as_never_moved()
    {
        Assert.Equal(
            ReconcileAction.MarkNeverMoved,
            QuarantineReconciler.Decide(QuarantineStatus.Pending, atOriginalPath: true, inQuarantine: false));
    }

    [Fact]
    public void A_pending_quarantine_whose_file_did_move_is_recorded_as_held()
    {
        Assert.Equal(
            ReconcileAction.MarkHeld,
            QuarantineReconciler.Decide(QuarantineStatus.Pending, atOriginalPath: false, inQuarantine: true));
    }

    // ---- Interrupted on the way OUT ----

    /// <summary>
    /// The case the old code got wrong. The same observation — the file is at its
    /// original path — means "nothing happened" for a quarantine and "it worked" for
    /// a restore.
    /// </summary>
    [Fact]
    public void A_restore_that_completed_before_the_crash_is_recorded_as_restored()
    {
        Assert.Equal(
            ReconcileAction.MarkRestored,
            QuarantineReconciler.Decide(QuarantineStatus.Restoring, atOriginalPath: true, inQuarantine: false));
    }

    [Fact]
    public void A_restore_that_had_not_started_leaves_the_file_held()
    {
        Assert.Equal(
            ReconcileAction.MarkHeld,
            QuarantineReconciler.Decide(QuarantineStatus.Restoring, atOriginalPath: false, inQuarantine: true));
    }

    [Fact]
    public void The_same_observation_means_opposite_things_in_the_two_directions()
    {
        var duringQuarantine = QuarantineReconciler.Decide(QuarantineStatus.Pending, true, false);
        var duringRestore = QuarantineReconciler.Decide(QuarantineStatus.Restoring, true, false);

        Assert.NotEqual(duringQuarantine, duringRestore);
    }

    // ---- Ambiguous evidence ----

    [Theory]
    [InlineData(QuarantineStatus.Pending)]
    [InlineData(QuarantineStatus.Restoring)]
    [InlineData(QuarantineStatus.Held)]
    public void Two_copies_always_keep_the_one_the_user_can_find(QuarantineStatus status)
    {
        Assert.Equal(
            ReconcileAction.KeepOriginalAndDeleteQuarantineCopy,
            QuarantineReconciler.Decide(status, atOriginalPath: true, inQuarantine: true));
    }

    [Theory]
    [InlineData(QuarantineStatus.Pending)]
    [InlineData(QuarantineStatus.Restoring)]
    [InlineData(QuarantineStatus.Held)]
    public void A_file_in_neither_place_is_reported_missing_rather_than_papered_over(QuarantineStatus status)
    {
        Assert.Equal(
            ReconcileAction.MarkMissing,
            QuarantineReconciler.Decide(status, atOriginalPath: false, inQuarantine: false));
    }

    // ---- Totality ----

    [Fact]
    public void Every_combination_of_status_and_evidence_has_a_decision()
    {
        foreach (QuarantineStatus status in Enum.GetValues<QuarantineStatus>())
        {
            foreach (bool atOrigin in new[] { true, false })
            {
                foreach (bool inQuarantine in new[] { true, false })
                {
                    var action = QuarantineReconciler.Decide(status, atOrigin, inQuarantine);
                    Assert.True(Enum.IsDefined(action), $"{status}/{atOrigin}/{inQuarantine} produced {action}");
                }
            }
        }
    }

    [Fact]
    public void Every_action_has_a_sentence_naming_the_file()
    {
        foreach (ReconcileAction action in Enum.GetValues<ReconcileAction>())
        {
            var message = QuarantineReconciler.Describe(action, "invoice.pdf.exe");

            Assert.Contains("invoice.pdf.exe", message, StringComparison.Ordinal);
            Assert.True(message.Length > 20, $"{action} has no real explanation");
        }
    }
}
