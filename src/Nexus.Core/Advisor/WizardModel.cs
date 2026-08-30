namespace Nexus.Core.Advisor;

public enum WizardStepId
{
    Welcome,
    Scan,
    Recommendations,
    Games,
    Security,
    Apply,
    Finish,
}

public sealed record WizardStep(WizardStepId Id, string Title, string Subtitle);

/// <summary>
/// The ordered steps of the first-run setup wizard (Hone-style guided flow). The
/// dynamic content of each step (the actual recommendations and detected games) is
/// gathered live by the app; this model just defines the sequence and copy, so the
/// step ordering and navigation are unit-testable.
/// </summary>
public static class WizardModel
{
    public static IReadOnlyList<WizardStep> Steps { get; } =
    [
        new(WizardStepId.Welcome, "Welcome to Nexus",
            "A quick guided setup. Nothing is changed until you approve it on the Apply step, and everything is reversible."),
        new(WizardStepId.Scan, "Scanning your system",
            "Reading your CPU layout, current tweaks and services to score where you stand today."),
        new(WizardStepId.Recommendations, "Recommended optimizations",
            "Ranked by real effectiveness. Uncheck anything you'd rather skip — each one shows its pros and cons."),
        new(WizardStepId.Games, "Your games",
            "Detected games and any you add get a per-game profile. Higher-rated profiles are more completely tuned."),
        new(WizardStepId.Security, "Security",
            "Nexus watches for malware and tells you what it finds — it never blocks or deletes on its own. One of these options writes files into your folders, so it is here rather than switched on quietly."),
        new(WizardStepId.Apply, "Apply your choices",
            "Review the summary, then apply. A System Restore point and registry backups are taken first."),
        new(WizardStepId.Finish, "All set",
            "Your system rating has been recalculated. You can re-run this wizard any time from Settings."),
    ];

    public static WizardStep Step(WizardStepId id) => Steps.First(s => s.Id == id);

    public static WizardStepId? Next(WizardStepId current)
    {
        var index = IndexOf(current);
        return index + 1 < Steps.Count ? Steps[index + 1].Id : null;
    }

    public static WizardStepId? Previous(WizardStepId current)
    {
        var index = IndexOf(current);
        return index > 0 ? Steps[index - 1].Id : null;
    }

    public static int IndexOf(WizardStepId id)
    {
        for (int i = 0; i < Steps.Count; i++)
            if (Steps[i].Id == id)
                return i;
        return 0;
    }
}
