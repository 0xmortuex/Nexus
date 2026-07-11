using Nexus.Core.GameMode;

namespace Nexus.Core.Advisor;

public sealed record GameRatingAspect(string Name, bool Active, string Note);

public sealed record GameRating(
    string ExeName,
    int Score,
    string Grade,
    IReadOnlyList<GameRatingAspect> Aspects);

/// <summary>
/// Per-game optimization rating: how completely a detected game's profile is set up,
/// scored against what actually helps that game. Weighted so the high-value aspects
/// (priority, core pinning on a hybrid CPU, power plan) dominate and cosmetic ones
/// count little — the same honesty rule as the system rating.
/// </summary>
public static class GameRatingEngine
{
    public static GameRating Rate(GameProfile profile, bool isHybridCpu)
    {
        var aspects = new List<(GameRatingAspect Aspect, int Weight)>();

        bool highPriority = profile.Priority is Models.ProcessPriority.High or Models.ProcessPriority.AboveNormal;
        aspects.Add((new GameRatingAspect("Raised priority",
            highPriority,
            highPriority ? $"Launches at {profile.Priority}" : "Runs at default priority"), 4));

        bool pinned = profile.Pinning != Models.CpuAffinityMode.None;
        aspects.Add((new GameRatingAspect(
            isHybridCpu ? "Pinned to P-cores" : "Pinned to physical cores",
            pinned,
            pinned
                ? (profile.UseCpuSets ? "Soft CPU-set pinning (anti-cheat friendly)" : "Hard affinity pinning")
                : "Not pinned — the scheduler may move it onto E-cores"),
            isHybridCpu ? 4 : 3));

        aspects.Add((new GameRatingAspect("Background hogs demoted",
            profile.DemoteBackgroundHogs,
            profile.DemoteBackgroundHogs ? "Other CPU users drop to BelowNormal + EcoQoS" : "Background apps keep full priority"), 3));

        aspects.Add((new GameRatingAspect("Performance power plan",
            profile.UsePerformancePowerPlan,
            profile.UsePerformancePowerPlan ? "Core parking off, clocks held high" : "Uses the current power plan"), 3));

        aspects.Add((new GameRatingAspect("Pause Windows Update",
            profile.PauseWindowsUpdate,
            profile.PauseWindowsUpdate ? "Update service paused while playing" : "Windows Update may run mid-session"), 1));

        double total = aspects.Sum(a => a.Weight);
        double active = aspects.Where(a => a.Aspect.Active).Sum(a => a.Weight);
        int score = total <= 0 ? 0 : (int)Math.Round(active / total * 100);

        return new GameRating(profile.ExeName, score, SystemRatingEngine.GradeFor(score),
            aspects.Select(a => a.Aspect).ToList());
    }
}
