namespace Nexus.Core.Advisor;

/// <summary>One optimization the rating considers: whether it's active, weighted by
/// its honest effectiveness. Category groups related factors for the breakdown.</summary>
public sealed record RatingFactor(string Id, string Category, Effectiveness Effectiveness, bool Active);

public sealed record CategoryRating(string Category, int Score, int ActiveCount, int TotalCount);

public sealed record SystemRating(
    int Score,
    string Grade,
    string Summary,
    IReadOnlyList<CategoryRating> Categories);

/// <summary>
/// Overall system optimization score. Honest by construction: it measures "of the
/// impactful optimizations available, how much weighted value is currently active",
/// where weight = effectiveness. It is NOT a benchmark or a promise of FPS — it
/// reflects configuration completeness, and situational tweaks count for little so
/// the score can't be gamed by toggling low-value switches.
/// </summary>
public static class SystemRatingEngine
{
    public static SystemRating Rate(IReadOnlyList<RatingFactor> factors)
    {
        if (factors.Count == 0)
            return new SystemRating(0, "—", "Nothing to rate yet.", []);

        var categories = factors
            .GroupBy(f => f.Category)
            .Select(g =>
            {
                double total = g.Sum(f => (int)f.Effectiveness);
                double active = g.Where(f => f.Active).Sum(f => (int)f.Effectiveness);
                int score = total <= 0 ? 0 : (int)Math.Round(active / total * 100);
                return new CategoryRating(g.Key, score, g.Count(f => f.Active), g.Count());
            })
            .OrderBy(c => c.Category, StringComparer.Ordinal)
            .ToList();

        // Overall weights each category by the total effectiveness it carries, so a
        // category full of strong optimizations matters more than one of minor ones.
        double weightSum = 0, weighted = 0;
        foreach (var group in factors.GroupBy(f => f.Category))
        {
            double w = group.Sum(f => (int)f.Effectiveness);
            var cat = categories.First(c => c.Category == group.Key);
            weighted += cat.Score * w;
            weightSum += w;
        }
        int overall = weightSum <= 0 ? 0 : (int)Math.Round(weighted / weightSum);

        return new SystemRating(overall, GradeFor(overall), SummaryFor(overall), categories);
    }

    public static string GradeFor(int score) => score switch
    {
        >= 90 => "A",
        >= 80 => "B",
        >= 65 => "C",
        >= 50 => "D",
        _ => "F",
    };

    private static string SummaryFor(int score) => score switch
    {
        >= 90 => "Well tuned — the high-value optimizations are in place.",
        >= 80 => "Good shape. A few worthwhile optimizations remain.",
        >= 65 => "Decent baseline; several impactful options are still off.",
        >= 50 => "Lightly optimized — the wizard can walk you through the rest.",
        _ => "Mostly stock. Run the setup wizard to get the big wins first.",
    };
}
