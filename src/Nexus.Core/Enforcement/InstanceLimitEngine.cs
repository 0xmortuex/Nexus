using Nexus.Core.Models;

namespace Nexus.Core.Enforcement;

public sealed record InstanceLimit
{
    public required string ExeName { get; set; }
    public int MaxInstances { get; set; } = 1;
    public bool Enabled { get; set; } = true;

    public string NormalizedName => ProcessRule.Normalize(ExeName);
}

public sealed record RunningInstance(int Pid, string ExeName, DateTimeOffset StartedAt);

/// <summary>Pure selection: which PIDs to kill so at most MaxInstances of an exe
/// survive. Newest instances die first; ties broken by higher PID.</summary>
public static class InstanceLimitEngine
{
    public static IReadOnlyList<int> SelectPidsToKill(
        IEnumerable<RunningInstance> instances, InstanceLimit limit)
    {
        if (!limit.Enabled || limit.MaxInstances < 1)
            return [];

        var matching = instances
            .Where(i => string.Equals(ProcessRule.Normalize(i.ExeName), limit.NormalizedName, StringComparison.Ordinal))
            .OrderBy(i => i.StartedAt)
            .ThenBy(i => i.Pid)
            .ToList();

        if (matching.Count <= limit.MaxInstances)
            return [];

        return matching
            .Skip(limit.MaxInstances)
            .OrderByDescending(i => i.StartedAt)
            .ThenByDescending(i => i.Pid)
            .Select(i => i.Pid)
            .ToArray();
    }
}
