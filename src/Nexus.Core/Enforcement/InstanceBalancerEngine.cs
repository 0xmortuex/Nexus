using Nexus.Core.Models;

namespace Nexus.Core.Enforcement;

public sealed record InstanceBalanceAssignment(int Pid, ulong AffinityMask);

/// <summary>
/// Pure allocation for the Instance Balancer: given several running instances of the
/// same exe and the machine's core count, split the cores evenly between instances
/// so identical processes stop fighting over the same cores. Deterministic in PID
/// order so the same set of instances always maps to the same layout.
/// </summary>
public static class InstanceBalancerEngine
{
    /// <param name="instances">PIDs of the same-named process, any order.</param>
    /// <param name="allCoresMask">Group-0 affinity mask of usable logical processors.</param>
    public static IReadOnlyList<InstanceBalanceAssignment> Balance(
        IReadOnlyList<int> instances, ulong allCoresMask)
    {
        var pids = instances.Distinct().OrderBy(p => p).ToArray();
        if (pids.Length < 2 || allCoresMask == 0)
            return [];

        var coreBits = new List<int>();
        for (int bit = 0; bit < 64; bit++)
            if ((allCoresMask & (1UL << bit)) != 0)
                coreBits.Add(bit);

        int coreCount = coreBits.Count;
        // If there are fewer cores than instances, some instances share a single core.
        int perInstance = Math.Max(1, coreCount / pids.Length);

        var assignments = new List<InstanceBalanceAssignment>(pids.Length);
        for (int i = 0; i < pids.Length; i++)
        {
            ulong mask = 0;
            for (int j = 0; j < perInstance; j++)
            {
                int index = (i * perInstance + j) % coreCount;
                mask |= 1UL << coreBits[index];
            }
            assignments.Add(new InstanceBalanceAssignment(pids[i], mask));
        }
        return assignments;
    }
}
