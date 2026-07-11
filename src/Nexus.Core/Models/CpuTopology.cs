namespace Nexus.Core.Models;

/// <summary>One logical processor (hardware thread).</summary>
/// <param name="Group">Processor group (0 on machines with ≤64 logical processors).</param>
/// <param name="IndexInGroup">Bit index within the group's affinity mask.</param>
/// <param name="PhysicalCoreId">Ordinal of the physical core this thread belongs to.</param>
/// <param name="EfficiencyClass">Higher = more performant. On hybrid Intel CPUs P-cores
/// report a higher class than E-cores; homogeneous CPUs report 0 for all.</param>
/// <param name="IsSmtSibling">True for every hardware thread of a core except its first.</param>
/// <param name="CpuSetId">The CPU set ID used by SetProcessDefaultCpuSets (0 if unknown).</param>
public sealed record LogicalCpu(
    int Group,
    int IndexInGroup,
    int PhysicalCoreId,
    byte EfficiencyClass,
    bool IsSmtSibling,
    uint CpuSetId);

/// <summary>
/// Immutable snapshot of the machine's CPU layout with the derived masks the rest of
/// the app needs. All masks refer to processor group 0; machines with more than 64
/// logical processors fall back to "no restriction" for the extra groups.
/// </summary>
public sealed class CpuTopology
{
    public IReadOnlyList<LogicalCpu> LogicalCpus { get; }
    public byte MaxEfficiencyClass { get; }
    public bool IsHybrid { get; }
    public int PhysicalCoreCount { get; }

    /// <summary>Affinity mask of all group-0 logical processors.</summary>
    public ulong AllCpusMask { get; }
    /// <summary>Group-0 logical processors whose efficiency class is the maximum (P-cores).</summary>
    public ulong PCoreMask { get; }
    /// <summary>Group-0 logical processors below the maximum efficiency class (E-cores).</summary>
    public ulong ECoreMask { get; }
    /// <summary>First hardware thread of each group-0 physical core (SMT siblings excluded).</summary>
    public ulong PhysicalCoreMask { get; }

    public CpuTopology(IReadOnlyList<LogicalCpu> logicalCpus)
    {
        LogicalCpus = logicalCpus;
        MaxEfficiencyClass = logicalCpus.Count == 0 ? (byte)0 : logicalCpus.Max(c => c.EfficiencyClass);
        IsHybrid = logicalCpus.Select(c => c.EfficiencyClass).Distinct().Count() > 1;
        PhysicalCoreCount = logicalCpus.Select(c => c.PhysicalCoreId).Distinct().Count();

        ulong all = 0, p = 0, e = 0, phys = 0;
        foreach (var cpu in logicalCpus.Where(c => c.Group == 0))
        {
            var bit = 1UL << cpu.IndexInGroup;
            all |= bit;
            if (cpu.EfficiencyClass == MaxEfficiencyClass) p |= bit; else e |= bit;
            if (!cpu.IsSmtSibling) phys |= bit;
        }

        AllCpusMask = all;
        PCoreMask = p;
        ECoreMask = e;
        PhysicalCoreMask = phys;
    }

    /// <summary>Resolve an affinity mode to a concrete group-0 affinity mask.
    /// Returns null when the mode imposes no restriction (or would leave zero CPUs).</summary>
    public ulong? MaskFor(CpuAffinityMode mode, ulong? customMask = null)
    {
        var mask = mode switch
        {
            CpuAffinityMode.PCoresOnly => PCoreMask,
            CpuAffinityMode.ECoresOnly => ECoreMask,
            CpuAffinityMode.PhysicalCoresOnly => PhysicalCoreMask,
            CpuAffinityMode.CustomMask => (customMask ?? 0) & AllCpusMask,
            _ => 0UL,
        };
        return mask == 0 ? null : mask;
    }

    /// <summary>Resolve an affinity mode to CPU set IDs. Returns null when the mode
    /// imposes no restriction or CPU set IDs are unavailable.</summary>
    public IReadOnlyList<uint>? CpuSetIdsFor(CpuAffinityMode mode, ulong? customMask = null)
    {
        var mask = MaskFor(mode, customMask);
        if (mask is null)
            return null;

        var ids = LogicalCpus
            .Where(c => c.Group == 0 && c.CpuSetId != 0 && (mask.Value & (1UL << c.IndexInGroup)) != 0)
            .Select(c => c.CpuSetId)
            .ToArray();
        return ids.Length == 0 ? null : ids;
    }
}
