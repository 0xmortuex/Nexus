using Nexus.Core.Models;
using Nexus.Core.Topology;
using Xunit;

namespace Nexus.Core.Tests;

public class LogicalProcessorInfoParserTests
{
    /// <summary>Layout modeled on an i7-12700K: 8 P-cores with SMT (class 1) + 4 E-cores (class 0).</summary>
    private static byte[] HybridBuffer()
    {
        var builder = new GlpieBufferBuilder();
        for (int core = 0; core < 8; core++)
            builder.AddCore(efficiencyClass: 1, mask: 0b11UL << (core * 2), smt: true);
        for (int core = 0; core < 4; core++)
            builder.AddCore(efficiencyClass: 0, mask: 1UL << (16 + core));
        builder.AddIrrelevantRecord(relationship: 2); // a RelationCache record to skip
        return builder.Build();
    }

    [Fact]
    public void Hybrid_cpu_classifies_p_and_e_cores()
    {
        var topology = LogicalProcessorInfoParser.Parse(HybridBuffer());

        Assert.True(topology.IsHybrid);
        Assert.Equal(12, topology.PhysicalCoreCount);
        Assert.Equal(20, topology.LogicalCpus.Count);
        Assert.Equal(0xFFFFUL, topology.PCoreMask);          // 16 SMT threads on P-cores
        Assert.Equal(0xF0000UL, topology.ECoreMask);         // 4 E-cores
        Assert.Equal(0xFFFFFUL, topology.AllCpusMask);
    }

    [Fact]
    public void Physical_core_mask_excludes_smt_siblings_but_keeps_e_cores()
    {
        var topology = LogicalProcessorInfoParser.Parse(HybridBuffer());

        // First thread of each P-core (even bits 0..15) + all E-cores (bits 16..19).
        Assert.Equal(0xF5555UL, topology.PhysicalCoreMask);
    }

    [Fact]
    public void Homogeneous_smt_cpu_is_not_hybrid_and_p_mask_is_everything()
    {
        var builder = new GlpieBufferBuilder();
        for (int core = 0; core < 8; core++)
            builder.AddCore(efficiencyClass: 0, mask: 0b11UL << (core * 2), smt: true);

        var topology = LogicalProcessorInfoParser.Parse(builder.Build());

        Assert.False(topology.IsHybrid);
        Assert.Equal(8, topology.PhysicalCoreCount);
        Assert.Equal(16, topology.LogicalCpus.Count);
        Assert.Equal(topology.AllCpusMask, topology.PCoreMask);
        Assert.Equal(0UL, topology.ECoreMask);
        Assert.Equal(0x5555UL, topology.PhysicalCoreMask);
    }

    [Fact]
    public void Smt_off_cpu_physical_mask_equals_all()
    {
        var builder = new GlpieBufferBuilder();
        for (int core = 0; core < 6; core++)
            builder.AddCore(efficiencyClass: 0, mask: 1UL << core);

        var topology = LogicalProcessorInfoParser.Parse(builder.Build());

        Assert.Equal(topology.AllCpusMask, topology.PhysicalCoreMask);
        Assert.All(topology.LogicalCpus, c => Assert.False(c.IsSmtSibling));
    }

    [Fact]
    public void Cpu_set_ids_merge_onto_logical_cpus()
    {
        var glpie = new GlpieBufferBuilder()
            .AddCore(efficiencyClass: 1, mask: 0b11, smt: true)
            .AddCore(efficiencyClass: 0, mask: 0b100)
            .Build();
        var cpuSets = CpuSetInfoParser.Parse(new CpuSetBufferBuilder()
            .AddCpuSet(id: 0x100, logicalProcessorIndex: 0, coreIndex: 0, efficiencyClass: 1)
            .AddCpuSet(id: 0x101, logicalProcessorIndex: 1, coreIndex: 0, efficiencyClass: 1)
            .AddCpuSet(id: 0x102, logicalProcessorIndex: 2, coreIndex: 1, efficiencyClass: 0)
            .Build());

        var topology = LogicalProcessorInfoParser.Parse(glpie, cpuSets);

        Assert.Equal([0x100u, 0x101u], topology.CpuSetIdsFor(CpuAffinityMode.PCoresOnly));
        Assert.Equal([0x102u], topology.CpuSetIdsFor(CpuAffinityMode.ECoresOnly));
        Assert.Equal([0x100u, 0x102u], topology.CpuSetIdsFor(CpuAffinityMode.PhysicalCoresOnly));
    }

    [Fact]
    public void Mask_resolution_covers_all_modes()
    {
        var topology = LogicalProcessorInfoParser.Parse(HybridBuffer());

        Assert.Equal(0xFFFFUL, topology.MaskFor(CpuAffinityMode.PCoresOnly));
        Assert.Equal(0xF0000UL, topology.MaskFor(CpuAffinityMode.ECoresOnly));
        Assert.Null(topology.MaskFor(CpuAffinityMode.None));
        Assert.Equal(0b1010UL, topology.MaskFor(CpuAffinityMode.CustomMask, 0b1010));
        // A custom mask with no valid CPUs must resolve to "no restriction", never 0.
        Assert.Null(topology.MaskFor(CpuAffinityMode.CustomMask, 0));
        Assert.Null(topology.MaskFor(CpuAffinityMode.CustomMask, 1UL << 63));
    }

    [Fact]
    public void Empty_buffer_yields_empty_topology_without_throwing()
    {
        var topology = LogicalProcessorInfoParser.Parse([]);

        Assert.Empty(topology.LogicalCpus);
        Assert.False(topology.IsHybrid);
        Assert.Null(topology.MaskFor(CpuAffinityMode.PCoresOnly));
        Assert.Null(topology.CpuSetIdsFor(CpuAffinityMode.PCoresOnly));
    }

    [Fact]
    public void Truncated_buffer_does_not_throw()
    {
        var full = HybridBuffer();
        var truncated = full[..(full.Length / 2 + 3)];

        var exception = Record.Exception(() => LogicalProcessorInfoParser.Parse(truncated));

        Assert.Null(exception);
    }
}
