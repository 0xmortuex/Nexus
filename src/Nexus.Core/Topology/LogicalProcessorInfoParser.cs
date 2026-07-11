using System.Buffers.Binary;
using Nexus.Core.Models;

namespace Nexus.Core.Topology;

/// <summary>One entry from GetSystemCpuSetInformation, keyed by (Group, IndexInGroup).</summary>
public sealed record CpuSetEntry(uint CpuSetId, int Group, int IndexInGroup, byte CoreIndex, byte EfficiencyClass);

/// <summary>
/// Pure parsers for the raw buffers returned by GetLogicalProcessorInformationEx
/// (RelationProcessorCore records) and GetSystemCpuSetInformation. Kept free of any
/// interop so the byte-offset logic is unit-testable off-Windows.
/// </summary>
public static class LogicalProcessorInfoParser
{
    // SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX layout (winnt.h):
    //   LOGICAL_PROCESSOR_RELATIONSHIP Relationship;  // int32  @ 0
    //   DWORD Size;                                   // uint32 @ 4
    //   union { PROCESSOR_RELATIONSHIP Processor; ... }        @ 8
    // PROCESSOR_RELATIONSHIP:
    //   BYTE Flags;            @ union+0   (LTP_PC_SMT = 0x1 when the core has SMT)
    //   BYTE EfficiencyClass;  @ union+1
    //   BYTE Reserved[20];     @ union+2
    //   WORD GroupCount;       @ union+22
    //   GROUP_AFFINITY GroupMask[GroupCount]; @ union+24 (8-byte aligned)
    // GROUP_AFFINITY: { KAFFINITY Mask (8 bytes); WORD Group; WORD Reserved[3] } = 16 bytes
    private const int RelationProcessorCore = 0;

    public static CpuTopology Parse(ReadOnlySpan<byte> buffer, IReadOnlyList<CpuSetEntry>? cpuSets = null)
    {
        var setsByCpu = new Dictionary<(int Group, int Index), CpuSetEntry>();
        if (cpuSets is not null)
        {
            foreach (var entry in cpuSets)
                setsByCpu[(entry.Group, entry.IndexInGroup)] = entry;
        }

        var logical = new List<LogicalCpu>();
        int coreId = 0;
        int offset = 0;

        while (offset + 8 <= buffer.Length)
        {
            int relationship = BinaryPrimitives.ReadInt32LittleEndian(buffer[offset..]);
            int size = BinaryPrimitives.ReadInt32LittleEndian(buffer[(offset + 4)..]);
            if (size <= 8 || offset + size > buffer.Length)
                break;

            if (relationship == RelationProcessorCore)
            {
                byte efficiencyClass = buffer[offset + 9];
                ushort groupCount = BinaryPrimitives.ReadUInt16LittleEndian(buffer[(offset + 30)..]);

                for (int g = 0; g < groupCount; g++)
                {
                    int groupAffinityOffset = offset + 32 + g * 16;
                    if (groupAffinityOffset + 16 > offset + size)
                        break;

                    ulong mask = BinaryPrimitives.ReadUInt64LittleEndian(buffer[groupAffinityOffset..]);
                    ushort group = BinaryPrimitives.ReadUInt16LittleEndian(buffer[(groupAffinityOffset + 8)..]);

                    bool first = true;
                    for (int bit = 0; bit < 64; bit++)
                    {
                        if ((mask & (1UL << bit)) == 0)
                            continue;

                        setsByCpu.TryGetValue((group, bit), out var set);
                        logical.Add(new LogicalCpu(
                            Group: group,
                            IndexInGroup: bit,
                            PhysicalCoreId: coreId,
                            EfficiencyClass: efficiencyClass,
                            IsSmtSibling: !first,
                            CpuSetId: set?.CpuSetId ?? 0));
                        first = false;
                    }
                }

                coreId++;
            }

            offset += size;
        }

        return new CpuTopology(logical
            .OrderBy(c => c.Group)
            .ThenBy(c => c.IndexInGroup)
            .ToArray());
    }
}

public static class CpuSetInfoParser
{
    // SYSTEM_CPU_SET_INFORMATION layout (winnt.h):
    //   DWORD Size;                      @ 0
    //   CPU_SET_INFORMATION_TYPE Type;   @ 4   (CpuSetInformation = 0)
    //   struct CpuSet {
    //     DWORD Id;                      @ 8
    //     WORD  Group;                   @ 12
    //     BYTE  LogicalProcessorIndex;   @ 14  (index within the group)
    //     BYTE  CoreIndex;               @ 15
    //     BYTE  LastLevelCacheIndex;     @ 16
    //     BYTE  NumaNodeIndex;           @ 17
    //     BYTE  EfficiencyClass;         @ 18
    //     ...flags/reserved...
    //   }
    private const int CpuSetInformationType = 0;

    public static IReadOnlyList<CpuSetEntry> Parse(ReadOnlySpan<byte> buffer)
    {
        var entries = new List<CpuSetEntry>();
        int offset = 0;

        while (offset + 8 <= buffer.Length)
        {
            int size = BinaryPrimitives.ReadInt32LittleEndian(buffer[offset..]);
            int type = BinaryPrimitives.ReadInt32LittleEndian(buffer[(offset + 4)..]);
            if (size <= 0 || offset + size > buffer.Length)
                break;

            if (type == CpuSetInformationType && size >= 19)
            {
                entries.Add(new CpuSetEntry(
                    CpuSetId: BinaryPrimitives.ReadUInt32LittleEndian(buffer[(offset + 8)..]),
                    Group: BinaryPrimitives.ReadUInt16LittleEndian(buffer[(offset + 12)..]),
                    IndexInGroup: buffer[offset + 14],
                    CoreIndex: buffer[offset + 15],
                    EfficiencyClass: buffer[offset + 18]));
            }

            offset += size;
        }

        return entries;
    }
}
