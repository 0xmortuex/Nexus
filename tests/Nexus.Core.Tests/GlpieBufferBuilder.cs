using System.Buffers.Binary;

namespace Nexus.Core.Tests;

/// <summary>
/// Builds byte buffers in the exact on-the-wire layout of
/// SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX / SYSTEM_CPU_SET_INFORMATION so the
/// parsers can be exercised without Windows. Offsets mirror winnt.h; see the
/// comments in LogicalProcessorInfoParser.
/// </summary>
internal sealed class GlpieBufferBuilder
{
    private readonly List<byte[]> _records = [];

    public GlpieBufferBuilder AddCore(byte efficiencyClass, ulong mask, ushort group = 0, bool smt = false)
    {
        // 8 header + 24 fixed PROCESSOR_RELATIONSHIP + one 16-byte GROUP_AFFINITY
        var record = new byte[8 + 24 + 16];
        BinaryPrimitives.WriteInt32LittleEndian(record, 0);                       // RelationProcessorCore
        BinaryPrimitives.WriteInt32LittleEndian(record.AsSpan(4), record.Length); // Size
        record[8] = smt ? (byte)1 : (byte)0;                                      // Flags (LTP_PC_SMT)
        record[9] = efficiencyClass;                                              // EfficiencyClass
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(30), 1);           // GroupCount
        BinaryPrimitives.WriteUInt64LittleEndian(record.AsSpan(32), mask);        // GroupMask[0].Mask
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(40), group);       // GroupMask[0].Group
        _records.Add(record);
        return this;
    }

    /// <summary>A record type the parser must skip (e.g. RelationCache = 2).</summary>
    public GlpieBufferBuilder AddIrrelevantRecord(int relationship, int payloadSize = 40)
    {
        var record = new byte[8 + payloadSize];
        BinaryPrimitives.WriteInt32LittleEndian(record, relationship);
        BinaryPrimitives.WriteInt32LittleEndian(record.AsSpan(4), record.Length);
        _records.Add(record);
        return this;
    }

    public byte[] Build() => _records.SelectMany(r => r).ToArray();
}

internal sealed class CpuSetBufferBuilder
{
    private readonly List<byte[]> _records = [];

    public CpuSetBufferBuilder AddCpuSet(uint id, byte logicalProcessorIndex, byte coreIndex,
        byte efficiencyClass, ushort group = 0)
    {
        var record = new byte[32];
        BinaryPrimitives.WriteInt32LittleEndian(record, record.Length);        // Size
        BinaryPrimitives.WriteInt32LittleEndian(record.AsSpan(4), 0);          // CpuSetInformation
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(8), id);        // Id
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(12), group);    // Group
        record[14] = logicalProcessorIndex;
        record[15] = coreIndex;
        record[18] = efficiencyClass;
        _records.Add(record);
        return this;
    }

    public byte[] Build() => _records.SelectMany(r => r).ToArray();
}
