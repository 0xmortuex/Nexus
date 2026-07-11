using System.Buffers.Binary;
using System.Text;
using Nexus.Core.Models;

namespace Nexus.App.Interop;

/// <summary>
/// Produces a SystemSnapshot per call using two NtQuerySystemInformation queries
/// (one for per-core times, one for every process's CPU time + working set) instead
/// of opening hundreds of process handles. CPU percentages are deltas against the
/// previous call, so the first snapshot reports zeros.
/// </summary>
public sealed class SystemSampler
{
    // SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION: IdleTime, KernelTime, UserTime,
    // DpcTime, InterruptTime (LARGE_INTEGER each) + ULONG InterruptCount, padded to 48 bytes.
    private const int ProcessorPerfEntrySize = 48;

    // SYSTEM_PROCESS_INFORMATION x64 offsets (this app publishes win-x64 only):
    private const int OffNextEntryOffset = 0x00;
    private const int OffUserTime = 0x28;
    private const int OffKernelTime = 0x30;
    private const int OffImageNameLength = 0x38;  // UNICODE_STRING.Length
    private const int OffImageNameBuffer = 0x40;  // UNICODE_STRING.Buffer (pointer)
    private const int OffUniqueProcessId = 0x50;
    private const int OffWorkingSetSize = 0x90;
    private const int MinProcessEntrySize = 0x98;

    private long[] _prevIdle = [];
    private long[] _prevBusy = [];
    private readonly Dictionary<int, long> _prevProcessTime = new();
    private DateTimeOffset _prevSampleAt;
    // Pinned: SYSTEM_PROCESS_INFORMATION embeds absolute pointers into this buffer
    // (UNICODE_STRING.Buffer). A movable array could be relocated by the GC between
    // the syscall and the read, invalidating them.
    private byte[] _procBuffer = GC.AllocateArray<byte>(1 << 19, pinned: true);
    private byte[] _perfBuffer = [];

    public SystemSnapshot Sample()
    {
        var now = DateTimeOffset.Now;
        var elapsed = _prevSampleAt == default ? TimeSpan.Zero : now - _prevSampleAt;
        _prevSampleAt = now;

        var perCore = SampleCores();
        var processes = SampleProcesses(elapsed);
        var (available, total) = SampleMemory();

        double totalCpu = perCore.Count == 0 ? 0 : perCore.Average();
        return new SystemSnapshot(now, totalCpu, perCore, processes, available, total);
    }

    private List<double> SampleCores()
    {
        int coreCount = Environment.ProcessorCount;
        int needed = coreCount * ProcessorPerfEntrySize;
        if (_perfBuffer.Length < needed)
            _perfBuffer = new byte[needed];

        var result = new List<double>(coreCount);
        int status = NativeMethods.NtQuerySystemInformation(
            NativeMethods.SystemProcessorPerformanceInformationClass, _perfBuffer, (uint)needed, out var returned);
        if (status != 0)
            return result;

        int cores = (int)(returned / ProcessorPerfEntrySize);
        var idle = new long[cores];
        var busy = new long[cores];

        for (int i = 0; i < cores; i++)
        {
            var span = _perfBuffer.AsSpan(i * ProcessorPerfEntrySize);
            long idleTime = BinaryPrimitives.ReadInt64LittleEndian(span);
            long kernelTime = BinaryPrimitives.ReadInt64LittleEndian(span[8..]);   // includes idle
            long userTime = BinaryPrimitives.ReadInt64LittleEndian(span[16..]);

            idle[i] = idleTime;
            busy[i] = kernelTime + userTime - idleTime;

            if (i < _prevIdle.Length)
            {
                long dIdle = idleTime - _prevIdle[i];
                long dBusy = busy[i] - _prevBusy[i];
                long dTotal = dIdle + dBusy;
                result.Add(dTotal <= 0 ? 0 : Math.Clamp(100.0 * dBusy / dTotal, 0, 100));
            }
            else
            {
                result.Add(0);
            }
        }

        _prevIdle = idle;
        _prevBusy = busy;
        return result;
    }

    private List<ProcSample> SampleProcesses(TimeSpan elapsed)
    {
        var result = new List<ProcSample>(256);

        for (int attempt = 0; attempt < 5; attempt++)
        {
            int status = NativeMethods.NtQuerySystemInformation(
                NativeMethods.SystemProcessInformationClass, _procBuffer, (uint)_procBuffer.Length, out var returned);
            if (status == NativeMethods.STATUS_INFO_LENGTH_MISMATCH)
            {
                _procBuffer = GC.AllocateArray<byte>(
                    Math.Max(_procBuffer.Length * 2, (int)returned + 65536), pinned: true);
                continue;
            }
            if (status != 0)
                return result;
            break;
        }

        double intervalTicks = elapsed.Ticks * (double)Environment.ProcessorCount;
        var seen = new HashSet<int>();
        var newTimes = new Dictionary<int, long>();
        int offset = 0;

        while (offset >= 0 && offset + MinProcessEntrySize <= _procBuffer.Length)
        {
            var entry = _procBuffer.AsSpan(offset);
            int pid = (int)BinaryPrimitives.ReadUInt64LittleEndian(entry[OffUniqueProcessId..]);

            if (pid > 0 && seen.Add(pid))
            {
                long cpuTime = BinaryPrimitives.ReadInt64LittleEndian(entry[OffUserTime..])
                             + BinaryPrimitives.ReadInt64LittleEndian(entry[OffKernelTime..]);
                long workingSet = (long)BinaryPrimitives.ReadUInt64LittleEndian(entry[OffWorkingSetSize..]);

                double cpuPct = 0;
                if (intervalTicks > 0 && _prevProcessTime.TryGetValue(pid, out var prev))
                    cpuPct = Math.Clamp(100.0 * (cpuTime - prev) / intervalTicks, 0, 100);
                newTimes[pid] = cpuTime;

                result.Add(new ProcSample(pid, ReadImageName(offset), cpuPct, workingSet));
            }

            int next = BinaryPrimitives.ReadInt32LittleEndian(entry[OffNextEntryOffset..]);
            if (next == 0)
                break;
            offset += next;
        }

        _prevProcessTime.Clear();
        foreach (var (pid, time) in newTimes)
            _prevProcessTime[pid] = time;

        return result;
    }

    private string ReadImageName(int entryOffset)
    {
        var entry = _procBuffer.AsSpan(entryOffset);
        ushort length = BinaryPrimitives.ReadUInt16LittleEndian(entry[OffImageNameLength..]);
        if (length == 0)
            return "system";

        // UNICODE_STRING.Buffer points into this same snapshot buffer; translate the
        // absolute pointer back to a buffer offset.
        ulong bufferPtr = BinaryPrimitives.ReadUInt64LittleEndian(entry[OffImageNameBuffer..]);
        unsafe
        {
            fixed (byte* basePtr = _procBuffer)
            {
                long nameOffset = (long)(bufferPtr - (ulong)basePtr);
                if (nameOffset <= 0 || nameOffset + length > _procBuffer.Length)
                    return "unknown";
                return Encoding.Unicode.GetString(_procBuffer, (int)nameOffset, length);
            }
        }
    }

    private static (long Available, long Total) SampleMemory()
    {
        var status = new NativeMethods.MEMORYSTATUSEX
        {
            Length = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.MEMORYSTATUSEX>(),
        };
        return NativeMethods.GlobalMemoryStatusEx(ref status)
            ? ((long)status.AvailPhys, (long)status.TotalPhys)
            : (0, 0);
    }
}
