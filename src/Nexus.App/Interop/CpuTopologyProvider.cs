using System.ComponentModel;
using Nexus.Core.Logging;
using Nexus.Core.Models;
using Nexus.Core.Topology;

namespace Nexus.App.Interop;

/// <summary>
/// Reads the machine's CPU layout once (topology doesn't change at runtime) and
/// hands the raw buffers to the pure parsers in Nexus.Core.
/// </summary>
public sealed class CpuTopologyProvider
{
    private const int RelationProcessorCore = 0;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    private readonly Lazy<CpuTopology> _topology;

    public CpuTopologyProvider(ActivityLog log)
    {
        _topology = new Lazy<CpuTopology>(() => Read(log));
    }

    public CpuTopology Topology => _topology.Value;

    private static CpuTopology Read(ActivityLog log)
    {
        try
        {
            var glpie = ReadLogicalProcessorInfo();
            var cpuSets = ReadCpuSets(log);
            var topology = LogicalProcessorInfoParser.Parse(glpie, cpuSets);

            log.Info("Topology",
                $"Detected {topology.PhysicalCoreCount} physical cores / {topology.LogicalCpus.Count} logical CPUs" +
                (topology.IsHybrid
                    ? $" (hybrid: P-core mask 0x{topology.PCoreMask:X}, E-core mask 0x{topology.ECoreMask:X})."
                    : " (homogeneous)."));
            return topology;
        }
        catch (Exception ex)
        {
            log.Error("Topology", $"CPU topology detection failed ({ex.Message}); core-pinning features disabled.");
            return new CpuTopology([]);
        }
    }

    private static byte[] ReadLogicalProcessorInfo()
    {
        uint length = 0;
        if (!NativeMethods.GetLogicalProcessorInformationEx(RelationProcessorCore, null, ref length)
            && (uint)new Win32Exception().NativeErrorCode != ERROR_INSUFFICIENT_BUFFER)
        {
            // Fall through with whatever length was returned; a zero-length buffer
            // will fail the second call and surface a proper error.
        }

        var buffer = new byte[length];
        if (!NativeMethods.GetLogicalProcessorInformationEx(RelationProcessorCore, buffer, ref length))
            throw new Win32Exception();
        return buffer;
    }

    private static IReadOnlyList<CpuSetEntry> ReadCpuSets(ActivityLog log)
    {
        try
        {
            NativeMethods.GetSystemCpuSetInformation(null, 0, out var length, IntPtr.Zero, 0);
            if (length == 0)
                return [];

            var buffer = new byte[length];
            if (!NativeMethods.GetSystemCpuSetInformation(buffer, length, out _, IntPtr.Zero, 0))
                throw new Win32Exception();
            return CpuSetInfoParser.Parse(buffer);
        }
        catch (Exception ex)
        {
            // CPU sets are optional (affinity masks remain available), so degrade quietly.
            log.Warn("Topology", $"CPU set enumeration failed ({ex.Message}); falling back to affinity masks only.");
            return [];
        }
    }
}
