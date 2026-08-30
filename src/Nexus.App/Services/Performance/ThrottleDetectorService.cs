using System.Runtime.InteropServices;
using Microsoft.Win32;
using Nexus.Core.Logging;
using Nexus.Core.Performance;

namespace Nexus.App.Services.Performance;

/// <summary>
/// Reads per-core frequency and the enforced ceiling straight from the power
/// subsystem, and hands them to <see cref="ThrottleAnalysis"/>.
///
/// Uses <c>CallNtPowerInformation(ProcessorInformation)</c> rather than WMI's
/// <c>Win32_Processor.CurrentClockSpeed</c>, which on modern Windows is cached at
/// boot and reports the rated speed forever regardless of what the chip is doing.
/// No kernel driver is involved: this is a documented user-mode call, unlike the
/// WinRing0-family drivers that hardware monitors use — those are on Microsoft's
/// vulnerable-driver blocklist and shipping one would make Nexus a security
/// downgrade.
/// </summary>
public sealed class ThrottleDetectorService
{
    private const int ProcessorInformation = 11;
    private const int StatusSuccess = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESSOR_POWER_INFORMATION
    {
        public uint Number;
        public uint MaxMhz;
        public uint CurrentMhz;
        public uint MhzLimit;
        public uint MaxIdleState;
        public uint CurrentIdleState;
    }

    [DllImport("powrprof.dll", SetLastError = true)]
    private static extern int CallNtPowerInformation(
        int informationLevel,
        IntPtr inputBuffer,
        uint inputBufferSize,
        IntPtr outputBuffer,
        uint outputBufferSize);

    private readonly ActivityLog _log;

    public ThrottleDetectorService(ActivityLog log)
    {
        _log = log;
    }

    /// <summary>Per-core frequency readings, or an empty list if unavailable.</summary>
    public IReadOnlyList<CoreFrequency> ReadCoreFrequencies()
    {
        int coreCount = Environment.ProcessorCount;
        int entrySize = Marshal.SizeOf<PROCESSOR_POWER_INFORMATION>();
        int bufferSize = entrySize * coreCount;

        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            int status = CallNtPowerInformation(
                ProcessorInformation, IntPtr.Zero, 0, buffer, (uint)bufferSize);

            if (status != StatusSuccess)
            {
                _log.Warn("Performance", $"Could not read processor power information (status {status}).");
                return [];
            }

            var cores = new List<CoreFrequency>(coreCount);
            for (int i = 0; i < coreCount; i++)
            {
                var entry = Marshal.PtrToStructure<PROCESSOR_POWER_INFORMATION>(buffer + i * entrySize);

                cores.Add(new CoreFrequency(
                    (int)entry.Number,
                    (int)entry.MaxMhz,
                    (int)entry.CurrentMhz,
                    (int)entry.MhzLimit));
            }

            return cores;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return [];
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>
    /// The active power plan's maximum processor state, as a percentage, or null when
    /// it cannot be read. Needed to tell "Windows is capping this" from "the hardware
    /// is capping this" — the difference between a fixable problem and a fact of life.
    /// </summary>
    public int? ReadPowerPlanMaxProcessorState()
    {
        // PROCTHROTTLEMAX under the active scheme's processor settings subgroup.
        const string subgroup = "54533251-82be-4824-96c1-47b60b740d00";
        const string setting = "bc5038f7-23e0-4960-96da-33abaf5935ec";

        try
        {
            var activeScheme = ReadActiveSchemeGuid();
            if (activeScheme is null)
                return null;

            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\{activeScheme}\{subgroup}\{setting}");

            // ACSettingIndex is the on-mains value, which is the one that matters for
            // a machine that is gaming.
            if (key?.GetValue("ACSettingIndex") is int value && value is > 0 and <= 100)
                return value;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            // Fall through: an unknown power plan state is reported as unknown, which
            // makes the analysis refuse to blame the power plan rather than guess.
        }

        return null;
    }

    private static string? ReadActiveSchemeGuid()
    {
        using var key = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes");

        return key?.GetValue("ActivePowerScheme") as string;
    }

    /// <summary>Read the machine and report whether anything is holding the CPU down.</summary>
    public ThrottleFinding? Detect()
    {
        var cores = ReadCoreFrequencies();
        if (cores.Count == 0)
            return null;

        return ThrottleAnalysis.Analyse(cores, ReadPowerPlanMaxProcessorState());
    }
}
