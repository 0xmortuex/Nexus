namespace Nexus.Core.Models;

/// <summary>One process as seen in a sampling pass.</summary>
/// <param name="CpuPct">CPU use over the last sampling interval, 0–100 across all cores.</param>
public sealed record ProcSample(int Pid, string ExeName, double CpuPct, long WorkingSetBytes);

/// <summary>
/// A point-in-time view of system load. Produced by the interop sampler; consumed by
/// every engine (ProBalance, watchdog, SmartTrim) so none of them touch interop directly.
/// </summary>
public sealed record SystemSnapshot(
    DateTimeOffset Timestamp,
    double TotalCpuPct,
    IReadOnlyList<double> PerCoreCpuPct,
    IReadOnlyList<ProcSample> Processes,
    long AvailableMemoryBytes,
    long TotalMemoryBytes);
