using Nexus.Core.Models;

namespace Nexus.Core.Enforcement;

public sealed record SmartTrimOptions
{
    public bool Enabled { get; set; }
    /// <summary>Only processes with a working set above this are trimmed.</summary>
    public int WorkingSetThresholdMb { get; set; } = 300;
    /// <summary>How often a trim pass runs.</summary>
    public int IntervalMinutes { get; set; } = 5;
    /// <summary>Per-process cooldown so the same process isn't trimmed back-to-back
    /// (re-faulting pages in costs more than the trim saves).</summary>
    public int CooldownMinutes { get; set; } = 15;
}

/// <summary>Pure selection of working-set trim targets: background processes over the
/// RAM threshold, excluding the foreground app and everything restraint-exempt.</summary>
public sealed class SmartTrimEngine
{
    private readonly Func<string, bool> _isExempt;
    private readonly Dictionary<int, DateTimeOffset> _lastTrimmed = new();
    private DateTimeOffset _lastPass = DateTimeOffset.MinValue;

    public SmartTrimEngine(Func<string, bool>? isExempt = null)
    {
        _isExempt = isExempt ?? ProcessSafety.IsRestraintExempt;
    }

    public IReadOnlyList<ProcSample> Tick(
        SystemSnapshot snapshot, int? foregroundPid, SmartTrimOptions options, DateTimeOffset now)
    {
        if (!options.Enabled || (now - _lastPass).TotalMinutes < options.IntervalMinutes)
            return [];
        _lastPass = now;

        // Drop cooldown entries for processes that no longer exist.
        var livePids = new HashSet<int>(snapshot.Processes.Select(p => p.Pid));
        foreach (var pid in _lastTrimmed.Keys.Where(p => !livePids.Contains(p)).ToArray())
            _lastTrimmed.Remove(pid);

        long thresholdBytes = (long)options.WorkingSetThresholdMb * 1024 * 1024;
        var targets = new List<ProcSample>();

        foreach (var proc in snapshot.Processes)
        {
            if (proc.Pid <= 4
                || proc.Pid == foregroundPid
                || proc.WorkingSetBytes < thresholdBytes
                || _isExempt(proc.ExeName))
                continue;

            if (_lastTrimmed.TryGetValue(proc.Pid, out var last)
                && (now - last).TotalMinutes < options.CooldownMinutes)
                continue;

            _lastTrimmed[proc.Pid] = now;
            targets.Add(proc);
        }

        return targets;
    }
}
