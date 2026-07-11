using Nexus.Core.Models;

namespace Nexus.Core.ProBalance;

public abstract record ProBalanceAction(int Pid, string ExeName, string Reason);

/// <summary>Lower this process to BelowNormal until a matching Restore arrives.</summary>
public sealed record RestrainAction(int Pid, string ExeName, string Reason) : ProBalanceAction(Pid, ExeName, Reason);

/// <summary>Return this process to its pre-restraint priority.
/// When <paramref name="ProcessExited"/> is true there is nothing to restore —
/// the host should only forget its saved state.</summary>
public sealed record RestoreAction(int Pid, string ExeName, string Reason, bool ProcessExited = false)
    : ProBalanceAction(Pid, ExeName, Reason);

/// <summary>
/// The ProBalance decision core: a pure state machine over load snapshots.
/// It owns all timing/hysteresis so the surrounding service stays trivially thin,
/// and it never touches a process itself — it only emits actions.
///
/// Flap resistance comes from four mechanisms: separate enter/exit load thresholds,
/// sustain windows on both thresholds, a per-process sustain window, and a minimum
/// restraint duration.
/// </summary>
public sealed class ProBalanceEngine
{
    private sealed record RestrainedProcess(string ExeName, DateTimeOffset Since);

    private readonly Func<string, bool> _isExempt;

    private DateTimeOffset? _highLoadSince;
    private DateTimeOffset? _lowLoadSince;
    private readonly Dictionary<int, DateTimeOffset> _hogSince = new();
    private readonly Dictionary<int, RestrainedProcess> _restrained = new();

    public ProBalanceOptions Options { get; set; }

    /// <param name="isExempt">Extra exemption predicate (defaults to the built-in
    /// restraint-exempt list; injectable for tests).</param>
    public ProBalanceEngine(ProBalanceOptions options, Func<string, bool>? isExempt = null)
    {
        Options = options;
        _isExempt = isExempt ?? ProcessSafety.IsRestraintExempt;
    }

    public IReadOnlyCollection<int> RestrainedPids => _restrained.Keys;

    public IReadOnlyList<ProBalanceAction> Tick(SystemSnapshot snapshot, int? foregroundPid, DateTimeOffset now)
    {
        var actions = new List<ProBalanceAction>();
        var opts = Options;

        if (!opts.Enabled)
        {
            foreach (var (pid, state) in _restrained)
                actions.Add(new RestoreAction(pid, state.ExeName, "ProBalance disabled"));
            Reset();
            return actions;
        }

        UpdateLoadState(snapshot.TotalCpuPct, opts, now);

        bool underPressure = _highLoadSince is { } high && (now - high).TotalMilliseconds >= opts.SustainMs;
        bool calm = _lowLoadSince is { } low && (now - low).TotalMilliseconds >= opts.ReleaseMs;

        var livePids = new HashSet<int>(snapshot.Processes.Count);
        foreach (var proc in snapshot.Processes)
            livePids.Add(proc.Pid);

        // --- Restores ---
        foreach (var (pid, state) in _restrained.ToArray())
        {
            if (!livePids.Contains(pid))
            {
                _restrained.Remove(pid);
                actions.Add(new RestoreAction(pid, state.ExeName, "process exited", ProcessExited: true));
            }
            else if (pid == foregroundPid)
            {
                _restrained.Remove(pid);
                actions.Add(new RestoreAction(pid, state.ExeName, "became the foreground app"));
            }
            else if (calm && (now - state.Since).TotalMilliseconds >= opts.MinRestraintMs)
            {
                _restrained.Remove(pid);
                actions.Add(new RestoreAction(pid, state.ExeName, "system load returned to normal"));
            }
        }

        // --- Hog tracking & new restraints ---
        foreach (var proc in snapshot.Processes)
        {
            bool eligible = proc.CpuPct >= opts.ProcessCpuThresholdPct
                            && proc.Pid != foregroundPid
                            && proc.Pid > 4 // idle/system pseudo-processes
                            && !_restrained.ContainsKey(proc.Pid)
                            && !_isExempt(proc.ExeName)
                            && !IsUserExcluded(proc.ExeName, opts);

            if (!eligible)
            {
                _hogSince.Remove(proc.Pid);
                continue;
            }

            if (!_hogSince.TryGetValue(proc.Pid, out var since))
            {
                _hogSince[proc.Pid] = since = now;
            }

            if (underPressure
                && (now - since).TotalMilliseconds >= opts.ProcessSustainMs
                && _restrained.Count < opts.MaxRestrainedProcesses)
            {
                _hogSince.Remove(proc.Pid);
                _restrained[proc.Pid] = new RestrainedProcess(proc.ExeName, now);
                actions.Add(new RestrainAction(proc.Pid, proc.ExeName,
                    $"using {proc.CpuPct:F0}% CPU in the background while total load is {snapshot.TotalCpuPct:F0}%"));
            }
        }

        // Drop hog-tracking for processes that vanished.
        foreach (var pid in _hogSince.Keys.Where(p => !livePids.Contains(p)).ToArray())
            _hogSince.Remove(pid);

        return actions;
    }

    private void UpdateLoadState(double totalCpuPct, ProBalanceOptions opts, DateTimeOffset now)
    {
        if (totalCpuPct >= opts.SystemLoadEnterPct)
        {
            _highLoadSince ??= now;
            _lowLoadSince = null;
        }
        else if (totalCpuPct <= opts.SystemLoadExitPct)
        {
            _lowLoadSince ??= now;
            _highLoadSince = null;
        }
        else
        {
            // Between the thresholds: pressure is no longer building, and the system
            // isn't calm either. Reset both accumulators so each state must be
            // re-earned from scratch — this is the hysteresis dead zone.
            _highLoadSince = null;
            _lowLoadSince = null;
        }
    }

    private static bool IsUserExcluded(string exeName, ProBalanceOptions opts)
    {
        foreach (var excluded in opts.UserExclusions)
        {
            if (string.Equals(ProcessRuleNormalize(excluded), ProcessRuleNormalize(exeName), StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;

        static string ProcessRuleNormalize(string name) => Models.ProcessRule.Normalize(name);
    }

    private void Reset()
    {
        _highLoadSince = null;
        _lowLoadSince = null;
        _hogSince.Clear();
        _restrained.Clear();
    }
}
