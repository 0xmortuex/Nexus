using System.Diagnostics;
using Nexus.App.Interop;
using Nexus.Core;
using Nexus.Core.Logging;
using Nexus.Core.Models;
using Nexus.Core.Rules;

namespace Nexus.App.Services;

/// <summary>
/// Applies persistent per-exe rules: to everything already running at startup,
/// and to each new process the instant the watcher reports it.
/// </summary>
public sealed class RuleApplicationService : IDisposable
{
    private readonly IProcessWatcher _watcher;
    private readonly RulesRepository _rules;
    private readonly ProcessApi _api;
    private readonly CpuTopologyProvider _topologyProvider;
    private readonly ActivityLog _log;

    public RuleApplicationService(
        IProcessWatcher watcher,
        RulesRepository rules,
        ProcessApi api,
        CpuTopologyProvider topologyProvider,
        ActivityLog log)
    {
        _watcher = watcher;
        _rules = rules;
        _api = api;
        _topologyProvider = topologyProvider;
        _log = log;
    }

    public void Start()
    {
        _watcher.ProcessStarted += OnProcessStarted;
        ApplyToRunningProcesses();
    }

    private void OnProcessStarted(ProcessEvent e)
    {
        var rule = _rules.Find(e.ExeName);
        if (rule is { Enabled: true })
            Apply(e.Pid, e.ExeName, rule);
    }

    private void ApplyToRunningProcesses()
    {
        if (_rules.All().Count == 0)
            return;

        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                var name = process.ProcessName + ".exe";
                var rule = _rules.Find(name);
                if (rule is { Enabled: true })
                    Apply(process.Id, name, rule);
            }
        }
    }

    /// <summary>Apply every configured aspect of a rule; failures are logged per-aspect
    /// and never abort the remaining aspects.</summary>
    public void Apply(int pid, string exeName, ProcessRule rule)
    {
        if (ProcessSafety.IsProtected(exeName))
            return;

        var applied = new List<string>();

        if (rule.Priority is { } priority)
            Do(applied, $"priority {priority}",
                (out string? err) => _api.TrySetPriority(pid, exeName, priority, out err));

        if (rule.AffinityMode != CpuAffinityMode.None)
            ApplyCoreRestriction(pid, exeName, rule, applied);

        if (rule.IoPriority is { } io)
            Do(applied, $"IO priority {io}",
                (out string? err) => _api.TrySetIoPriority(pid, exeName, io, out err));

        if (rule.MemoryPriority is { } mem)
            Do(applied, $"memory priority {mem}",
                (out string? err) => _api.TrySetMemoryPriority(pid, exeName, mem, out err));

        if (rule.EfficiencyMode is { } eco)
            Do(applied, eco ? "efficiency mode on" : "efficiency mode off",
                (out string? err) => _api.TrySetEfficiencyMode(pid, exeName, eco, out err));

        if (rule.TrimWorkingSetOnStart)
            Do(applied, "working set trimmed",
                (out string? err) => _api.TryTrimWorkingSet(pid, exeName, out err));

        if (applied.Count > 0)
            _log.Info("Rules", $"Applied rule to {exeName} (PID {pid}): {string.Join(", ", applied)}.");
    }

    private void ApplyCoreRestriction(int pid, string exeName, ProcessRule rule, List<string> applied)
    {
        var topology = _topologyProvider.Topology;

        if (rule.UseCpuSets)
        {
            var ids = topology.CpuSetIdsFor(rule.AffinityMode, rule.CustomAffinityMask);
            if (ids is not null)
            {
                Do(applied, $"CPU sets {rule.AffinityMode} ({ids.Count} CPUs)",
                    (out string? err) => _api.TrySetCpuSets(pid, exeName, ids, out err));
                return;
            }
            // No CPU set IDs available (old Windows) — fall back to a hard mask.
        }

        var mask = topology.MaskFor(rule.AffinityMode, rule.CustomAffinityMask);
        if (mask is { } m)
            Do(applied, $"affinity {rule.AffinityMode} (0x{m:X})",
                (out string? err) => _api.TrySetAffinity(pid, exeName, m, out err));
    }

    private delegate bool TryAction(out string? error);

    private void Do(List<string> applied, string description, TryAction action)
    {
        if (action(out var error))
            applied.Add(description);
        else if (error is not null)
            _log.Warn("Rules", $"Could not apply {description}: {error}");
    }

    public void Dispose() => _watcher.ProcessStarted -= OnProcessStarted;
}
