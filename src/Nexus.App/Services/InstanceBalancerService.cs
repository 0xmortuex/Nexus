using System.Diagnostics;
using Nexus.App.Interop;
using Nexus.Core.Enforcement;
using Nexus.Core.Logging;
using Nexus.Core.Models;
using Nexus.Core.Persistence;

namespace Nexus.App.Services;

/// <summary>
/// Instance Balancer: for each configured exe, splits the CPU cores evenly between
/// its running copies so identical processes stop contending for the same cores
/// (e.g. multiple game clients or render workers). Re-balances whenever an instance
/// of a balanced exe starts or stops.
/// </summary>
public sealed class InstanceBalancerService : IDisposable
{
    private readonly IProcessWatcher _watcher;
    private readonly ProcessApi _api;
    private readonly CpuTopologyProvider _topology;
    private readonly SettingsService _settings;
    private readonly ActivityLog _log;

    public InstanceBalancerService(
        IProcessWatcher watcher,
        ProcessApi api,
        CpuTopologyProvider topology,
        SettingsService settings,
        ActivityLog log)
    {
        _watcher = watcher;
        _api = api;
        _topology = topology;
        _settings = settings;
        _log = log;
    }

    public void Start()
    {
        _watcher.ProcessStarted += OnChanged;
        _watcher.ProcessStopped += OnChanged;
        foreach (var exe in _settings.Current.Enforcement.BalancedProcesses)
            Rebalance(exe);
    }

    private void OnChanged(ProcessEvent e)
    {
        var normalized = ProcessRule.Normalize(e.ExeName);
        if (_settings.Current.Enforcement.BalancedProcesses.Any(b => ProcessRule.Normalize(b) == normalized))
            Rebalance(e.ExeName);
    }

    /// <summary>Public so the UI can force a re-balance after editing the list.</summary>
    public void Rebalance(string exeName)
    {
        var normalized = ProcessRule.Normalize(exeName);
        var processName = normalized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? normalized[..^4] : normalized;

        var pids = new List<int>();
        foreach (var process in Process.GetProcessesByName(processName))
        {
            using (process)
            {
                pids.Add(process.Id);
            }
        }
        if (pids.Count < 2)
            return;

        var assignments = InstanceBalancerEngine.Balance(pids, _topology.Topology.AllCpusMask);
        foreach (var assignment in assignments)
        {
            if (_api.TrySetAffinity(assignment.Pid, exeName, assignment.AffinityMask, out _))
                _log.Info("Balancer",
                    $"Instance balancer: {exeName} PID {assignment.Pid} → cores 0x{assignment.AffinityMask:X}.");
        }
    }

    public void Dispose()
    {
        _watcher.ProcessStarted -= OnChanged;
        _watcher.ProcessStopped -= OnChanged;
    }
}
