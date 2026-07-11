using System.Collections.ObjectModel;
using System.Windows;
using Nexus.App.Interop;
using Nexus.App.Services;
using Nexus.Core;
using Nexus.Core.Logging;
using Nexus.Core.Models;
using Nexus.Core.Rules;

namespace Nexus.App.ViewModels;

public sealed class ProcessRow : ViewModelBase
{
    private double _cpu;
    private double _ramMb;

    public required int Pid { get; init; }
    public required string ExeName { get; init; }
    public bool HasRule { get; set; }

    public double Cpu
    {
        get => _cpu;
        set => Set(ref _cpu, value);
    }

    public double RamMb
    {
        get => _ramMb;
        set => Set(ref _ramMb, value);
    }
}

/// <summary>
/// The Processes tab: live sortable process list; the context menu applies one-shot
/// actions or writes a persistent rule ("always"). Mirrors Process Lasso's main view.
/// </summary>
public sealed class ProcessesViewModel : ViewModelBase
{
    private readonly ProBalanceService _snapshots;
    private readonly ProcessApi _api;
    private readonly RulesRepository _rules;
    private readonly RuleApplicationService _ruleApplication;
    private readonly CpuLimiterService _limiter;
    private readonly IfeoService _ifeo;
    private readonly ActivityLog _log;

    public ObservableCollection<ProcessRow> Processes { get; } = [];

    private ProcessRow? _selected;
    public ProcessRow? Selected
    {
        get => _selected;
        set => Set(ref _selected, value);
    }

    private string _filter = "";
    public string Filter
    {
        get => _filter;
        set
        {
            if (Set(ref _filter, value))
                Refresh();
        }
    }

    public RelayCommand SetPriorityCommand { get; }
    public RelayCommand SetPriorityAlwaysCommand { get; }
    public RelayCommand SetAffinityCommand { get; }
    public RelayCommand SetAffinityAlwaysCommand { get; }
    public RelayCommand SetIoPriorityCommand { get; }
    public RelayCommand SetEfficiencyCommand { get; }
    public RelayCommand TrimCommand { get; }
    public RelayCommand KillCommand { get; }
    public RelayCommand RemoveRuleCommand { get; }
    public RelayCommand LimitCpuCommand { get; }
    public RelayCommand ClearCpuLimitCommand { get; }
    public RelayCommand SetLaunchPriorityCommand { get; }
    public RelayCommand ClearLaunchPriorityCommand { get; }

    public ProcessesViewModel(
        ProBalanceService snapshots,
        ProcessApi api,
        RulesRepository rules,
        RuleApplicationService ruleApplication,
        CpuLimiterService limiter,
        IfeoService ifeo,
        ActivityLog log)
    {
        _snapshots = snapshots;
        _api = api;
        _rules = rules;
        _ruleApplication = ruleApplication;
        _limiter = limiter;
        _ifeo = ifeo;
        _log = log;

        SetPriorityCommand = new RelayCommand(p => WithSelected(row => SetPriority(row, Parse<ProcessPriority>(p))));
        SetPriorityAlwaysCommand = new RelayCommand(p => WithSelected(row =>
            UpsertRule(row, r => r with { Priority = Parse<ProcessPriority>(p) })));
        SetAffinityCommand = new RelayCommand(p => WithSelected(row => SetAffinity(row, Parse<CpuAffinityMode>(p))));
        SetAffinityAlwaysCommand = new RelayCommand(p => WithSelected(row =>
            UpsertRule(row, r => r with { AffinityMode = Parse<CpuAffinityMode>(p) })));
        SetIoPriorityCommand = new RelayCommand(p => WithSelected(row => SetIo(row, Parse<IoPriorityLevel>(p))));
        SetEfficiencyCommand = new RelayCommand(p => WithSelected(row => SetEco(row, p as string == "on")));
        TrimCommand = new RelayCommand(() => WithSelected(Trim));
        KillCommand = new RelayCommand(() => WithSelected(Kill));
        RemoveRuleCommand = new RelayCommand(() => WithSelected(row =>
        {
            if (_rules.Remove(row.ExeName))
                _log.Info("Rules", $"Removed the rule for {row.ExeName}.");
            Refresh();
        }));
        LimitCpuCommand = new RelayCommand(p => WithSelected(row =>
        {
            if (int.TryParse(p as string, out var pct) && !_limiter.TryLimit(row.Pid, row.ExeName, pct, out var error))
                Report(error);
        }));
        ClearCpuLimitCommand = new RelayCommand(() => WithSelected(row =>
            _limiter.TryClearLimit(row.Pid, row.ExeName, out _)));
        SetLaunchPriorityCommand = new RelayCommand(p => WithSelected(row =>
        {
            if (!_ifeo.SetLaunchPriority(row.ExeName, Parse<ProcessPriority>(p), null, null, out var error))
                Report(error);
            else
                _log.Info("Processes",
                    $"{row.ExeName} will launch at {p} priority from now on (kernel-enforced, survives anti-cheat).");
        }));
        ClearLaunchPriorityCommand = new RelayCommand(() => WithSelected(row =>
        {
            if (!_ifeo.Clear(row.ExeName, out var error))
                Report(error);
        }));
    }

    private static T Parse<T>(object? parameter) where T : struct, Enum
        => Enum.Parse<T>(parameter as string ?? throw new ArgumentNullException(nameof(parameter)));

    private void WithSelected(Action<ProcessRow> action)
    {
        if (Selected is { } row)
            action(row);
    }

    public void Refresh()
    {
        var snapshot = _snapshots.LastSnapshot;
        if (snapshot is null)
            return;

        var filter = Filter.Trim();
        var samples = snapshot.Processes
            .Where(p => p.Pid > 4)
            .Where(p => filter.Length == 0 || p.ExeName.Contains(filter, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(p => p.CpuPct)
            .ToDictionary(p => p.Pid);

        for (int i = Processes.Count - 1; i >= 0; i--)
        {
            if (!samples.ContainsKey(Processes[i].Pid))
                Processes.RemoveAt(i);
        }

        var known = Processes.ToDictionary(r => r.Pid);
        foreach (var (pid, sample) in samples)
        {
            if (known.TryGetValue(pid, out var row))
            {
                row.Cpu = Math.Round(sample.CpuPct, 1);
                row.RamMb = Math.Round(sample.WorkingSetBytes / (1024.0 * 1024), 1);
                row.HasRule = _rules.Find(sample.ExeName) is not null;
            }
            else
            {
                Processes.Add(new ProcessRow
                {
                    Pid = pid,
                    ExeName = sample.ExeName,
                    Cpu = Math.Round(sample.CpuPct, 1),
                    RamMb = Math.Round(sample.WorkingSetBytes / (1024.0 * 1024), 1),
                    HasRule = _rules.Find(sample.ExeName) is not null,
                });
            }
        }
    }

    private void SetPriority(ProcessRow row, ProcessPriority priority)
    {
        if (_api.TrySetPriority(row.Pid, row.ExeName, priority, out var error))
            _log.Info("Processes", $"Set {row.ExeName} (PID {row.Pid}) to {priority} priority.");
        else
            Report(error);
    }

    private void SetAffinity(ProcessRow row, CpuAffinityMode mode)
    {
        var rule = new ProcessRule { ExeName = row.ExeName, AffinityMode = mode };
        _ruleApplication.Apply(row.Pid, row.ExeName, rule);
    }

    private void SetIo(ProcessRow row, IoPriorityLevel level)
    {
        if (_api.TrySetIoPriority(row.Pid, row.ExeName, level, out var error))
            _log.Info("Processes", $"Set {row.ExeName} (PID {row.Pid}) IO priority to {level}.");
        else
            Report(error);
    }

    private void SetEco(ProcessRow row, bool enable)
    {
        if (_api.TrySetEfficiencyMode(row.Pid, row.ExeName, enable, out var error))
            _log.Info("Processes", $"{(enable ? "Enabled" : "Disabled")} efficiency mode for {row.ExeName} (PID {row.Pid}).");
        else
            Report(error);
    }

    private void Trim(ProcessRow row)
    {
        if (_api.TryTrimWorkingSet(row.Pid, row.ExeName, out var error))
            _log.Info("Processes", $"Trimmed the working set of {row.ExeName} (PID {row.Pid}).");
        else
            Report(error);
    }

    private void Kill(ProcessRow row)
    {
        if (ProcessSafety.IsProtected(row.ExeName))
        {
            Report($"{row.ExeName} is protected and cannot be terminated");
            return;
        }
        if (MessageBox.Show($"Terminate {row.ExeName} (PID {row.Pid})?", "Nexus",
                MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;

        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(row.Pid);
            process.Kill();
            _log.Info("Processes", $"Terminated {row.ExeName} (PID {row.Pid}).");
        }
        catch (Exception ex)
        {
            Report(ex.Message);
        }
    }

    private void UpsertRule(ProcessRow row, Func<ProcessRule, ProcessRule> mutate)
    {
        var existing = _rules.Find(row.ExeName) ?? new ProcessRule { ExeName = row.ExeName };
        var updated = mutate(existing);
        _rules.Upsert(updated);
        _log.Info("Rules", $"Saved a persistent rule for {row.ExeName}.");
        _ruleApplication.Apply(row.Pid, row.ExeName, updated);
        Refresh();
    }

    private void Report(string? error)
    {
        if (error is not null)
            MessageBox.Show(error, "Nexus", MessageBoxButton.OK, MessageBoxImage.Warning);
    }
}
