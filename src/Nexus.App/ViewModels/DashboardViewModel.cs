using Nexus.App.Interop;
using Nexus.App.Services;
using Nexus.Core.Models;
using Nexus.Core.Rules;

namespace Nexus.App.ViewModels;

public sealed record RestrainedRow(int Pid, string ExeName);

public sealed class DashboardViewModel : ViewModelBase
{
    private const int HistoryLength = 60;

    private readonly ProBalanceService _proBalance;
    private readonly RulesRepository _rules;
    private readonly CpuTopologyProvider _topology;
    private readonly Services.RatingService _rating;
    private readonly Queue<double> _cpuHistory = new(HistoryLength);
    private readonly Queue<double> _ramHistory = new(HistoryLength);

    public DashboardViewModel(ProBalanceService proBalance, RulesRepository rules,
        CpuTopologyProvider topology, Services.RatingService rating)
    {
        _proBalance = proBalance;
        _rules = rules;
        _topology = topology;
        _rating = rating;
        RefreshRating();
    }

    // ---- System optimization rating ----
    public int RatingScore { get; private set; }
    public string RatingGrade { get; private set; } = "—";
    public string RatingSummary { get; private set; } = "";
    public IReadOnlyList<Nexus.Core.Advisor.CategoryRating> RatingCategories { get; private set; } = [];

    /// <summary>Recomputed on demand (dashboard timer every ~10 s, and after the wizard).</summary>
    public void RefreshRating()
    {
        var rating = _rating.RateSystem();
        RatingScore = rating.Score;
        RatingGrade = rating.Grade;
        RatingSummary = rating.Summary;
        RatingCategories = rating.Categories;
        OnPropertyChanged(nameof(RatingScore));
        OnPropertyChanged(nameof(RatingGrade));
        OnPropertyChanged(nameof(RatingSummary));
        OnPropertyChanged(nameof(RatingCategories));
    }

    public IReadOnlyList<double> CpuHistory { get; private set; } = [];
    public IReadOnlyList<double> RamHistory { get; private set; } = [];
    public IReadOnlyList<double> PerCore { get; private set; } = [];
    public ulong ECoreMask => _topology.Topology.ECoreMask;
    public string CpuText { get; private set; } = "—";
    public string RamText { get; private set; } = "—";
    public string TopologyText { get; private set; } = "";
    public string RulesText { get; private set; } = "";
    public IReadOnlyList<RestrainedRow> Restrained { get; private set; } = [];
    public bool ProBalanceEnabled
    {
        get => _proBalance.Enabled;
        set
        {
            _proBalance.SetEnabled(value);
            OnPropertyChanged();
        }
    }

    /// <summary>Called on the UI thread once a second.</summary>
    public void Refresh()
    {
        var snapshot = _proBalance.LastSnapshot;
        if (snapshot is null)
            return;

        Push(_cpuHistory, snapshot.TotalCpuPct);
        double ramPct = snapshot.TotalMemoryBytes > 0
            ? 100.0 * (snapshot.TotalMemoryBytes - snapshot.AvailableMemoryBytes) / snapshot.TotalMemoryBytes
            : 0;
        Push(_ramHistory, ramPct);

        CpuHistory = _cpuHistory.ToArray();
        RamHistory = _ramHistory.ToArray();
        PerCore = snapshot.PerCoreCpuPct;
        CpuText = $"{snapshot.TotalCpuPct:F0}%";
        RamText = $"{(snapshot.TotalMemoryBytes - snapshot.AvailableMemoryBytes) / (1024.0 * 1024 * 1024):F1} / {snapshot.TotalMemoryBytes / (1024.0 * 1024 * 1024):F1} GB ({ramPct:F0}%)";

        var topology = _topology.Topology;
        TopologyText = topology.IsHybrid
            ? $"{topology.PhysicalCoreCount} cores / {topology.LogicalCpus.Count} threads (hybrid: P+E)"
            : $"{topology.PhysicalCoreCount} cores / {topology.LogicalCpus.Count} threads";
        RulesText = $"{_rules.All().Count} persistent rule(s) active";

        var restrainedPids = _proBalance.RestrainedPids.ToHashSet();
        Restrained = snapshot.Processes
            .Where(p => restrainedPids.Contains(p.Pid))
            .Select(p => new RestrainedRow(p.Pid, p.ExeName))
            .ToArray();

        OnPropertyChanged(nameof(CpuHistory));
        OnPropertyChanged(nameof(RamHistory));
        OnPropertyChanged(nameof(PerCore));
        OnPropertyChanged(nameof(CpuText));
        OnPropertyChanged(nameof(RamText));
        OnPropertyChanged(nameof(TopologyText));
        OnPropertyChanged(nameof(RulesText));
        OnPropertyChanged(nameof(Restrained));
        OnPropertyChanged(nameof(ECoreMask));
    }

    private static void Push(Queue<double> queue, double value)
    {
        if (queue.Count >= HistoryLength)
            queue.Dequeue();
        queue.Enqueue(value);
    }
}
