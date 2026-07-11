using System.Collections.ObjectModel;
using System.Windows;
using Nexus.App.Services;
using Nexus.Core.Persistence;

namespace Nexus.App.ViewModels;

public sealed class DnsResultRow
{
    public required string Name { get; init; }
    public required string Servers { get; init; }
    public required string Latency { get; init; }
    public required DnsResolver Resolver { get; init; }
}

/// <summary>The "Memory & Network" tools: standby-list purge (manual + auto) and
/// the DNS benchmark/switcher, both with the honest caveats shown in the UI.</summary>
public sealed class ToolsViewModel : ViewModelBase
{
    private readonly StandbyListService _standby;
    private readonly DnsService _dns;
    private readonly SettingsService _settings;

    public ObservableCollection<DnsResultRow> DnsResults { get; } = [];

    public ToolsViewModel(StandbyListService standby, DnsService dns, SettingsService settings)
    {
        _standby = standby;
        _dns = dns;
        _settings = settings;

        PurgeStandbyCommand = new RelayCommand(() =>
        {
            if (_standby.TryPurge(out var error))
                MemoryStatus = "Standby list purged.";
            else
                MemoryStatus = $"Purge failed: {error}";
            OnPropertyChanged(nameof(MemoryStatus));
        });

        BenchmarkDnsCommand = new RelayCommand(async () =>
        {
            DnsStatus = "Pinging resolvers…";
            OnPropertyChanged(nameof(DnsStatus));
            var results = await _dns.BenchmarkAsync();
            DnsResults.Clear();
            foreach (var r in results.OrderBy(r => r.AverageMs ?? double.MaxValue))
                DnsResults.Add(new DnsResultRow
                {
                    Name = r.Resolver.Name,
                    Servers = $"{r.Resolver.Primary}, {r.Resolver.Secondary}",
                    Latency = r.AverageMs is { } ms ? $"{ms:F0} ms" : "no ICMP reply",
                    Resolver = r.Resolver,
                });
            DnsStatus = "Lower latency ≈ faster name lookups. This does not change bandwidth or in-game ping to the server.";
            OnPropertyChanged(nameof(DnsStatus));
        });

        ApplyDnsCommand = new RelayCommand(p =>
        {
            if (p is not DnsResultRow row)
                return;
            if (_dns.Apply(row.Resolver, out var error))
                DnsStatus = $"DNS set to {row.Name} on all adapters. Use Restore to undo.";
            else
                DnsStatus = $"Could not set DNS: {error}";
            OnPropertyChanged(nameof(DnsStatus));
            OnPropertyChanged(nameof(CanRestoreDns));
        });

        RestoreDnsCommand = new RelayCommand(() =>
        {
            if (_dns.Restore(out var error))
                DnsStatus = "Restored the previous DNS configuration.";
            else
                DnsStatus = $"Could not restore DNS: {error}";
            OnPropertyChanged(nameof(DnsStatus));
            OnPropertyChanged(nameof(CanRestoreDns));
        });
    }

    public string MemoryStatus { get; private set; } = "Purging frees cached (standby) pages. Windows normally reuses them on demand, so only purge if you see standby-bloat stutter.";
    public string DnsStatus { get; private set; } = "Benchmark public DNS resolvers on your own connection, then switch with one click (fully reversible).";
    public bool CanRestoreDns => _dns.HasAppliedCustomDns;

    public bool AutoPurgeStandby
    {
        get => _settings.Current.Memory.AutoPurgeStandby;
        set { _settings.Update(s => s with { Memory = s.Memory with { AutoPurgeStandby = value } }); OnPropertyChanged(); }
    }

    public int FreeMemoryThresholdMb
    {
        get => _settings.Current.Memory.FreeMemoryThresholdMb;
        set { _settings.Update(s => s with { Memory = s.Memory with { FreeMemoryThresholdMb = value } }); OnPropertyChanged(); }
    }

    public RelayCommand PurgeStandbyCommand { get; }
    public RelayCommand BenchmarkDnsCommand { get; }
    public RelayCommand ApplyDnsCommand { get; }
    public RelayCommand RestoreDnsCommand { get; }
}
