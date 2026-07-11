using System.Collections.ObjectModel;
using System.Windows;
using Nexus.App.TweaksImpl;
using Nexus.Core.Tweaks;

namespace Nexus.App.ViewModels;

public sealed class TweakRow : ViewModelBase
{
    private readonly TweakService _service;
    private readonly TweaksViewModel _parent;

    public TweakDefinition Tweak { get; }

    public TweakRow(TweakDefinition tweak, TweakService service, TweaksViewModel parent)
    {
        Tweak = tweak;
        _service = service;
        _parent = parent;
    }

    public string Name => Tweak.Name;
    public string Description => Tweak.Description + (Tweak.RequiresReboot ? " (reboot required)" : "");
    public string Category => Tweak.Category;
    public bool IsApplied => _service.IsApplied(Tweak.Id);
    public string ButtonText => IsApplied ? "Undo" : "Apply";

    private Nexus.Core.Advisor.OptimizationInfo? Info => Nexus.Core.Advisor.OptimizationCatalog.Find(Tweak.Id);

    /// <summary>1–4 filled bars; the honest average impact of this tweak.</summary>
    public int EffectivenessBars => (int)(Info?.Effectiveness ?? Nexus.Core.Advisor.Effectiveness.Minor);
    public string EffectivenessLabel => (Info?.Effectiveness ?? Nexus.Core.Advisor.Effectiveness.Minor).ToString();
    public string ImpactText => Info is null ? "" : SplitCamel(Info.Impact.ToString());
    public string Pros => Info is { } i ? "＋ " + string.Join("\n＋ ", i.Pros) : "";
    public string Cons => Info is { } i ? "－ " + string.Join("\n－ ", i.Cons) : "";

    private static string SplitCamel(string s)
        => string.Concat(s.Select((c, i) => i > 0 && char.IsUpper(c) ? " " + char.ToLower(c) : c.ToString()));

    public void NotifyStateChanged()
    {
        OnPropertyChanged(nameof(IsApplied));
        OnPropertyChanged(nameof(ButtonText));
    }

    public RelayCommand ToggleCommand => new(() =>
    {
        string? error;
        bool ok = IsApplied ? _service.Undo(Tweak.Id, out error) : _service.Apply(Tweak.Id, out error);
        if (!ok && error is not null)
            MessageBox.Show(error, "Nexus", MessageBoxButton.OK, MessageBoxImage.Warning);
        OnPropertyChanged(nameof(IsApplied));
        OnPropertyChanged(nameof(ButtonText));
        _parent.RefreshAll();
    });
}

public sealed class DebloatServiceRow : ViewModelBase
{
    private readonly DebloatService _service;
    public DebloatServiceEntry Entry { get; }

    public DebloatServiceRow(DebloatServiceEntry entry, DebloatService service)
    {
        Entry = entry;
        _service = service;
    }

    public string Name => Entry.DisplayName + (Entry.Warning ? "  ⚠" : "");
    public string Description => Entry.Description;
    public bool IsDisabled => _service.IsServiceDisabled(Entry.ServiceName);
    public string ButtonText => IsDisabled ? "Re-enable" : "Disable";

    public RelayCommand ToggleCommand => new(() =>
    {
        string? error;
        if (IsDisabled)
        {
            _service.RestoreService(Entry.ServiceName, out error);
        }
        else
        {
            if (Entry.Warning && MessageBox.Show(
                    $"{Entry.Description}\n\nDisable {Entry.DisplayName} anyway?",
                    "Nexus", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                return;
            _service.DisableService(Entry.ServiceName, out error);
        }
        if (error is not null)
            MessageBox.Show(error, "Nexus", MessageBoxButton.OK, MessageBoxImage.Warning);
        OnPropertyChanged(nameof(IsDisabled));
        OnPropertyChanged(nameof(ButtonText));
    });
}

public sealed class DebloatTaskRow : ViewModelBase
{
    private readonly DebloatService _service;
    public DebloatTaskEntry Entry { get; }

    public DebloatTaskRow(DebloatTaskEntry entry, DebloatService service)
    {
        Entry = entry;
        _service = service;
    }

    public string Name => Entry.TaskPath;
    public string Description => Entry.Description;
    public bool IsDisabled => _service.IsTaskDisabledByNexus(Entry.TaskPath);
    public string ButtonText => IsDisabled ? "Re-enable" : "Disable";

    public RelayCommand ToggleCommand => new(() =>
    {
        string? error;
        if (IsDisabled)
            _service.EnableTask(Entry.TaskPath, out error);
        else
            _service.DisableTask(Entry.TaskPath, out error);
        if (error is not null)
            MessageBox.Show(error, "Nexus", MessageBoxButton.OK, MessageBoxImage.Warning);
        OnPropertyChanged(nameof(IsDisabled));
        OnPropertyChanged(nameof(ButtonText));
    });
}

public sealed class AppxRow : ViewModelBase
{
    private readonly DebloatService _service;
    public DebloatAppxEntry Entry { get; }
    private bool _checked;
    private bool _removed;

    public AppxRow(DebloatAppxEntry entry, DebloatService service)
    {
        Entry = entry;
        _service = service;
    }

    public string Name => Entry.DisplayName;
    public string PackageFamily => Entry.PackageFamily;

    public bool Checked
    {
        get => _checked;
        set => Set(ref _checked, value);
    }

    public bool Removed
    {
        get => _removed;
        set => Set(ref _removed, value);
    }

    public bool Remove(out string? error) => _service.RemoveAppx(Entry.PackageFamily, out error);
}

public sealed class CleanerRow : ViewModelBase
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    private long _sizeBytes;
    private bool _checked;

    public long SizeBytes
    {
        get => _sizeBytes;
        set
        {
            if (Set(ref _sizeBytes, value))
                OnPropertyChanged(nameof(SizeText));
        }
    }

    public string SizeText => $"{SizeBytes / (1024.0 * 1024):F0} MB";

    public bool Checked
    {
        get => _checked;
        set => Set(ref _checked, value);
    }
}

public sealed class StartupRow : ViewModelBase
{
    private readonly StartupManagerService _service;
    private StartupEntry _entry;

    public StartupRow(StartupEntry entry, StartupManagerService service)
    {
        _entry = entry;
        _service = service;
    }

    public string Name => _entry.Name;
    public string Command => _entry.Command;
    public string Source => _entry.Source.ToString();

    public bool Enabled
    {
        get => _entry.Enabled;
        set
        {
            if (_service.SetEnabled(_entry, value, out var error))
                _entry = _entry with { Enabled = value };
            else if (error is not null)
                MessageBox.Show(error, "Nexus", MessageBoxButton.OK, MessageBoxImage.Warning);
            OnPropertyChanged();
        }
    }
}

public sealed class TweaksViewModel : ViewModelBase
{
    private readonly TweakService _tweaks;
    private readonly DebloatService _debloat;
    private readonly CleanerService _cleaner;
    private readonly StartupManagerService _startup;

    public ObservableCollection<TweakRow> Tweaks { get; } = [];
    public ObservableCollection<DebloatServiceRow> Services { get; } = [];
    public ObservableCollection<DebloatTaskRow> Tasks { get; } = [];
    public ObservableCollection<AppxRow> Apps { get; } = [];
    public ObservableCollection<CleanerRow> CleanTargets { get; } = [];
    public ObservableCollection<StartupRow> StartupEntries { get; } = [];

    private string _cleanerStatus = "Run a scan to see reclaimable space.";
    public string CleanerStatus
    {
        get => _cleanerStatus;
        set => Set(ref _cleanerStatus, value);
    }

    public RelayCommand ScanCommand { get; }
    public RelayCommand CleanCommand { get; }
    public RelayCommand RemoveCheckedAppsCommand { get; }
    public RelayCommand RefreshStartupCommand { get; }

    public TweaksViewModel(TweakService tweaks, DebloatService debloat, CleanerService cleaner, StartupManagerService startup)
    {
        _tweaks = tweaks;
        _debloat = debloat;
        _cleaner = cleaner;
        _startup = startup;

        foreach (var tweak in tweaks.Catalog)
            Tweaks.Add(new TweakRow(tweak, tweaks, this));
        foreach (var entry in DebloatService.Services)
            Services.Add(new DebloatServiceRow(entry, debloat));
        foreach (var entry in DebloatService.Tasks)
            Tasks.Add(new DebloatTaskRow(entry, debloat));
        foreach (var entry in DebloatService.AppxCandidates)
            Apps.Add(new AppxRow(entry, debloat));

        ScanCommand = new RelayCommand(async () =>
        {
            CleanerStatus = "Scanning…";
            var preview = await _cleaner.ScanAsync();
            CleanTargets.Clear();
            foreach (var entry in preview)
                CleanTargets.Add(new CleanerRow { Id = entry.Target.Id, Name = entry.Target.Name, SizeBytes = entry.SizeBytes });
            CleanerStatus = $"Scan complete: {preview.Sum(p => p.SizeBytes) / (1024.0 * 1024):F0} MB reclaimable. Check items, then Clean.";
        });

        CleanCommand = new RelayCommand(async () =>
        {
            var ids = CleanTargets.Where(t => t.Checked).Select(t => t.Id).ToArray();
            if (ids.Length == 0)
                return;
            if (MessageBox.Show($"Delete the contents of {ids.Length} cache location(s)? Files in use are skipped automatically.",
                    "Nexus", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
                return;
            CleanerStatus = "Cleaning…";
            long freed = await _cleaner.DeleteAsync(ids);
            CleanerStatus = $"Freed {freed / (1024.0 * 1024):F0} MB.";
            ScanCommand!.Execute(null);
        });

        RemoveCheckedAppsCommand = new RelayCommand(() =>
        {
            var selected = Apps.Where(a => a.Checked && !a.Removed).ToArray();
            if (selected.Length == 0)
                return;
            if (MessageBox.Show(
                    $"Remove {selected.Length} app(s) for the current user?\n\nThis cannot be undone from Nexus — reinstalling requires the Microsoft Store.",
                    "Nexus", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                return;
            foreach (var app in selected)
            {
                if (app.Remove(out var error))
                    app.Removed = true;
                else if (error is not null)
                    MessageBox.Show($"{app.Name}: {error}", "Nexus", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        });

        RefreshStartupCommand = new RelayCommand(RefreshStartup);
    }

    public void RefreshStartup()
    {
        Task.Run(() => _startup.Enumerate()).ContinueWith(t =>
        {
            if (t.IsFaulted)
                return;
            Application.Current.Dispatcher.Invoke(() =>
            {
                StartupEntries.Clear();
                foreach (var entry in t.Result.OrderBy(e => e.Source).ThenBy(e => e.Name))
                    StartupEntries.Add(new StartupRow(entry, _startup));
            });
        });
    }

    public void RefreshAll()
    {
        foreach (var row in Tweaks)
            row.NotifyStateChanged();
    }
}
