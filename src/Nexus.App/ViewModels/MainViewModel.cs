using Nexus.Core.Persistence;

namespace Nexus.App.ViewModels;

public sealed class MainViewModel : ViewModelBase
{
    private readonly SettingsService _settings;

    public MainViewModel(SettingsService settings)
    {
        _settings = settings;
        ToggleModeCommand = new RelayCommand(() => IsAdvanced = !IsAdvanced);
    }

    public required DashboardViewModel Dashboard { get; init; }
    public required SuggestionsViewModel Suggestions { get; init; }
    public required ProcessesViewModel Processes { get; init; }
    public required GameModeViewModel GameMode { get; init; }
    public required TweaksViewModel Tweaks { get; init; }
    public required ToolsViewModel Tools { get; init; }
    public required SecurityViewModel Security { get; init; }
    public required LatencyViewModel Latency { get; init; }
    public required LogViewModel Log { get; init; }
    public required SettingsViewModel Settings { get; init; }
    public required RelayCommand RestoreDefaultsCommand { get; init; }
    public required RelayCommand OpenWizardCommand { get; init; }

    /// <summary>Advanced (Developer) mode reveals the power-user surfaces: the
    /// Processes list, the Latency &amp; Hardware tab, and the deeper Tweaks sections.
    /// Simple mode keeps just Dashboard, Game Mode, one-click Tweaks, Log and Settings.</summary>
    public bool IsAdvanced
    {
        get => _settings.Current.AdvancedMode;
        set
        {
            if (value == _settings.Current.AdvancedMode)
                return;
            _settings.Update(s => s with { AdvancedMode = value });
            OnPropertyChanged();
            OnPropertyChanged(nameof(ModeLabel));
            OnPropertyChanged(nameof(ModeButtonText));
        }
    }

    public string ModeLabel => IsAdvanced ? "Advanced" : "Simple";
    public string ModeButtonText => IsAdvanced ? "Switch to Simple mode" : "Switch to Advanced mode";

    public RelayCommand ToggleModeCommand { get; }
}
