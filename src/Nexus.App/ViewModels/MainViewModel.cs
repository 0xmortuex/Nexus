namespace Nexus.App.ViewModels;

public sealed class MainViewModel : ViewModelBase
{
    public required DashboardViewModel Dashboard { get; init; }
    public required SuggestionsViewModel Suggestions { get; init; }
    public required ProcessesViewModel Processes { get; init; }
    public required GameModeViewModel GameMode { get; init; }
    public required TweaksViewModel Tweaks { get; init; }
    public required ToolsViewModel Tools { get; init; }
    public required LogViewModel Log { get; init; }
    public required SettingsViewModel Settings { get; init; }
    public required RelayCommand RestoreDefaultsCommand { get; init; }
}
