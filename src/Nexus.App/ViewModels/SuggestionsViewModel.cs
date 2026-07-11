using System.Collections.ObjectModel;
using System.Windows;
using Nexus.App.Services;
using Nexus.Core.Suggestions;

namespace Nexus.App.ViewModels;

public sealed class SuggestionRow : ViewModelBase
{
    private readonly SuggestionsViewModel _parent;
    public Suggestion Suggestion { get; }

    public SuggestionRow(Suggestion suggestion, SuggestionsViewModel parent)
    {
        Suggestion = suggestion;
        _parent = parent;
    }

    public string Title => Suggestion.Title;
    public string Reason => Suggestion.Reason;
    public bool Actionable => Suggestion.Kind != SuggestionKind.Hint;
    public string ActionText => Suggestion.Kind switch
    {
        SuggestionKind.ApplyTweak => "Apply",
        SuggestionKind.DisableService => "Disable",
        SuggestionKind.DisableTask => "Disable",
        SuggestionKind.EnableFeature => "Enable",
        _ => "",
    };

    public RelayCommand ApplyCommand => new(() => _parent.Apply(this));
}

/// <summary>
/// The "Suggested optimizations" panel (Hone's home-screen recommendations, done
/// honestly): every item is derived from real observed state and states its reason.
/// Applying routes through SuggestionService to a reversible change; the list
/// re-evaluates after each apply so completed items drop off.
/// </summary>
public sealed class SuggestionsViewModel : ViewModelBase
{
    private readonly SuggestionService _service;

    public ObservableCollection<SuggestionRow> Suggestions { get; } = [];

    private string _status = "";
    public string Status
    {
        get => _status;
        private set => Set(ref _status, value);
    }

    public bool HasSuggestions => Suggestions.Count > 0;

    public RelayCommand RefreshCommand { get; }

    public SuggestionsViewModel(SuggestionService service)
    {
        _service = service;
        RefreshCommand = new RelayCommand(Refresh);
        Refresh();
    }

    public void Refresh()
    {
        Suggestions.Clear();
        foreach (var suggestion in _service.GetSuggestions())
            Suggestions.Add(new SuggestionRow(suggestion, this));

        Status = Suggestions.Count == 0
            ? "Your system already matches Nexus's recommendations."
            : $"{Suggestions.Count} suggested optimization(s) based on your current system state.";
        OnPropertyChanged(nameof(HasSuggestions));
    }

    public void Apply(SuggestionRow row)
    {
        if (!_service.Apply(row.Suggestion, out var error))
        {
            MessageBox.Show(error ?? "Could not apply this suggestion.", "Nexus",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        Refresh();
    }
}
