using System.Collections.ObjectModel;
using Nexus.App.Services;
using Nexus.Core.Advisor;
using Nexus.Core.Suggestions;

namespace Nexus.App.ViewModels;

public sealed class WizardRecommendationRow : ViewModelBase
{
    public Suggestion Suggestion { get; }
    private bool _checked = true;

    public WizardRecommendationRow(Suggestion suggestion)
    {
        Suggestion = suggestion;
        var info = OptimizationCatalog.Find(suggestion.TargetId);
        EffectivenessBars = (int)(info?.Effectiveness ?? Effectiveness.Moderate);
        EffectivenessLabel = (info?.Effectiveness ?? Effectiveness.Moderate).ToString();
        Pros = info is { } i1 ? "＋ " + string.Join("\n＋ ", i1.Pros) : "";
        Cons = info is { } i2 ? "－ " + string.Join("\n－ ", i2.Cons) : "";
    }

    public string Title => Suggestion.Title;
    public string Reason => Suggestion.Reason;
    public bool Actionable => Suggestion.Kind != SuggestionKind.Hint;
    public int EffectivenessBars { get; }
    public string EffectivenessLabel { get; }
    public string Pros { get; }
    public string Cons { get; }

    public bool Checked
    {
        get => _checked && Actionable;
        set => Set(ref _checked, value);
    }
}

public sealed class WizardGameRow
{
    public WizardGameRow(GameRating rating)
    {
        ExeName = rating.ExeName;
        Score = rating.Score;
        Grade = rating.Grade;
        Detail = string.Join("\n", rating.Aspects.Select(a => $"{(a.Active ? "✓" : "·")} {a.Name} — {a.Note}"));
    }

    public string ExeName { get; }
    public int Score { get; }
    public string Grade { get; }
    public string Detail { get; }
}

/// <summary>
/// The Hone-style first-run setup wizard: Welcome → Scan → Recommendations →
/// Games → Apply → Finish. Shows the honest effectiveness meter and pros/cons for
/// each recommendation, the system rating before and after, and per-game ratings.
/// Nothing is applied until the Apply step.
/// </summary>
public sealed class WizardViewModel : ViewModelBase
{
    private readonly SuggestionService _suggestions;
    private readonly RatingService _rating;
    private readonly Func<IReadOnlyList<GameRating>> _games;
    private readonly Action _onFinished;

    public ObservableCollection<WizardRecommendationRow> Recommendations { get; } = [];
    public ObservableCollection<WizardGameRow> Games { get; } = [];

    private WizardStepId _step = WizardStepId.Welcome;

    public WizardViewModel(
        SuggestionService suggestions,
        RatingService rating,
        Func<IReadOnlyList<GameRating>> games,
        Action onFinished)
    {
        _suggestions = suggestions;
        _rating = rating;
        _games = games;
        _onFinished = onFinished;

        NextCommand = new RelayCommand(Next, () => !IsLastStep);
        BackCommand = new RelayCommand(Back, () => WizardModel.Previous(_step) is not null);
        FinishCommand = new RelayCommand(Finish);

        BeforeScore = _rating.RateSystem().Score;
        LoadStepData();
    }

    public string StepTitle => WizardModel.Step(_step).Title;
    public string StepSubtitle => WizardModel.Step(_step).Subtitle;
    public string StepProgress => $"Step {WizardModel.IndexOf(_step) + 1} of {WizardModel.Steps.Count}";
    public double ProgressFraction => (double)(WizardModel.IndexOf(_step) + 1) / WizardModel.Steps.Count;
    public bool IsLastStep => WizardModel.Next(_step) is null;

    public bool IsWelcome => _step == WizardStepId.Welcome;
    public bool IsScan => _step == WizardStepId.Scan;
    public bool IsRecommendations => _step == WizardStepId.Recommendations;
    public bool IsGames => _step == WizardStepId.Games;
    public bool IsApply => _step == WizardStepId.Apply;
    public bool IsFinish => _step == WizardStepId.Finish;

    public int BeforeScore { get; }
    public string BeforeGrade => SystemRatingEngine.GradeFor(BeforeScore);
    public int AfterScore { get; private set; }
    public string AfterGrade => SystemRatingEngine.GradeFor(AfterScore);
    public string ApplySummary { get; private set; } = "";

    public RelayCommand NextCommand { get; }
    public RelayCommand BackCommand { get; }
    public RelayCommand FinishCommand { get; }

    /// <summary>Raised when the wizard should close (Finish or the window's own close).</summary>
    public event Action? CloseRequested;

    private void Next()
    {
        if (_step == WizardStepId.Apply)
            ApplyChoices();
        if (WizardModel.Next(_step) is { } next)
        {
            _step = next;
            LoadStepData();
            RaiseStepChanged();
        }
    }

    private void Back()
    {
        if (WizardModel.Previous(_step) is { } prev)
        {
            _step = prev;
            RaiseStepChanged();
        }
    }

    private void LoadStepData()
    {
        if (_step == WizardStepId.Recommendations && Recommendations.Count == 0)
        {
            foreach (var suggestion in _suggestions.GetSuggestions())
                Recommendations.Add(new WizardRecommendationRow(suggestion));
        }
        else if (_step == WizardStepId.Games)
        {
            Games.Clear();
            foreach (var rating in _games())
                Games.Add(new WizardGameRow(rating));
        }
    }

    private void ApplyChoices()
    {
        int applied = 0, failed = 0;
        foreach (var row in Recommendations.Where(r => r.Checked && r.Actionable))
        {
            if (_suggestions.Apply(row.Suggestion, out _))
                applied++;
            else
                failed++;
        }
        AfterScore = _rating.RateSystem().Score;
        ApplySummary = failed == 0
            ? $"Applied {applied} optimization(s). Everything is reversible from its tab or Restore Defaults."
            : $"Applied {applied}; {failed} could not be applied (see the Log tab).";
        OnPropertyChanged(nameof(AfterScore));
        OnPropertyChanged(nameof(AfterGrade));
        OnPropertyChanged(nameof(ApplySummary));
    }

    private void Finish()
    {
        _onFinished();
        CloseRequested?.Invoke();
    }

    private void RaiseStepChanged()
    {
        foreach (var name in new[]
        {
            nameof(StepTitle), nameof(StepSubtitle), nameof(StepProgress), nameof(ProgressFraction),
            nameof(IsLastStep), nameof(IsWelcome), nameof(IsScan), nameof(IsRecommendations),
            nameof(IsGames), nameof(IsApply), nameof(IsFinish),
        })
            OnPropertyChanged(name);
    }
}
