using System.Collections.ObjectModel;
using Nexus.App.Services;
using Nexus.App.Services.Security;
using Nexus.Core.Persistence;
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
    private readonly SettingsService _settings;
    private readonly KnownGoodBaselineService _baseline;
    private readonly HashFeedImportService _feeds;
    private readonly Action _onFinished;

    private bool _isWorking;
    private string _applyProgress = "";

    public ObservableCollection<WizardRecommendationRow> Recommendations { get; } = [];
    public ObservableCollection<WizardGameRow> Games { get; } = [];

    private WizardStepId _step = WizardStepId.Welcome;

    public WizardViewModel(
        SuggestionService suggestions,
        RatingService rating,
        Func<IReadOnlyList<GameRating>> games,
        SettingsService settings,
        KnownGoodBaselineService baseline,
        HashFeedImportService feeds,
        Action onFinished)
    {
        _suggestions = suggestions;
        _rating = rating;
        _games = games;
        _settings = settings;
        _baseline = baseline;
        _feeds = feeds;
        _onFinished = onFinished;

        NextCommand = new RelayCommand(async () => await NextAsync(), () => !IsLastStep && !IsWorking);
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
    public bool IsSecurity => _step == WizardStepId.Security;
    public bool IsApply => _step == WizardStepId.Apply;
    public bool IsFinish => _step == WizardStepId.Finish;

    public int BeforeScore { get; }
    public string BeforeGrade => SystemRatingEngine.GradeFor(BeforeScore);
    public int AfterScore { get; private set; }
    public string AfterGrade => SystemRatingEngine.GradeFor(AfterScore);
    public string ApplySummary { get; private set; } = "";

    // ---- Security choices ----
    //
    // These are bound straight to settings rather than staged until Apply, because
    // they are not changes to the machine — they are consent for what Nexus itself
    // will do. Asking on the first run is the point: the ransomware watch writes
    // files into the user's own folders, and discovering that afterwards is not the
    // same as agreeing to it.

    public bool BehaviourMonitoring
    {
        get => _settings.Current.Security.BehaviourMonitoring;
        set { _settings.Update(s => s with { Security = s.Security with { BehaviourMonitoring = value } }); OnPropertyChanged(); }
    }

    public bool RansomwareWatch
    {
        get => _settings.Current.Security.RansomwareWatch;
        set { _settings.Update(s => s with { Security = s.Security with { RansomwareWatch = value } }); OnPropertyChanged(); }
    }

    public bool ScanDownloads
    {
        get => _settings.Current.Security.ScanDownloads;
        set { _settings.Update(s => s with { Security = s.Security with { ScanDownloads = value } }); OnPropertyChanged(); }
    }

    public RelayCommand NextCommand { get; }
    public RelayCommand BackCommand { get; }
    public RelayCommand FinishCommand { get; }

    /// <summary>Raised when the wizard should close (Finish or the window's own close).</summary>
    public event Action? CloseRequested;

    private async Task NextAsync()
    {
        if (_step == WizardStepId.Apply)
            await ApplyChoicesAsync();

        if (WizardModel.Next(_step) is { } next)
        {
            _step = next;
            LoadStepData();
            RaiseStepChanged();
        }
    }

    /// <summary>True while Apply is working, so the buttons cannot be double-clicked
    /// into running the setup twice.</summary>
    public bool IsWorking
    {
        get => _isWorking;
        private set
        {
            if (!Set(ref _isWorking, value))
                return;

            OnPropertyChanged(nameof(IsNotWorking));

            // RelayCommand re-queries on UI input events, which do not happen while an
            // async step is running — so Next would stay clickable through a two-minute
            // baseline build and a second click would start it again.
            System.Windows.Input.CommandManager.InvalidateRequerySuggested();
        }
    }

    public bool IsNotWorking => !_isWorking;

    /// <summary>Live progress during Apply. Building the baseline reads tens of
    /// thousands of files, and a wizard that appears frozen for two minutes is one
    /// people force-quit.</summary>
    public string ApplyProgress
    {
        get => _applyProgress;
        private set => Set(ref _applyProgress, value);
    }

    // ---- Security setup, done during Apply rather than left as homework ----
    //
    // Without a known-good baseline Nexus cannot report anything as "clean" — every
    // ordinary file comes back "unknown". Expecting a new user to know that, find the
    // Security tab and press the right button is how a feature goes unused. The
    // wizard offers to do it here, where the user is already saying yes to things.

    private bool _buildBaseline = true;
    public bool BuildBaselineNow
    {
        get => _buildBaseline;
        set => Set(ref _buildBaseline, value);
    }

    private bool _downloadHashList = true;
    public bool DownloadHashListNow
    {
        get => _downloadHashList;
        set => Set(ref _downloadHashList, value);
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

    private async Task ApplyChoicesAsync()
    {
        IsWorking = true;

        try
        {
            ApplyProgress = "Applying the optimizations you chose…";

            int applied = 0, failed = 0;
            foreach (var row in Recommendations.Where(r => r.Checked && r.Actionable))
            {
                if (_suggestions.Apply(row.Suggestion, out _))
                    applied++;
                else
                    failed++;
            }

            AfterScore = _rating.RateSystem().Score;

            var summary = failed == 0
                ? $"Applied {applied} optimization(s). Everything is reversible from its tab or Restore Defaults."
                : $"Applied {applied}; {failed} could not be applied (see the Log tab).";

            summary += await SetUpSecurityAsync();

            ApplySummary = summary;
            ApplyProgress = "";

            OnPropertyChanged(nameof(AfterScore));
            OnPropertyChanged(nameof(AfterGrade));
            OnPropertyChanged(nameof(ApplySummary));
        }
        finally
        {
            IsWorking = false;
        }
    }

    /// <summary>Do the security setup the user agreed to, and report what happened in
    /// the same sentence as everything else.</summary>
    private async Task<string> SetUpSecurityAsync()
    {
        var notes = new List<string>();

        if (BuildBaselineNow)
        {
            try
            {
                var progress = new Progress<string>(message => ApplyProgress = message);
                var result = await _baseline.BuildAsync(progress);

                notes.Add(result.HashCount > 0
                    ? $"recorded {result.HashCount:N0} known-good files on this PC"
                    : "could not record any known-good files");
            }
            catch (Exception ex)
            {
                // The wizard must finish even if this does not. A failed optional step
                // is a note, not a dead end.
                notes.Add($"the known-good baseline failed ({ex.Message})");
            }
        }

        if (DownloadHashListNow)
        {
            try
            {
                ApplyProgress = "Downloading the malware hash list…";
                var result = await _feeds.ImportAsync(HashFeedImportService.DefaultFeedUrl);

                notes.Add(result.Succeeded
                    ? $"downloaded {result.HashCount:N0} known-bad hashes"
                    : "could not download the malware hash list");
            }
            catch (Exception ex)
            {
                notes.Add($"the hash list download failed ({ex.Message})");
            }
        }

        return notes.Count == 0
            ? ""
            : " Security setup: " + string.Join("; ", notes) + ".";
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
            nameof(IsGames), nameof(IsSecurity), nameof(IsApply), nameof(IsFinish),
        })
            OnPropertyChanged(name);
    }
}
