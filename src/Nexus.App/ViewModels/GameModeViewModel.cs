using System.Collections.ObjectModel;
using Nexus.App.Services;
using Nexus.Core.GameMode;
using Nexus.Core.Persistence;

namespace Nexus.App.ViewModels;

public sealed class GameProfileRow : ViewModelBase
{
    private readonly GameProfileRepository _repository;
    private readonly bool _isHybrid;
    private GameProfile _profile;

    public GameProfileRow(GameProfile profile, GameProfileRepository repository, bool isHybrid)
    {
        _profile = profile;
        _repository = repository;
        _isHybrid = isHybrid;
    }

    public string ExeName => _profile.ExeName;

    private Nexus.Core.Advisor.GameRating Rating => Nexus.Core.Advisor.GameRatingEngine.Rate(_profile, _isHybrid);
    public int RatingScore => Rating.Score;
    public string RatingGrade => Rating.Grade;
    /// <summary>Multi-line "aspect — note" tuning breakdown for the tooltip/expander.</summary>
    public string RatingDetail => string.Join("\n",
        Rating.Aspects.Select(a => $"{(a.Active ? "✓" : "·")} {a.Name} — {a.Note}"));

    public bool Enabled
    {
        get => _profile.Enabled;
        set => Update(p => p with { Enabled = value });
    }

    public bool DemoteBackgroundHogs
    {
        get => _profile.DemoteBackgroundHogs;
        set => Update(p => p with { DemoteBackgroundHogs = value });
    }

    public bool UsePerformancePowerPlan
    {
        get => _profile.UsePerformancePowerPlan;
        set => Update(p => p with { UsePerformancePowerPlan = value });
    }

    public bool PauseWindowsUpdate
    {
        get => _profile.PauseWindowsUpdate;
        set => Update(p => p with { PauseWindowsUpdate = value });
    }

    public bool UseCpuSets
    {
        get => _profile.UseCpuSets;
        set => Update(p => p with { UseCpuSets = value });
    }

    private void Update(Func<GameProfile, GameProfile> mutate)
    {
        _profile = mutate(_profile);
        _repository.Upsert(_profile);
        OnPropertyChanged(null); // refresh every bound property incl. the rating
    }
}

public sealed class GameModeViewModel : ViewModelBase
{
    private readonly GameModeService _gameMode;
    private readonly GameProfileRepository _profiles;
    private readonly SettingsService _settings;

    public ObservableCollection<GameProfileRow> Games { get; } = [];

    private string _newGameExe = "";
    public string NewGameExe
    {
        get => _newGameExe;
        set => Set(ref _newGameExe, value);
    }

    public string StatusText => _gameMode.IsActive
        ? $"Game Mode ACTIVE — {_gameMode.ActiveGame}"
        : "No game detected.";

    public bool Enabled
    {
        get => _settings.Current.GameMode.Enabled;
        set
        {
            _settings.Update(s => s with { GameMode = s.GameMode with { Enabled = value } });
            OnPropertyChanged();
        }
    }

    public bool AutoDetect
    {
        get => _settings.Current.GameMode.AutoDetect;
        set
        {
            _settings.Update(s => s with { GameMode = s.GameMode with { AutoDetect = value } });
            OnPropertyChanged();
        }
    }

    public RelayCommand AddGameCommand { get; }
    public RelayCommand RemoveGameCommand { get; }
    public RelayCommand ForceCommand { get; }
    public RelayCommand EndCommand { get; }

    private readonly bool _isHybrid;

    public GameModeViewModel(GameModeService gameMode, GameProfileRepository profiles, SettingsService settings, bool isHybrid)
    {
        _gameMode = gameMode;
        _profiles = profiles;
        _settings = settings;
        _isHybrid = isHybrid;

        AddGameCommand = new RelayCommand(() =>
        {
            if (string.IsNullOrWhiteSpace(NewGameExe))
                return;
            _profiles.Upsert(new GameProfile { ExeName = NewGameExe.Trim() });
            NewGameExe = "";
            Reload();
        });
        RemoveGameCommand = new RelayCommand(p =>
        {
            if (p is GameProfileRow row)
            {
                _profiles.Remove(row.ExeName);
                Reload();
            }
        });
        ForceCommand = new RelayCommand(() => _gameMode.ForceForForeground());
        EndCommand = new RelayCommand(() => _gameMode.EndManually());

        _gameMode.StateChanged += () => OnPropertyChanged(nameof(StatusText));
        Reload();
    }

    public void Reload()
    {
        Games.Clear();
        foreach (var profile in _profiles.All().OrderBy(p => p.ExeName))
            Games.Add(new GameProfileRow(profile, _profiles, _isHybrid));
        OnPropertyChanged(nameof(StatusText));
    }
}
