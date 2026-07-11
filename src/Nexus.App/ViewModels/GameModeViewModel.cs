using System.Collections.ObjectModel;
using Nexus.App.Services;
using Nexus.Core.GameMode;
using Nexus.Core.Persistence;

namespace Nexus.App.ViewModels;

public sealed class GameProfileRow : ViewModelBase
{
    private readonly GameProfileRepository _repository;
    private GameProfile _profile;

    public GameProfileRow(GameProfile profile, GameProfileRepository repository)
    {
        _profile = profile;
        _repository = repository;
    }

    public string ExeName => _profile.ExeName;

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
        OnPropertyChanged(null);
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

    public GameModeViewModel(GameModeService gameMode, GameProfileRepository profiles, SettingsService settings)
    {
        _gameMode = gameMode;
        _profiles = profiles;
        _settings = settings;

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
            Games.Add(new GameProfileRow(profile, _profiles));
        OnPropertyChanged(nameof(StatusText));
    }
}
