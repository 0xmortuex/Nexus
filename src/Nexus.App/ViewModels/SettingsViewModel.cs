using Nexus.App.Services;
using Nexus.Core.Persistence;

namespace Nexus.App.ViewModels;

public sealed class SettingsViewModel : ViewModelBase
{
    private readonly SettingsService _settings;
    private readonly AutostartService _autostart;
    private readonly KeepAwakeService _keepAwake;

    public SettingsViewModel(SettingsService settings, AutostartService autostart, KeepAwakeService keepAwake)
    {
        _settings = settings;
        _autostart = autostart;
        _keepAwake = keepAwake;
        _startWithWindows = autostart.IsEnabled();
        keepAwake.EnabledChanged += _ => OnPropertyChanged(nameof(KeepAwake));
    }

    // ---- Security ----
    // Changes here take effect on the next start: stopping a running WMI subscription
    // or tearing down filesystem watchers midway is a good way to leave the module in
    // a half-on state that reports nothing while looking active. Saying "after a
    // restart" is honest; silently doing nothing would not be.

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

    public bool ScanRemovableDrives
    {
        get => _settings.Current.Security.ScanRemovableDrives;
        set { _settings.Update(s => s with { Security = s.Security with { ScanRemovableDrives = value } }); OnPropertyChanged(); }
    }

    public bool CheckDefenderHealth
    {
        get => _settings.Current.Security.CheckDefenderHealth;
        set { _settings.Update(s => s with { Security = s.Security with { CheckDefenderHealth = value } }); OnPropertyChanged(); }
    }

    public bool ScheduledQuickScan
    {
        get => _settings.Current.Security.ScheduledQuickScan;
        set { _settings.Update(s => s with { Security = s.Security with { ScheduledQuickScan = value } }); OnPropertyChanged(); }
    }

    // ---- ProBalance ----
    public double LoadEnterPct
    {
        get => _settings.Current.ProBalance.SystemLoadEnterPct;
        set { _settings.Update(s => s with { ProBalance = s.ProBalance with { SystemLoadEnterPct = value } }); OnPropertyChanged(); }
    }

    public double LoadExitPct
    {
        get => _settings.Current.ProBalance.SystemLoadExitPct;
        set { _settings.Update(s => s with { ProBalance = s.ProBalance with { SystemLoadExitPct = value } }); OnPropertyChanged(); }
    }

    public int SustainMs
    {
        get => _settings.Current.ProBalance.SustainMs;
        set { _settings.Update(s => s with { ProBalance = s.ProBalance with { SustainMs = value } }); OnPropertyChanged(); }
    }

    public int ReleaseMs
    {
        get => _settings.Current.ProBalance.ReleaseMs;
        set { _settings.Update(s => s with { ProBalance = s.ProBalance with { ReleaseMs = value } }); OnPropertyChanged(); }
    }

    public int MinRestraintMs
    {
        get => _settings.Current.ProBalance.MinRestraintMs;
        set { _settings.Update(s => s with { ProBalance = s.ProBalance with { MinRestraintMs = value } }); OnPropertyChanged(); }
    }

    public double ProcessCpuThresholdPct
    {
        get => _settings.Current.ProBalance.ProcessCpuThresholdPct;
        set { _settings.Update(s => s with { ProBalance = s.ProBalance with { ProcessCpuThresholdPct = value } }); OnPropertyChanged(); }
    }

    public string ProBalanceExclusions
    {
        get => string.Join(", ", _settings.Current.ProBalance.UserExclusions);
        set
        {
            var list = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            _settings.Update(s => s with { ProBalance = s.ProBalance with { UserExclusions = list } });
            OnPropertyChanged();
        }
    }

    // ---- IdleSaver ----
    public bool IdleSaverEnabled
    {
        get => _settings.Current.IdleSaver.Enabled;
        set { _settings.Update(s => s with { IdleSaver = s.IdleSaver with { Enabled = value } }); OnPropertyChanged(); }
    }

    public int IdleMinutes
    {
        get => _settings.Current.IdleSaver.IdleMinutes;
        set { _settings.Update(s => s with { IdleSaver = s.IdleSaver with { IdleMinutes = value } }); OnPropertyChanged(); }
    }

    // ---- SmartTrim ----
    public bool SmartTrimEnabled
    {
        get => _settings.Current.SmartTrim.Enabled;
        set { _settings.Update(s => s with { SmartTrim = s.SmartTrim with { Enabled = value } }); OnPropertyChanged(); }
    }

    public int TrimThresholdMb
    {
        get => _settings.Current.SmartTrim.WorkingSetThresholdMb;
        set { _settings.Update(s => s with { SmartTrim = s.SmartTrim with { WorkingSetThresholdMb = value } }); OnPropertyChanged(); }
    }

    public int TrimIntervalMinutes
    {
        get => _settings.Current.SmartTrim.IntervalMinutes;
        set { _settings.Update(s => s with { SmartTrim = s.SmartTrim with { IntervalMinutes = value } }); OnPropertyChanged(); }
    }

    // ---- Misc ----
    public bool ForegroundBoost
    {
        get => _settings.Current.ForegroundBoost;
        set { _settings.Update(s => s with { ForegroundBoost = value }); OnPropertyChanged(); }
    }

    public bool KeepAwake
    {
        get => _keepAwake.Enabled;
        set { _keepAwake.SetEnabled(value); OnPropertyChanged(); }
    }

    private bool _startWithWindows;
    public bool StartWithWindows
    {
        get => _startWithWindows;
        set
        {
            if (_autostart.SetEnabled(value))
                _startWithWindows = value;
            OnPropertyChanged();
        }
    }
}
