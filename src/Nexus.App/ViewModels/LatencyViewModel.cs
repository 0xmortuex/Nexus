using System.Collections.ObjectModel;
using System.Windows;
using Nexus.App.Services;

namespace Nexus.App.ViewModels;

public sealed class BootTimerRow : ViewModelBase
{
    private readonly BootTimerService _service;
    private readonly BootTimerSetting _setting;

    public BootTimerRow(BootTimerSetting setting, BootTimerService service)
    {
        _setting = setting;
        _service = service;
    }

    public string Name => _setting.Name;
    public string Description => _setting.Description;

    public RelayCommand ApplyCommand => new(() => Run(_service.Apply(_setting.Id, out var e), e));
    public RelayCommand UndoCommand => new(() => Run(_service.Undo(_setting.Id, out var e), e));

    private static void Run(bool ok, string? error)
    {
        if (!ok && error is not null)
            MessageBox.Show(error, "Nexus", MessageBoxButton.OK, MessageBoxImage.Warning);
    }
}

public sealed class InterruptDeviceRow : ViewModelBase
{
    private readonly InterruptTuningService _service;
    private InterruptDevice _device;

    public InterruptDeviceRow(InterruptDevice device, InterruptTuningService service)
    {
        _device = device;
        _service = service;
    }

    public string Name => _device.FriendlyName;
    public string Class => _device.Class;
    public string State => $"MSI {(_device.MsiEnabled ? "on" : "off")}" +
                           (_device.AssignedCore is { } c ? $", IRQ→CPU {c}" : "");

    public bool MsiEnabled
    {
        get => _device.MsiEnabled;
        set
        {
            if (_service.SetMsi(_device.InstancePath, value, out var error))
                _device = _device with { MsiEnabled = value };
            else if (error is not null)
                MessageBox.Show(error, "Nexus", MessageBoxButton.OK, MessageBoxImage.Warning);
            OnPropertyChanged();
            OnPropertyChanged(nameof(State));
        }
    }

    public string PinCore { get; set; } = "";

    public RelayCommand PinCommand => new(() =>
    {
        int? core = int.TryParse(PinCore, out var c) ? c : null;
        if (_service.SetIrqAffinity(_device.InstancePath, core, out var error))
            _device = _device with { AssignedCore = core };
        else if (error is not null)
            MessageBox.Show(error, "Nexus", MessageBoxButton.OK, MessageBoxImage.Warning);
        OnPropertyChanged(nameof(State));
    });
}

/// <summary>
/// The "Latency &amp; Hardware" tab: timer resolution, BCD boot-timer settings,
/// per-device interrupt tuning (MSI + IRQ affinity), and NIC latency properties.
/// Everything here is reboot-sensitive and clearly labelled; each control is
/// reversible.
/// </summary>
public sealed class LatencyViewModel : ViewModelBase
{
    private readonly TimerResolutionService _timer;
    private readonly BootTimerService _bootTimer;
    private readonly InterruptTuningService _interrupts;
    private readonly NicTuningService _nic;

    public ObservableCollection<BootTimerRow> BootSettings { get; } = [];
    public ObservableCollection<InterruptDeviceRow> Devices { get; } = [];
    public ObservableCollection<string> NicAdapters { get; } = [];

    public LatencyViewModel(
        TimerResolutionService timer,
        BootTimerService bootTimer,
        InterruptTuningService interrupts,
        NicTuningService nic)
    {
        _timer = timer;
        _bootTimer = bootTimer;
        _interrupts = interrupts;
        _nic = nic;

        foreach (var setting in BootTimerService.Settings)
            BootSettings.Add(new BootTimerRow(setting, bootTimer));

        RefreshDevicesCommand = new RelayCommand(RefreshDevices);
        ApplyNicLatencyCommand = new RelayCommand(ApplyNicLatency);
    }

    public bool HighTimerResolution
    {
        get => _timer.Enabled;
        set { _timer.SetEnabled(value); OnPropertyChanged(); OnPropertyChanged(nameof(TimerStatus)); }
    }

    public string TimerStatus => _timer.CurrentMs is { } ms
        ? $"Current system timer resolution: {ms:F2} ms."
        : "Timer resolution unknown.";

    public string NicStatus { get; private set; } =
        "Applies Interrupt Moderation / Flow Control / Energy-Efficient Ethernet = off to all up adapters. Helps only on a fast wired link; costs CPU.";

    public RelayCommand RefreshDevicesCommand { get; }
    public RelayCommand ApplyNicLatencyCommand { get; }

    public void RefreshDevices()
    {
        Task.Run(() => _interrupts.Enumerate()).ContinueWith(t =>
        {
            if (t.IsFaulted)
                return;
            Application.Current.Dispatcher.Invoke(() =>
            {
                Devices.Clear();
                foreach (var device in t.Result)
                    Devices.Add(new InterruptDeviceRow(device, _interrupts));
                NicAdapters.Clear();
                foreach (var name in _nic.GetAdapterNames())
                    NicAdapters.Add(name);
            });
        });
    }

    private void ApplyNicLatency()
    {
        Task.Run(() =>
        {
            int changed = 0;
            foreach (var adapter in _nic.GetAdapterNames())
                foreach (var (keyword, _, offValue) in NicTuningService.LatencyKeywords)
                    if (_nic.SetKeyword(adapter, keyword, offValue, out _))
                        changed++;
            Application.Current.Dispatcher.Invoke(() =>
            {
                NicStatus = $"Applied latency settings to adapters ({changed} propert(ies) changed). Not-supported properties are skipped.";
                OnPropertyChanged(nameof(NicStatus));
            });
        });
    }
}
