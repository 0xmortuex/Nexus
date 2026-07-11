using System.Drawing;
using System.Windows;
using Nexus.Core.Persistence;

namespace Nexus.App.Services;

/// <summary>
/// System tray icon with quick toggles. The one WinForms dependency in the app,
/// quarantined here (WPF has no built-in NotifyIcon; the WindowsDesktop runtime
/// ships WinForms anyway, so this costs nothing extra in the published exe).
/// </summary>
public sealed class TrayIconService : IDisposable
{
    private readonly System.Windows.Forms.NotifyIcon _icon;
    private readonly ProBalanceService _proBalance;
    private readonly PowerPlanService _power;
    private readonly GameModeService _gameMode;
    private readonly SettingsService _settings;
    private readonly System.Windows.Forms.ToolStripMenuItem _proBalanceItem;
    private readonly System.Windows.Forms.ToolStripMenuItem _performanceItem;
    private readonly System.Windows.Forms.ToolStripMenuItem _gameModeItem;

    public event Action? OpenRequested;
    public event Action? ExitRequested;

    public TrayIconService(
        ProBalanceService proBalance,
        PowerPlanService power,
        GameModeService gameMode,
        SettingsService settings)
    {
        _proBalance = proBalance;
        _power = power;
        _gameMode = gameMode;
        _settings = settings;

        var menu = new System.Windows.Forms.ContextMenuStrip();

        _proBalanceItem = new System.Windows.Forms.ToolStripMenuItem("ProBalance (dynamic restraint)")
        {
            CheckOnClick = true,
        };
        _proBalanceItem.Click += (_, _) => _proBalance.SetEnabled(_proBalanceItem.Checked);

        _performanceItem = new System.Windows.Forms.ToolStripMenuItem("Performance Mode power plan")
        {
            CheckOnClick = true,
        };
        _performanceItem.Click += (_, _) =>
        {
            if (_performanceItem.Checked)
                _power.ActivatePerformanceMode();
            else
                _power.RestorePreviousPlan();
        };

        _gameModeItem = new System.Windows.Forms.ToolStripMenuItem("Game Mode for current app");
        _gameModeItem.Click += (_, _) =>
        {
            if (_gameMode.IsActive)
                _gameMode.EndManually();
            else
                _gameMode.ForceForForeground();
        };

        var open = new System.Windows.Forms.ToolStripMenuItem("Open Nexus");
        open.Click += (_, _) => OpenRequested?.Invoke();
        var exit = new System.Windows.Forms.ToolStripMenuItem("Exit");
        exit.Click += (_, _) => ExitRequested?.Invoke();

        menu.Items.Add(open);
        menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
        menu.Items.Add(_proBalanceItem);
        menu.Items.Add(_performanceItem);
        menu.Items.Add(_gameModeItem);
        menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
        menu.Items.Add(exit);
        menu.Opening += (_, _) => RefreshChecks();

        _icon = new System.Windows.Forms.NotifyIcon
        {
            Icon = SystemIcons.Application,
            Text = "Nexus Optimizer",
            Visible = true,
            ContextMenuStrip = menu,
        };
        _icon.DoubleClick += (_, _) => OpenRequested?.Invoke();

        _gameMode.StateChanged += () =>
        {
            var app = Application.Current;
            app?.Dispatcher.BeginInvoke(() =>
                _icon.Text = _gameMode.IsActive ? $"Nexus — Game Mode: {_gameMode.ActiveGame}" : "Nexus Optimizer");
        };
    }

    private void RefreshChecks()
    {
        _proBalanceItem.Checked = _settings.Current.ProBalance.Enabled;
        _performanceItem.Checked = _power.PerformanceModeActive;
        _gameModeItem.Text = _gameMode.IsActive
            ? $"End Game Mode ({_gameMode.ActiveGame})"
            : "Game Mode for current app";
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
    }
}
