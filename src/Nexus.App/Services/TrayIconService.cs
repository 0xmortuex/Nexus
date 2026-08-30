using System.Drawing;
using System.Windows;
using Nexus.App.Services.Security;
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
    private readonly SentinelService _sentinel;
    private readonly System.Windows.Forms.ToolStripMenuItem _securityItem;
    private readonly System.Windows.Forms.ToolStripMenuItem _protectionItem;
    private readonly System.Windows.Forms.ToolStripMenuItem _proBalanceItem;
    private readonly System.Windows.Forms.ToolStripMenuItem _performanceItem;
    private readonly System.Windows.Forms.ToolStripMenuItem _gameModeItem;

    public event Action? OpenRequested;
    public event Action? ExitRequested;

    public TrayIconService(
        ProBalanceService proBalance,
        PowerPlanService power,
        GameModeService gameMode,
        SettingsService settings,
        SentinelService sentinel)
    {
        _proBalance = proBalance;
        _power = power;
        _gameMode = gameMode;
        _settings = settings;
        _sentinel = sentinel;

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

        // Security is a menu entry rather than a toggle: there is nothing here to
        // switch on or off, because Sentinel never acts. Clicking it opens the tab
        // where the reasons are, which is the only useful action.
        _securityItem = new System.Windows.Forms.ToolStripMenuItem("Security: checking…");
        _securityItem.Click += (_, _) => OpenRequested?.Invoke();

        // Reachable without opening the window, because the moment someone wants to
        // switch protection off is exactly the moment they do not want to hunt for it.
        _protectionItem = new System.Windows.Forms.ToolStripMenuItem("Turn protection off");
        _protectionItem.Click += (_, _) =>
        {
            if (_sentinel.IsProtectionOn)
                _sentinel.StopProtection();
            else
                _sentinel.StartProtection();
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
        menu.Items.Add(_securityItem);
        menu.Items.Add(_protectionItem);
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

        // A balloon for a genuine finding only. Sentinel cannot block anything, so a
        // notification is the entire response — which also means it has to be rare
        // enough to still mean something when it appears.
        _sentinel.AlertRaised += OnAlertRaised;
    }

    private void OnAlertRaised(SecurityAlert alert)
    {
        if (alert.Verdict.Level < Nexus.Core.Security.ThreatLevel.LikelyMalicious)
            return;

        var app = Application.Current;
        app?.Dispatcher.BeginInvoke(() =>
        {
            try
            {
                _icon.BalloonTipTitle = "Nexus Security";
                _icon.BalloonTipText = alert.Verdict.Headline + " Nothing has been changed.";
                _icon.BalloonTipIcon = System.Windows.Forms.ToolTipIcon.Warning;
                _icon.ShowBalloonTip(10_000);
            }
            catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
            {
                // The tray icon is gone; a missed balloon is not worth crashing over,
                // and the finding is already in the log and the Security tab.
            }
        });
    }

    private void RefreshChecks()
    {
        _proBalanceItem.Checked = _settings.Current.ProBalance.Enabled;
        _performanceItem.Checked = _power.PerformanceModeActive;
        _gameModeItem.Text = _gameMode.IsActive
            ? $"End Game Mode ({_gameMode.ActiveGame})"
            : "Game Mode for current app";

        var findings = _sentinel.Alerts.Count(a => a.Verdict.WarrantsAlert);
        var defender = _sentinel.DefenderStatus;

        _securityItem.Text = !_sentinel.IsProtectionOn
            ? "Security: protection is OFF"
            : defender.Available && defender.RealTimeProtectionEnabled == false
                ? "Security: Defender is OFF"
                : findings > 0
                    ? $"Security: {findings} finding(s) to review"
                    : "Security: nothing flagged";

        _protectionItem.Text = _sentinel.IsProtectionOn
            ? "Turn protection off"
            : "Turn protection ON";
    }

    public void Dispose()
    {
        _sentinel.AlertRaised -= OnAlertRaised;
        _icon.Visible = false;
        _icon.Dispose();
    }
}
