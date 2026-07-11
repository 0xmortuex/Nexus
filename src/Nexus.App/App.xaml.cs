using System.Windows;
using Nexus.App.Interop;
using Nexus.App.Services;
using Nexus.App.TweaksImpl;
using Nexus.App.ViewModels;
using Nexus.Core.GameMode;
using Nexus.Core.Logging;
using Nexus.Core.Persistence;
using Nexus.Core.Rules;
using Nexus.Core.Tweaks;

namespace Nexus.App;

public partial class App : System.Windows.Application
{
    private Mutex? _singleInstanceMutex;
    private ActivityLog? _log;
    private MainWindow? _window;
    private TrayIconService? _tray;
    private readonly List<IDisposable> _disposables = [];

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _singleInstanceMutex = new Mutex(true, @"Global\NexusOptimizerSingleInstance", out bool isNew);
        if (!isNew)
        {
            MessageBox.Show("Nexus is already running (check the tray).", "Nexus",
                MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        // ---- Composition root ----
        var paths = NexusPaths.Default();
        var log = _log = new ActivityLog(paths.LogsDirectory);
        log.Info("App", "Nexus starting.");

        DispatcherUnhandledException += (_, args) =>
        {
            log.Error("App", $"Unhandled UI exception: {args.Exception}");
            args.Handled = true; // keep the engines alive; the log tab shows the details
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            log.Error("App", $"Unhandled exception: {args.ExceptionObject}");

        var settings = new SettingsService(paths);
        var api = new ProcessApi(log);
        var topology = new CpuTopologyProvider(log);
        var sampler = new SystemSampler();
        var rules = new RulesRepository(paths);
        var games = new GameProfileRepository(paths);
        var journal = new IntendedStateJournal(paths);

        var watcher = new FailoverProcessWatcher(log);
        var kills = new KillTracker();
        var limiter = new CpuLimiterService(log);
        var ruleApplication = new RuleApplicationService(watcher, rules, api, topology, limiter, log);
        var proBalance = new ProBalanceService(sampler, api, log, settings);
        var enforcement = new EnforcementService(watcher, proBalance, api, log, settings, kills);
        var power = new PowerPlanService(log, settings);
        var idleSaver = new IdleSaverService(power, log, settings);
        var smartTrim = new SmartTrimService(proBalance, api, log, settings);
        var keepAwake = new KeepAwakeService(log);
        var standby = new StandbyListService(log, settings, proBalance);
        var foreground = new ForegroundMonitor();
        var gameMode = new GameModeService(foreground, proBalance, games, journal, api, topology, power, log, settings);
        var foregroundBoost = new ForegroundBoostService(foreground, api, log, settings, gameMode);
        var lifecycle = new RuleLifecycleService(watcher, rules, keepAwake, limiter, kills, log);
        var dns = new DnsService(log, paths);
        var balancer = new InstanceBalancerService(watcher, api, topology, settings, log);
        var timerResolution = new TimerResolutionService(log, settings);
        var ifeo = new IfeoService(log);
        var bootTimer = new BootTimerService(log);
        var interrupts = new InterruptTuningService(log);
        var nic = new NicTuningService(log);
        var recovery = new CrashRecoveryService(journal, api, power, log);
        idleSaver.IsSuppressed = () => gameMode.IsActive;

        var tweakState = new TweakStateStore(paths);
        var registryApplier = new RegistryTweakApplier();
        var backup = new BackupService(paths, log);
        var tweaks = new TweakService(registryApplier, backup, tweakState, log);
        var debloat = new DebloatService(tweakState, log);
        var cleaner = new CleanerService(log);
        var startup = new StartupManagerService(log);
        var autostart = new AutostartService(log);
        var suggestions = new SuggestionService(tweaks, debloat, settings, games, power, topology, log);
        var restoreDefaults = new RestoreDefaultsService(
            tweaks, debloat, gameMode, recovery, power, rules, games, autostart, keepAwake, dns, log);

        _disposables.AddRange([watcher, ruleApplication, proBalance, enforcement,
            idleSaver, smartTrim, keepAwake, standby, foreground, gameMode,
            foregroundBoost, lifecycle, limiter, balancer, timerResolution]);

        // ---- Crash recovery BEFORE any engine starts mutating ----
        recovery.RecoverIfNeeded();

        // ---- Start engines ----
        watcher.Start();
        ruleApplication.Start();
        proBalance.Start();
        enforcement.Start();
        idleSaver.Start();
        smartTrim.Start();
        standby.Start();
        foreground.Start();
        gameMode.Start();
        foregroundBoost.Start();
        lifecycle.Start();
        balancer.Start();
        timerResolution.Start();

        // ---- UI ----
        var mainViewModel = new MainViewModel
        {
            Dashboard = new DashboardViewModel(proBalance, rules, topology),
            Suggestions = new SuggestionsViewModel(suggestions),
            Processes = new ProcessesViewModel(proBalance, api, rules, ruleApplication, limiter, ifeo, log),
            GameMode = new GameModeViewModel(gameMode, games, settings),
            Tweaks = new TweaksViewModel(tweaks, debloat, cleaner, startup),
            Tools = new ToolsViewModel(standby, dns, settings),
            Latency = new LatencyViewModel(timerResolution, bootTimer, interrupts, nic),
            Log = new LogViewModel(log),
            Settings = new SettingsViewModel(settings, autostart, keepAwake),
            RestoreDefaultsCommand = new RelayCommand(() =>
            {
                if (MessageBox.Show(
                        "Undo every tweak, re-enable disabled services and tasks, clear all process rules and game profiles, remove the Nexus power plan, and turn off autostart?",
                        "Nexus — Restore all defaults", MessageBoxButton.YesNo, MessageBoxImage.Warning)
                    != MessageBoxResult.Yes)
                    return;
                var failures = restoreDefaults.RestoreEverything();
                MessageBox.Show(failures.Count == 0
                        ? "All defaults restored."
                        : "Restored with issues:\n" + string.Join('\n', failures),
                    "Nexus", MessageBoxButton.OK,
                    failures.Count == 0 ? MessageBoxImage.Information : MessageBoxImage.Warning);
            }),
        };

        _window = new MainWindow(mainViewModel);

        _tray = new TrayIconService(proBalance, power, gameMode, settings);
        _tray.OpenRequested += () =>
        {
            _window.Show();
            _window.WindowState = WindowState.Normal;
            _window.Activate();
        };
        _tray.ExitRequested += () =>
        {
            _window.MinimizeToTrayOnClose = false;
            Shutdown();
        };

        _window.Show();
        log.Info("App", "Nexus ready. Closing the window minimizes to the tray.");
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _log?.Info("App", "Nexus shutting down; restoring anything still boosted or restrained.");
        _tray?.Dispose();
        foreach (var disposable in _disposables.AsEnumerable().Reverse())
        {
            try
            {
                disposable.Dispose();
            }
            catch (Exception ex)
            {
                _log?.Error("App", $"Cleanup error: {ex.Message}");
            }
        }
        _singleInstanceMutex?.Dispose();
        base.OnExit(e);
    }
}
