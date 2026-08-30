using System.Windows;
using Nexus.App.Interop;
using Nexus.App.Interop.Security;
using Nexus.App.Services;
using Nexus.App.Services.Performance;
using Nexus.App.Services.Security;
using Nexus.App.TweaksImpl;
using Nexus.App.ViewModels;
using Nexus.Core.GameMode;
using Nexus.Core.Logging;
using Nexus.Core.Performance;
using Nexus.Core.Persistence;
using Nexus.Core.Rules;
using Nexus.Core.Security;
using Nexus.Core.Security.Behavior;
using Nexus.Core.Security.Ransomware;
using Nexus.Core.Tweaks;

namespace Nexus.App;

public partial class App : System.Windows.Application
{
    /// <summary>Stamped into the verdict cache. Bump this whenever a detection rule,
    /// heuristic weight, or pattern file changes, so cached conclusions from the old
    /// logic are discarded instead of suppressing a new detection.</summary>
    private const string SentinelRulesVersion = "sentinel-1";

    private Mutex? _singleInstanceMutex;
    private ActivityLog? _log;
    private MainWindow? _window;
    private TrayIconService? _tray;
    private Action? _showWizard;
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

        // ---- Performance measurement: makes "measure before trusting" executable ----
        var latencyProbe = new LatencyProbeService(log);
        var throttleDetector = new ThrottleDetectorService(log);
        var baselines = new BaselineStore(paths);
        var benchmark = new BenchmarkService(latencyProbe, baselines, throttleDetector, log);

        // ---- Sentinel: the advisory security module ----
        // Constructed after the optimizer engines because it observes them (it audits
        // Nexus's own IFEO keys and scheduled task) rather than being exempt from them.
        var signatures = new AuthenticodeVerifier(log);
        var fileIdentity = new FileIdentityService(log);
        var reputation = new ReputationService(log);
        var scannerHost = new ScannerHost(log);
        var autoruns = new AutorunEnumerator(log, signatures);
        var behaviorEngine = new BehaviorEngine();
        var behaviourWatcher = new ProcessDetailWatcher(log, behaviorEngine);
        var trustStore = new TrustStore(paths);
        var quarantineJournal = new QuarantineJournal(paths);
        var quarantine = new QuarantineService(quarantineJournal, paths, log);
        var verdictCache = new VerdictCache(paths, SentinelRulesVersion);
        var massChange = new MassChangeDetector();
        var ransomwareGuard = new RansomwareGuardService(log, massChange);
        var defenderHealth = new DefenderHealthService(log);
        var networkMonitor = new NetworkMonitorService(log);
        var sentinel = new SentinelService(
            log, fileIdentity, signatures, reputation, scannerHost,
            autoruns, behaviourWatcher, trustStore, verdictCache,
            ransomwareGuard, defenderHealth, networkMonitor, settings);

        var tweakState = new TweakStateStore(paths);
        var registryApplier = new RegistryTweakApplier();
        var backup = new BackupService(paths, log);
        var tweaks = new TweakService(registryApplier, backup, tweakState, log);
        var debloat = new DebloatService(tweakState, log);
        var cleaner = new CleanerService(log);
        var startup = new StartupManagerService(log);
        var autostart = new AutostartService(log);
        var suggestions = new SuggestionService(
            tweaks, debloat, settings, games, power, topology,
            throttleDetector, () => sentinel.DefenderStatus, log);
        var rating = new RatingService(tweaks, debloat, dns, settings, games, topology, () => keepAwake.Enabled);
        var sentinelReset = new SentinelResetService(
            quarantine, quarantineJournal, trustStore, verdictCache, baselines, ransomwareGuard, log);
        var restoreDefaults = new RestoreDefaultsService(
            tweaks, debloat, gameMode, recovery, power, rules, games, autostart, keepAwake, dns,
            sentinelReset, log);

        _disposables.AddRange([watcher, ruleApplication, proBalance, enforcement,
            idleSaver, smartTrim, keepAwake, standby, foreground, gameMode,
            foregroundBoost, lifecycle, limiter, balancer, timerResolution, sentinel]);

        // ---- Crash recovery BEFORE any engine starts mutating ----
        recovery.RecoverIfNeeded();
        quarantine.ReconcileOnStartup();

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
        sentinel.Start();

        // ---- UI ----
        var mainViewModel = new MainViewModel(settings)
        {
            Dashboard = new DashboardViewModel(proBalance, rules, topology, rating, sentinel),
            Suggestions = new SuggestionsViewModel(suggestions),
            Processes = new ProcessesViewModel(proBalance, api, rules, ruleApplication, limiter, ifeo, log),
            GameMode = new GameModeViewModel(gameMode, games, settings, topology.Topology.IsHybrid),
            Tweaks = new TweaksViewModel(tweaks, debloat, cleaner, startup),
            Tools = new ToolsViewModel(standby, dns, settings),
            Security = new SecurityViewModel(sentinel, quarantine, quarantineJournal, trustStore),
            Latency = new LatencyViewModel(timerResolution, bootTimer, interrupts, nic, benchmark, baselines),
            Log = new LogViewModel(log),
            Settings = new SettingsViewModel(settings, autostart, keepAwake),
            RestoreDefaultsCommand = new RelayCommand(() =>
            {
                if (MessageBox.Show(
                        "Undo every tweak, re-enable disabled services and tasks, clear all process rules and game profiles, remove the Nexus power plan, turn off autostart, put any quarantined files back, and remove the ransomware tripwire files?",
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
            OpenWizardCommand = new RelayCommand(() => _showWizard?.Invoke()),
        };

        _window = new MainWindow(mainViewModel);

        _showWizard = () =>
        {
            var wizardVm = new WizardViewModel(suggestions, rating, rating.RateGames, () =>
            {
                settings.Update(s => s with { WizardCompleted = true });
                mainViewModel.Dashboard.RefreshRating();
                mainViewModel.Suggestions.Refresh();
                mainViewModel.GameMode.Reload();
            });
            var wizard = new WizardWindow(wizardVm) { Owner = _window };
            wizard.ShowDialog();
        };

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

        // First run: guide the user through setup.
        if (!settings.Current.WizardCompleted)
            _window.Dispatcher.BeginInvoke(_showWizard);
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
