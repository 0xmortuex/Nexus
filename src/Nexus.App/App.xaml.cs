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

    /// <summary>
    /// False until the main window is up. Until then an unhandled exception must be
    /// shown and the app closed, not swallowed — a swallowed startup failure leaves a
    /// process running with no window, which the user can only find in Task Manager.
    /// </summary>
    private bool _startupCompleted;

    private Mutex? _singleInstanceMutex;
    private ScanRequestChannel? _scanRequests;
    private ActivityLog? _log;
    private MainWindow? _window;
    private TrayIconService? _tray;
    private Action? _showWizard;
    private readonly List<IDisposable> _disposables = [];

    /// <summary>
    /// Pull the path out of <c>--scan "C:\some\file"</c>.
    ///
    /// Returns null when the switch is absent or names something that no longer
    /// exists, so a stale shortcut cannot make Nexus report on nothing.
    /// </summary>
    private static string? ReadScanArgument(string[] args)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (!string.Equals(args[i], "--scan", StringComparison.OrdinalIgnoreCase))
                continue;

            var path = args[i + 1];
            if (System.IO.File.Exists(path) || System.IO.Directory.Exists(path))
                return path;

            return null;
        }

        return null;
    }

    /// <summary>
    /// Act on a right-click scan: show the window, switch to Security, and scan.
    ///
    /// Bringing the window up is the point. A scan the user asked for that reports
    /// into a tray icon they cannot see has not answered their question.
    /// </summary>
    private void HandleScanRequest(ViewModels.MainViewModel mainViewModel, string path)
    {
        if (_window is null || path.Length == 0)
            return;

        _window.Show();
        _window.WindowState = WindowState.Normal;
        _window.Activate();

        _window.ShowSecurityTab();
        _ = mainViewModel.Security.ScanPathAsync(path);
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        string? scanRequest = ReadScanArgument(e.Args);

        _singleInstanceMutex = new Mutex(true, @"Global\NexusOptimizerSingleInstance", out bool isNew);
        if (!isNew)
        {
            // A right-click "Scan with Nexus" while Nexus is already running. Hand the
            // path to the instance that has the window and exit quietly — telling the
            // user their own program is already running, when they just asked it to do
            // something, is not an answer.
            if (scanRequest is not null && ScanRequestChannel.TrySend(scanRequest, TimeSpan.FromSeconds(3)))
            {
                Shutdown();
                return;
            }

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

            // Swallowing is right AFTER the window exists: one broken tab should not
            // take the optimizer engines down with it, and the Log tab shows what
            // happened. Before that, it is badly wrong — it leaves a process running
            // with no window and no way to reach it, which is exactly what happened
            // when a settings file written by an older build produced a null section.
            // A startup failure has to be visible.
            if (!_startupCompleted)
            {
                MessageBox.Show(
                    "Nexus could not finish starting up.\n\n" +
                    $"{args.Exception.GetType().Name}: {args.Exception.Message}\n\n" +
                    $"The full details are in:\n{paths.LogsDirectory}\n\n" +
                    "Nexus will close now rather than keep running where you cannot see it.",
                    "Nexus — startup failed",
                    MessageBoxButton.OK, MessageBoxImage.Error);

                args.Handled = true;
                Shutdown(1);
                return;
            }

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
        var baselineBuilder = new KnownGoodBaselineService(log, paths, signatures, fileIdentity);
        var hashFeeds = new HashFeedImportService(log, paths);
        var reputation = new ReputationService(log, paths);
        // One worker per concurrent scan slot. A single worker would become the
        // queue every parallel file waits in.
        var scannerHost = new ScannerPool(log, Math.Clamp(Environment.ProcessorCount - 2, 2, 8));
        var autoruns = new AutorunEnumerator(log, signatures);
        // Told its own name so the helper processes Nexus launches — schtasks for the
        // autostart task, PowerShell for the Defender query — are reported as its own
        // rather than accused.
        var behaviorEngine = new BehaviorEngine(
            System.IO.Path.GetFileName(Environment.ProcessPath) ?? "Nexus.exe");
        var behaviourWatcher = new ProcessDetailWatcher(log, behaviorEngine);
        var trustStore = new TrustStore(paths);
        var shellMenu = new ShellIntegrationService(log, Environment.ProcessPath ?? "");
        var scanHistory = new ScanHistory(paths);
        var quarantineJournal = new QuarantineJournal(paths);
        var quarantine = new QuarantineService(quarantineJournal, paths, log);
        var verdictCache = new VerdictCache(paths, SentinelRulesVersion);
        var massChange = new MassChangeDetector();
        var ransomwareGuard = new RansomwareGuardService(log, massChange);
        var defenderHealth = new DefenderHealthService(log);
        var networkMonitor = new NetworkMonitorService(log);
        var systemIntegrity = new SystemIntegrityService(log, () => dns.HasAppliedCustomDns);
        var sentinel = new SentinelService(
            log, fileIdentity, signatures, reputation, scannerHost,
            autoruns, behaviourWatcher, behaviorEngine, trustStore, verdictCache,
            ransomwareGuard, massChange, defenderHealth, networkMonitor, systemIntegrity, settings,
            baselineBuilder, hashFeeds, scanHistory, () => gameMode.IsActive);

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
        var scheduledScan = new ScheduledScanService(
            log, sentinel, settings, scanHistory,
            () => gameMode.IsActive, IdleSaverService.GetIdleTime);

        var sentinelReset = new SentinelResetService(
            quarantine, quarantineJournal, trustStore, verdictCache, baselines, ransomwareGuard,
            shellMenu, paths, log);
        var restoreDefaults = new RestoreDefaultsService(
            tweaks, debloat, gameMode, recovery, power, rules, games, autostart, keepAwake, dns,
            sentinelReset, log);

        _disposables.AddRange([watcher, ruleApplication, proBalance, enforcement,
            idleSaver, smartTrim, keepAwake, standby, foreground, gameMode,
            foregroundBoost, lifecycle, limiter, balancer, timerResolution, sentinel,
            scheduledScan]);

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
        scheduledScan.Start();

        // ---- UI ----
        var mainViewModel = new MainViewModel(settings)
        {
            Dashboard = new DashboardViewModel(proBalance, rules, topology, rating, sentinel),
            Suggestions = new SuggestionsViewModel(suggestions),
            Processes = new ProcessesViewModel(proBalance, api, rules, ruleApplication, limiter, ifeo, log),
            GameMode = new GameModeViewModel(gameMode, games, settings, topology.Topology.IsHybrid),
            Tweaks = new TweaksViewModel(tweaks, debloat, cleaner, startup),
            Tools = new ToolsViewModel(standby, dns, settings),
            Security = new SecurityViewModel(
                sentinel, quarantine, quarantineJournal, trustStore, scheduledScan,
                baselineBuilder, hashFeeds, scanHistory),
            Latency = new LatencyViewModel(timerResolution, bootTimer, interrupts, nic, benchmark, baselines),
            Log = new LogViewModel(log),
            Settings = new SettingsViewModel(settings, autostart, keepAwake, shellMenu),
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
            var wizardVm = new WizardViewModel(
                suggestions, rating, rating.RateGames, settings, baselineBuilder, hashFeeds, () =>
            {
                settings.Update(s => s with { WizardCompleted = true });
                mainViewModel.Dashboard.RefreshRating();
                mainViewModel.Suggestions.Refresh();
                mainViewModel.GameMode.Reload();
            });
            var wizard = new WizardWindow(wizardVm) { Owner = _window };
            wizard.ShowDialog();
        };

        _tray = new TrayIconService(proBalance, power, gameMode, settings, sentinel);
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

        // Right-click scan requests from later launches. Started before the window is
        // shown so a request that arrives during startup is not dropped.
        _scanRequests = new ScanRequestChannel(log, path =>
            Dispatcher.Invoke(() => HandleScanRequest(mainViewModel, path)));
        _scanRequests.Start();

        _window.Show();

        // A path passed on this launch's own command line, once the UI exists to show
        // the result in.
        if (scanRequest is not null)
            Dispatcher.BeginInvoke(() => HandleScanRequest(mainViewModel, scanRequest));

        _startupCompleted = true;
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
        Interop.Security.AuthenticodeVerifier.ReleaseCatalogContexts();
        _scanRequests?.Dispose();
        _singleInstanceMutex?.Dispose();
        base.OnExit(e);
    }
}
