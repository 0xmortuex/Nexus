using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using Nexus.App.Services.Security;
using Nexus.Core.Security;
using Nexus.Core.Security.Persistence;

namespace Nexus.App.ViewModels;

/// <summary>One finding as the UI shows it.</summary>
public sealed class FindingRow
{
    public required Verdict Verdict { get; init; }
    public required string Name { get; init; }
    public required string Location { get; init; }
    public required string Level { get; init; }
    public required int Score { get; init; }
    public required string Origin { get; init; }

    /// <summary>Every reason, one per line — the whole point of the module is that
    /// the user can read why, not just what.</summary>
    public required string Reasons { get; init; }

    public bool CanQuarantine => QuarantineService.RefusalReason(Verdict) is null;
}

/// <summary>One file the user has vouched for.</summary>
public sealed class TrustedFileRow
{
    public required string IdentityKey { get; init; }
    public required string Name { get; init; }
    public required string When { get; init; }
}

/// <summary>One path or extension Nexus has been told to skip.</summary>
public sealed class ExclusionRow
{
    public required string Pattern { get; init; }
    public required string Kind { get; init; }

    /// <summary>Empty unless this exclusion is wide enough to be worth warning about.</summary>
    public required string Warning { get; init; }

    public bool HasWarning => Warning.Length > 0;
}

/// <summary>One installed browser extension, as the UI shows it.</summary>
public sealed class ExtensionRow
{
    public required string Name { get; init; }
    public required string Where { get; init; }
    public required string Version { get; init; }

    /// <summary>What it can do, one per line, in plain language. Empty when it asks
    /// for nothing worth mentioning.</summary>
    public required string Capabilities { get; init; }

    public bool HasCapabilities => Capabilities.Length > 0;
}

/// <summary>One quarantined file the user can put back.</summary>
public sealed class QuarantineRow
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string OriginalPath { get; init; }
    public required string When { get; init; }
    public required string Reason { get; init; }
}

/// <summary>
/// The Security tab.
///
/// Every destructive command here mints a <see cref="UserConsent"/> at the moment of
/// the click and passes it straight into the service. That is the only place in
/// Nexus where such a token is created, which keeps the "nothing happens without a
/// gesture" rule verifiable by reading one file rather than auditing the whole
/// module.
/// </summary>
public sealed class SecurityViewModel : ViewModelBase
{
    private readonly SentinelService _sentinel;
    private readonly QuarantineService _quarantine;
    private readonly QuarantineJournal _journal;
    private readonly TrustStore _trust;
    private readonly ScheduledScanService _scheduledScan;
    private readonly KnownGoodBaselineService _baseline;
    private readonly HashFeedImportService _feeds;
    private readonly ScanHistory _history;

    private CancellationTokenSource? _scanCancellation;
    private string _defenderStatus = "Checking Microsoft Defender…";
    private string _status = "Nexus watches, explains, and leaves the decisions to you. Nothing here is changed without you clicking it.";
    private bool _isScanning;

    public ObservableCollection<FindingRow> Findings { get; } = [];
    public ObservableCollection<QuarantineRow> Quarantined { get; } = [];
    public ObservableCollection<TrustedFileRow> TrustedFiles { get; } = [];
    public ObservableCollection<ProtectionComponent> Protection { get; } = [];
    public ObservableCollection<ConnectionInfo> Connections { get; } = [];
    public ObservableCollection<ExclusionRow> Exclusions { get; } = [];
    public ObservableCollection<ScanRun> History { get; } = [];
    public ObservableCollection<ExtensionRow> Extensions { get; } = [];
    public ObservableCollection<ConnectionRecord> ConnectionLog { get; } = [];

    public SecurityViewModel(
        SentinelService sentinel,
        QuarantineService quarantine,
        QuarantineJournal journal,
        TrustStore trust,
        ScheduledScanService scheduledScan,
        KnownGoodBaselineService baseline,
        HashFeedImportService feeds,
        ScanHistory history)
    {
        _sentinel = sentinel;
        _quarantine = quarantine;
        _journal = journal;
        _trust = trust;
        _scheduledScan = scheduledScan;
        _baseline = baseline;
        _feeds = feeds;
        _history = history;

        _sentinel.AlertsChanged += RefreshFindings;
        _sentinel.ProtectionStateChanged += RefreshProtectionState;
        _journal.Changed += RefreshQuarantine;
        _trust.Changed += RefreshTrusted;

        ScanFolderCommand = new RelayCommand(async p => await ScanFolderAsync(p as string), _ => !IsScanning);
        AuditStartupCommand = new RelayCommand(AuditStartup, () => !IsScanning);
        CancelScanCommand = new RelayCommand(() => _scanCancellation?.Cancel(), () => IsScanning);
        QuarantineCommand = new RelayCommand(p => Quarantine(p as FindingRow));
        TrustCommand = new RelayCommand(p => Trust(p as FindingRow));
        RestoreCommand = new RelayCommand(p => Restore(p as QuarantineRow));
        ClearFindingsCommand = new RelayCommand(() => _sentinel.ClearAlerts());
        CheckDefenderCommand = new RelayCommand(CheckDefender);
        RefreshProtectionCommand = new RelayCommand(RefreshProtection);
        DismissRansomwareAlarmCommand = new RelayCommand(DismissRansomwareAlarm);
        BuildBaselineCommand = new RelayCommand(async _ => await BuildBaselineAsync(), _ => !IsScanning);
        ImportFeedCommand = new RelayCommand(async p => await ImportFeedAsync(p as string), _ => !IsScanning);
        CheckConnectionsCommand = new RelayCommand(CheckConnections);
        QuickScanCommand = new RelayCommand(async _ => await QuickScanAsync(), _ => !IsScanning);
        RevokeTrustCommand = new RelayCommand(p => RevokeTrust(p as TrustedFileRow));
        ToggleProtectionCommand = new RelayCommand(
            async _ => await ToggleProtectionAsync(), _ => !IsTogglingProtection);
        AddExclusionCommand = new RelayCommand(AddExclusion);
        RemoveExclusionCommand = new RelayCommand(p => RemoveExclusion(p as ExclusionRow));
        BrowseExclusionCommand = new RelayCommand(BrowseForExclusion);
        AuditSystemSettingsCommand = new RelayCommand(AuditSystemSettings);
        AuditPostureCommand = new RelayCommand(AuditPosture);
        AuditExtensionsCommand = new RelayCommand(AuditExtensions);
        ScanRunningCommand = new RelayCommand(async _ => await ScanRunningAsync(), _ => !IsScanning);
        RefreshConnectionLogCommand = new RelayCommand(RefreshConnectionLog);
        BrowseScanFolderCommand = new RelayCommand(BrowseScanFolder);
        ClearConnectionLogCommand = new RelayCommand(() => { _sentinel.Connections.Clear(); RefreshConnectionLog(); });
        FullScanCommand = new RelayCommand(async _ => await FullScanAsync(), _ => !IsScanning);
        SaveReportCommand = new RelayCommand(SaveReport);
        ClearHistoryCommand = new RelayCommand(() => { _history.Clear(); RefreshHistory(); });

        RefreshDefenderStatus();

        // Findings included: Sentinel starts before the UI is built, so anything it
        // reports at startup — a Defender that is switched off, a leftover
        // quarantine problem — is already in the list by the time this runs. Without
        // this call those sit invisible until some later event happens to fire
        // AlertsChanged, and the tab looks reassuringly empty while the log says
        // otherwise.
        RefreshFindings();
        RefreshQuarantine();
        RefreshTrusted();
        RefreshProtection();
        RefreshExclusions();
        RefreshHistory();
    }

    public string Status
    {
        get => _status;
        private set => Set(ref _status, value);
    }

    public bool IsScanning
    {
        get => _isScanning;
        private set
        {
            if (!Set(ref _isScanning, value))
                return;

            OnPropertyChanged(nameof(CanScan));

            // RelayCommand re-evaluates CanExecute on CommandManager.RequerySuggested,
            // which WPF raises on input. During a long scan there may be no input at
            // all, so Stop could stay greyed out for minutes. Ask explicitly.
            System.Windows.Input.CommandManager.InvalidateRequerySuggested();
        }
    }

    public bool CanScan => !IsScanning;

    public RelayCommand ScanFolderCommand { get; }
    public RelayCommand AuditStartupCommand { get; }
    public RelayCommand CancelScanCommand { get; }
    public RelayCommand QuarantineCommand { get; }
    public RelayCommand TrustCommand { get; }
    public RelayCommand RestoreCommand { get; }
    public RelayCommand ClearFindingsCommand { get; }
    public RelayCommand CheckDefenderCommand { get; }
    public RelayCommand CheckConnectionsCommand { get; }
    public RelayCommand QuickScanCommand { get; }
    public RelayCommand RevokeTrustCommand { get; }
    public RelayCommand RefreshProtectionCommand { get; }
    public RelayCommand ToggleProtectionCommand { get; }
    public RelayCommand AddExclusionCommand { get; }
    public RelayCommand RemoveExclusionCommand { get; }
    public RelayCommand BrowseExclusionCommand { get; }
    public RelayCommand AuditSystemSettingsCommand { get; }
    public RelayCommand AuditPostureCommand { get; }
    public RelayCommand AuditExtensionsCommand { get; }
    public RelayCommand ScanRunningCommand { get; }
    public RelayCommand RefreshConnectionLogCommand { get; }
    public RelayCommand BrowseScanFolderCommand { get; }
    public RelayCommand ClearConnectionLogCommand { get; }
    public RelayCommand FullScanCommand { get; }
    public RelayCommand SaveReportCommand { get; }
    public RelayCommand ClearHistoryCommand { get; }

    // ---- The big switch ----
    //
    // One control that turns the whole security module on and off, in words rather
    // than jargon, without needing Settings or a restart. Someone who is unsure what
    // Nexus is doing to their machine should be able to stop it in one click and see
    // that it stopped.

    public bool IsProtectionOn => _sentinel.IsProtectionOn;

    public string ProtectionHeadline => _sentinel.IsProtectionOn
        ? "Protection is ON"
        : "Protection is OFF";

    public string ProtectionDetail => _sentinel.IsProtectionOn
        ? "Nexus is watching for suspicious programs, ransomware-shaped file activity and new " +
          "downloads. It reports what it finds and never blocks or deletes on its own."
        : "Nexus is not watching anything. Microsoft Defender is unaffected and still protecting " +
          "you — this switch only controls Nexus.";

    public string ProtectionButtonText => _sentinel.IsProtectionOn
        ? "Turn protection OFF"
        : "Turn protection ON";

    /// <summary>
    /// Turn protection on or off.
    ///
    /// Done off the UI thread, because stopping is not instant: the watchers wait for
    /// their background loops to unwind, and a USB scan or an ETW pump mid-work can
    /// hold that up for seconds. Run inline, that froze the window at exactly the
    /// moment the user had just clicked something — which is when they are most
    /// likely to click again.
    /// </summary>
    private async Task ToggleProtectionAsync()
    {
        bool turningOff = _sentinel.IsProtectionOn;

        Status = turningOff ? "Turning protection off…" : "Turning protection on…";
        IsTogglingProtection = true;

        try
        {
            if (turningOff)
                await Task.Run(_sentinel.StopProtection).ConfigureAwait(true);
            else
                await Task.Run(_sentinel.StartProtection).ConfigureAwait(true);

            Status = turningOff
                ? "Protection is off. Nothing is being watched. Turn it back on whenever you like."
                : "Protection is on.";
        }
        catch (Exception ex)
        {
            Status = $"Could not change protection: {ex.Message}";
        }
        finally
        {
            IsTogglingProtection = false;
            RefreshProtection();
        }
    }

    private bool _isTogglingProtection;

    /// <summary>True while the switch is being thrown, so the button can be disabled
    /// rather than letting a second click race the first.</summary>
    public bool IsTogglingProtection
    {
        get => _isTogglingProtection;
        private set
        {
            if (Set(ref _isTogglingProtection, value))
                System.Windows.Input.CommandManager.InvalidateRequerySuggested();
        }
    }

    private void RefreshProtectionState()
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            OnPropertyChanged(nameof(IsProtectionOn));
            OnPropertyChanged(nameof(ProtectionHeadline));
            OnPropertyChanged(nameof(ProtectionDetail));
            OnPropertyChanged(nameof(ProtectionButtonText));
        });

        RefreshProtection();
    }
    public RelayCommand DismissRansomwareAlarmCommand { get; }
    public RelayCommand BuildBaselineCommand { get; }
    public RelayCommand ImportFeedCommand { get; }

    /// <summary>Pre-filled in the UI so the common case is one click.</summary>
    public string DefaultFeedUrl => HashFeedImportService.DefaultFeedUrl;

    /// <summary>The small top-up list, for anyone who does not want a 42 MB download.</summary>
    public string RecentFeedUrl => HashFeedImportService.RecentFeedUrl;

    /// <summary>
    /// Import a public known-bad hash list.
    ///
    /// This is the only outbound request Sentinel ever makes, and it downloads a
    /// published list — it sends nothing about the user's files. It happens only when
    /// this button is pressed.
    /// </summary>
    private async Task ImportFeedAsync(string? source)
    {
        if (source is not { Length: > 0 })
        {
            Status = "Give a file path or an http(s) address to import from.";
            return;
        }

        IsScanning = true;
        _scanCancellation = new CancellationTokenSource();

        try
        {
            Status = $"Importing from {source}…";
            var result = await _feeds.ImportAsync(source, _scanCancellation.Token);
            Status = result.Message;
        }
        catch (OperationCanceledException)
        {
            Status = "Import stopped. Any list you already had is untouched.";
        }
        finally
        {
            IsScanning = false;
            _scanCancellation?.Dispose();
            _scanCancellation = null;
            RefreshProtection();
        }
    }

    /// <summary>
    /// Record every validly-signed binary on this machine as known-good.
    ///
    /// Without a known-good set Sentinel cannot say "clean" at all — reputation never
    /// counts as an engine consulted, so even an ordinary signed Windows program comes
    /// back "unknown". Shipping NIST's reference set is impractical (tens of
    /// gigabytes), and building the list locally is smaller, tailored to this
    /// machine's patch level, and free of licensing questions.
    /// </summary>
    private async Task BuildBaselineAsync()
    {
        IsScanning = true;
        _scanCancellation = new CancellationTokenSource();

        try
        {
            var progress = new Progress<string>(message => Status = message);
            var result = await _baseline.BuildAsync(progress, _scanCancellation.Token);

            Status = result.Message;
        }
        catch (OperationCanceledException)
        {
            Status = "Stopped. Any previous baseline is untouched.";
        }
        finally
        {
            IsScanning = false;
            _scanCancellation?.Dispose();
            _scanCancellation = null;
            RefreshProtection();
        }
    }

    /// <summary>
    /// Tell the ransomware watch that a burst of file activity was expected.
    ///
    /// Restoring a backup or bulk-converting photos looks exactly like the start of
    /// an encryption run, and only the user knows which it was. Without this, the
    /// rational response to one false alarm is to switch the whole feature off.
    /// </summary>
    private void DismissRansomwareAlarm()
    {
        _sentinel.DismissRansomwareAlarm();
        Status = "Ransomware watch reset. It will keep watching, starting from now.";
    }

    /// <summary>Re-read which parts of the module are actually working.</summary>
    private void RefreshProtection()
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            Protection.Clear();
            foreach (var component in _sentinel.ProtectionStatus())
                Protection.Add(component);
        });
    }

    /// <summary>
    /// Scan the drives the user picks, with real progress.
    ///
    /// It asks first. "Full scan" used to mean every fixed drive, decided silently,
    /// and on a machine with a second disk full of games that is a completely
    /// different job from scanning Windows.
    ///
    /// The files are counted before scanning. That is a second walk, but it only reads
    /// directory entries rather than file contents, and it buys a percentage and an
    /// estimate instead of a number climbing with no end in sight.
    /// </summary>
    private async Task FullScanAsync()
    {
        var drives = SentinelService.ScannableDrives();

        if (drives.Count == 0)
        {
            Status = "No drives available to scan.";
            return;
        }

        var systemRoot = Path.GetPathRoot(Environment.SystemDirectory);
        var chooser = new DriveChooserWindow(drives, systemRoot)
        {
            Owner = Application.Current?.MainWindow,
        };

        if (chooser.ShowDialog() != true)
        {
            Status = "Scan cancelled.";
            return;
        }

        var roots = chooser.SelectedRoots;

        IsScanning = true;
        _scanCancellation = new CancellationTokenSource();
        var token = _scanCancellation.Token;

        var started = DateTimeOffset.Now;
        int scanned = 0;
        int notable = 0;
        bool completed = true;

        try
        {
            var names = string.Join(", ", roots.Select(r => r.TrimEnd('\\')));

            ScanIsCounting = true;
            ScanProgress = 0;
            ScanDetail = "";
            Status = $"Counting the files on {names}\u2026 you can stop at any time.";

            // Counting is cancellable, and has to be: on a machine with several drives
            // it is the part that takes minutes, and Stop doing nothing during it made
            // the button look broken exactly when someone would reach for it.
            int total = await Task.Run(
                () => _sentinel.EnumerateDrives(roots, token).Count(), token).ConfigureAwait(true);

            ScanTotal = total;
            ScanIsCounting = false;

            Status = $"Scanning {total:N0} files on {names}. You can keep using the machine, " +
                     "and you can stop at any time.";

            // The whole loop stays off the UI thread.
            //
            // With ConfigureAwait(true) every single verdict resumed on the WPF
            // dispatcher -- half a million round-trips onto a thread that is also
            // drawing charts once a second. Measured on a real scan that capped the
            // whole pipeline at about 35 files a second, while the scanner workers
            // alone manage 239 and the host-side checks manage 375. The dispatcher was
            // the queue everything waited in.
            //
            // Progress is pushed to the UI on a timer instead, which is all a person
            // can read anyway.
            var lastUpdate = Stopwatch.StartNew();

            await foreach (var verdict in _sentinel
                .ScanFilesAsync(_sentinel.EnumerateDrives(roots, token), token)
                .ConfigureAwait(false))
            {
                scanned++;
                if (verdict.WarrantsAlert)
                    notable++;

                if (lastUpdate.ElapsedMilliseconds >= ProgressUpdateMs || scanned == total)
                {
                    lastUpdate.Restart();
                    PublishProgress(scanned, total, notable, DateTimeOffset.Now - started);
                }
            }

            PublishProgress(scanned, total, notable, DateTimeOffset.Now - started);

            var took = Clock(DateTimeOffset.Now - started);

            OnUi(() =>
            {
                ScanProgress = 100;

                Status = notable == 0
                    ? $"Finished: {scanned:N0} files on {names} in {took}. Nothing worth flagging."
                    : $"Finished: {scanned:N0} files on {names} in {took}, {notable} worth a look. " +
                      "Nothing was changed \u2014 read the reasons and decide for yourself.";
            });
        }
        catch (OperationCanceledException)
        {
            completed = false;
            OnUi(() => Status = scanned == 0
                ? "Stopped before scanning started. Nothing was changed."
                : $"Stopped after {scanned:N0} files. What was found is below; nothing was changed.");
        }
        finally
        {
            OnUi(() =>
            {
                IsScanning = false;
                ScanIsCounting = false;
                ScanDetail = "";
            });

            _scanCancellation?.Dispose();
            _scanCancellation = null;
            RefreshFindings();

            Record(ScanKind.FullDisk, string.Join(", ", roots), started, scanned, notable, completed);
        }
    }

    /// <summary>
    /// How often progress reaches the screen. Faster than this is not readable, and
    /// every update is a hop onto the UI thread the scan would rather not take.
    /// </summary>
    private const int ProgressUpdateMs = 250;

    /// <summary>Push one progress snapshot to the UI in a single hop.</summary>
    private void PublishProgress(int scanned, int total, int notable, TimeSpan elapsed)
    {
        var detail = $"{scanned:N0} of {total:N0}  \u00b7  {Clock(elapsed)} elapsed" +
                     Remaining(scanned, total, elapsed) +
                     $"  \u00b7  {notable} worth a look";

        double percent = total > 0 ? Math.Min(100.0, scanned * 100.0 / total) : 0;

        OnUi(() =>
        {
            ScanScanned = scanned;
            ScanNotable = notable;
            ScanProgress = percent;
            ScanDetail = detail;
        });
    }

    /// <summary>Run something on the UI thread, wherever this is called from.</summary>
    private static void OnUi(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;

        if (dispatcher is null || dispatcher.CheckAccess())
            action();
        else
            dispatcher.BeginInvoke(action);
    }

    /// <summary>A rough time-remaining, once there is enough of a rate to mean
    /// anything. Silent early on rather than showing a wild first guess.</summary>
    private static string Remaining(int scanned, int total, TimeSpan elapsed)
    {
        if (scanned < 200 || total <= scanned || elapsed.TotalSeconds < 5)
            return "";

        double perFile = elapsed.TotalSeconds / scanned;
        var left = TimeSpan.FromSeconds(perFile * (total - scanned));

        return $"  \u00b7  about {Clock(left)} left";
    }

    // ---- Progress, shown by the bar on the Security tab ----

    private double _scanProgress;
    private int _scanTotal;
    private int _scanScanned;
    private int _scanNotable;
    private bool _scanIsCounting;
    private string _scanDetail = "";

    /// <summary>0-100. Meaningless while <see cref="ScanIsCounting"/> is true.</summary>
    public double ScanProgress
    {
        get => _scanProgress;
        private set => Set(ref _scanProgress, value);
    }

    public int ScanTotal
    {
        get => _scanTotal;
        private set => Set(ref _scanTotal, value);
    }

    public int ScanScanned
    {
        get => _scanScanned;
        private set => Set(ref _scanScanned, value);
    }

    public int ScanNotable
    {
        get => _scanNotable;
        private set => Set(ref _scanNotable, value);
    }

    /// <summary>True while the files are being counted, so the bar can run
    /// indeterminate instead of sitting at zero looking stuck.</summary>
    public bool ScanIsCounting
    {
        get => _scanIsCounting;
        private set => Set(ref _scanIsCounting, value);
    }

    /// <summary>"12,400 of 96,000 · 00:01:12 elapsed · about 00:07:40 left · 2 worth a look"</summary>
    public string ScanDetail
    {
        get => _scanDetail;
        private set => Set(ref _scanDetail, value);
    }

    /// <summary>
    /// Scan whatever the user right-clicked, whether that is one file or a folder.
    ///
    /// A single file is reported even when it comes back clean. Everywhere else
    /// Nexus stays quiet about uninteresting results, but this scan was explicitly
    /// asked for, and silence in answer to a direct question reads as a failure.
    /// </summary>
    public async Task ScanPathAsync(string path)
    {
        if (IsScanning)
        {
            Status = "A scan is already running. Stop it first, or wait for it to finish.";
            return;
        }

        if (Directory.Exists(path))
        {
            await ScanFolderAsync(path).ConfigureAwait(false);
            return;
        }

        if (!File.Exists(path))
        {
            Status = $"{path} is not there any more.";
            return;
        }

        IsScanning = true;
        _scanCancellation = new CancellationTokenSource();

        var started = DateTimeOffset.Now;
        bool completed = true;
        int findings = 0;

        try
        {
            Status = $"Looking at {Path.GetFileName(path)}\u2026";

            var verdict = await _sentinel.ScanFileAsync(path, _scanCancellation.Token)
                .ConfigureAwait(false);

            if (verdict.WarrantsAlert)
                findings = 1;

            Status = verdict.WarrantsAlert
                ? $"{Path.GetFileName(path)}: {verdict.Level} at {verdict.Score}/100. The reasons are " +
                  "in the findings list below. Nothing was changed."
                : $"{Path.GetFileName(path)}: nothing worth flagging ({verdict.Score}/100). " +
                  "Nothing was changed.";
        }
        catch (OperationCanceledException)
        {
            completed = false;
            Status = "Stopped. Nothing was changed.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            completed = false;
            Status = $"Could not read {Path.GetFileName(path)}: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
            _scanCancellation?.Dispose();
            _scanCancellation = null;
            RefreshFindings();

            Record(ScanKind.SingleFile, path, started, filesScanned: 1, findings, completed);
        }
    }

    private static string Clock(TimeSpan elapsed) => elapsed.ToString(@"hh\:mm\:ss");

    /// <summary>The last two path segments — enough to show progress without
    /// spilling a 200-character path across the window.</summary>
    private static string ShortFolder(string? path)
    {
        if (path is not { Length: > 0 })
            return "…";

        var folder = Path.GetDirectoryName(path);
        if (folder is not { Length: > 0 })
            return path;

        var parts = folder.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length <= 2 ? folder : string.Join(Path.DirectorySeparatorChar, parts[^2..]);
    }

    private string _scanFolder = "";

    /// <summary>The folder in the box, so Browse can fill it in.</summary>
    public string ScanFolder
    {
        get => _scanFolder;
        set => Set(ref _scanFolder, value);
    }

    /// <summary>
    /// Pick a folder with a picker rather than typing a path.
    ///
    /// Typing one is the step people get wrong, and a mistyped path just reports
    /// "pick a folder that exists", which teaches nothing about what went wrong.
    /// </summary>
    private void BrowseScanFolder()
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "Pick a folder to scan",
            Multiselect = false,
        };

        if (dialog.ShowDialog() == true)
            ScanFolder = dialog.FolderName;
    }

    // ---- Exclusions ----

    private string _newExclusion = "";

    /// <summary>What the user has typed, or picked with Browse, but not yet added.</summary>
    public string NewExclusion
    {
        get => _newExclusion;
        set => Set(ref _newExclusion, value);
    }

    /// <summary>
    /// Fill the box with a folder chosen from a picker.
    ///
    /// Typing a path by hand is the step people get wrong, and an exclusion with a
    /// typo in it silently does nothing — the worst kind of failure, because the user
    /// believes they have switched something off and they have not.
    /// </summary>
    private void BrowseForExclusion()
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "Pick a folder for Nexus to skip",
            Multiselect = false,
        };

        if (dialog.ShowDialog() == true)
            NewExclusion = dialog.FolderName;
    }

    /// <summary>True when the skip list is empty, so the UI can say so plainly
    /// instead of showing an unexplained blank area.</summary>
    public bool SkipsNothing => Exclusions.Count == 0;

    private void AddExclusion()
    {
        Status = _sentinel.AddExclusion(NewExclusion);
        NewExclusion = "";
        RefreshExclusions();
    }

    private void RemoveExclusion(ExclusionRow? row)
    {
        if (row is null)
        {
            Status = "Pick an exclusion to remove first.";
            return;
        }

        Status = _sentinel.RemoveExclusion(row.Pattern);
        RefreshExclusions();
    }

    /// <summary>
    /// Rebuild the list, attaching each broad-exclusion warning to the row it is
    /// about rather than showing them in a separate block. A warning next to the
    /// thing it concerns gets read; a warning somewhere else does not.
    /// </summary>
    public void RefreshExclusions()
    {
        var list = _sentinel.Exclusions;
        var concerns = list.Audit();

        Application.Current?.Dispatcher.Invoke(() =>
        {
            Exclusions.Clear();

            foreach (var exclusion in list.All)
            {
                var warning = concerns.FirstOrDefault(c =>
                    c.Explanation.Contains(exclusion.Pattern, StringComparison.OrdinalIgnoreCase));

                Exclusions.Add(new ExclusionRow
                {
                    Pattern = exclusion.Pattern,
                    Kind = exclusion.IsExtension ? "Every file of this type" : "Folder and everything in it",
                    Warning = warning?.Explanation ?? "",
                });
            }

            OnPropertyChanged(nameof(SkipsNothing));
        });
    }

    // ---- Scan history ----

    /// <summary>True when nothing has been scanned yet, so the tab can say so rather
    /// than showing an empty box that could equally mean "nothing was found".</summary>
    public bool NothingScannedYet => History.Count == 0;

    public void RefreshHistory()
    {
        var runs = _history.All;

        Application.Current?.Dispatcher.Invoke(() =>
        {
            History.Clear();

            // The last 20. The rest stay on disk and go into the report.
            foreach (var run in runs.Take(20))
                History.Add(run);

            OnPropertyChanged(nameof(NothingScannedYet));
        });
    }

    private void Record(ScanKind kind, string target, DateTimeOffset started,
        int filesScanned, int findings, bool completed)
    {
        _history.Record(new ScanRun
        {
            StartedAt = started,
            Kind = kind,
            Target = target,
            FilesScanned = filesScanned,
            Findings = findings,
            DurationSeconds = (DateTimeOffset.Now - started).TotalSeconds,
            Completed = completed,
        });

        RefreshHistory();
    }

    /// <summary>
    /// Write the history out as plain text. Plain text because the thing people
    /// actually do with a scan report is paste it somewhere while asking for help.
    /// </summary>
    private void SaveReport()
    {
        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Save the scan report",
            FileName = $"nexus-scan-report-{DateTimeOffset.Now:yyyy-MM-dd}.txt",
            DefaultExt = ".txt",
            Filter = "Text file (*.txt)|*.txt|All files (*.*)|*.*",
        };

        if (dialog.ShowDialog() != true)
            return;

        try
        {
            File.WriteAllText(dialog.FileName, _history.BuildReport(DateTimeOffset.Now));
            Status = $"Report saved to {dialog.FileName}.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Status = $"Could not save the report: {ex.Message}";
        }
    }

    /// <summary>
    /// Check the programs running right now.
    ///
    /// Behaviour monitoring only sees processes as they start, so anything already
    /// running before Nexus was installed has never been looked at — which is exactly
    /// where something that wanted to stay would be.
    /// </summary>
    private async Task ScanRunningAsync()
    {
        IsScanning = true;
        _scanCancellation = new CancellationTokenSource();

        try
        {
            Status = "Checking the programs running right now…";

            int notable = await _sentinel.ScanRunningProgramsAsync(_scanCancellation.Token)
                .ConfigureAwait(false);

            Status = notable == 0
                ? "Checked every program running now. Nothing worth flagging. Nothing was changed."
                : $"Checked the programs running now and found {notable} worth a look. Nothing was " +
                  "stopped or changed — read the reasons and decide for yourself.";
        }
        catch (OperationCanceledException)
        {
            Status = "Stopped. Nothing was changed.";
        }
        finally
        {
            IsScanning = false;
            _scanCancellation?.Dispose();
            _scanCancellation = null;
            RefreshFindings();
            RefreshHistory();
        }
    }

    // ---- Network record ----

    /// <summary>True while nothing has been observed, so the panel explains itself
    /// rather than showing an empty box that could mean anything.</summary>
    public bool NoConnectionsSeen => ConnectionLog.Count == 0;

    /// <summary>
    /// Show what has been seen talking to the network this session.
    ///
    /// This is a record rather than a snapshot: the connection table is sampled while
    /// protection is on, so something that connected for four seconds an hour ago is
    /// still listed. Pressing a button would never have caught it.
    /// </summary>
    private void RefreshConnectionLog()
    {
        var records = _sentinel.Connections.All;

        ConnectionLog.Clear();
        foreach (var record in records.Take(200))
            ConnectionLog.Add(record);

        OnPropertyChanged(nameof(NoConnectionsSeen));

        Status = records.Count == 0
            ? "Nothing has been seen talking to the network yet. Sampling runs while protection is on."
            : $"{records.Count} connection(s) seen this session. This is kept in memory only " +
              "and is gone when Nexus closes — Nexus does not keep a record of where your " +
              "machine has been.";
    }

    // ---- Browser extensions ----

    private bool _extensionsChecked;

    /// <summary>True until the list has been built once, so the panel can explain
    /// itself rather than showing an empty box that looks like a result.</summary>
    public bool ExtensionsNotChecked => !_extensionsChecked;

    private void AuditExtensions()
    {
        var found = _sentinel.AuditBrowserExtensions();

        Extensions.Clear();
        foreach (var extension in found.OrderBy(e => e.Where).ThenBy(e => e.DisplayName))
        {
            Extensions.Add(new ExtensionRow
            {
                Name = extension.DisplayName,
                Where = extension.Where,
                Version = extension.Version.Length > 0 ? "v" + extension.Version : "",
                Capabilities = string.Join(
                    Environment.NewLine,
                    BrowserExtensionAudit.Capabilities(extension).Select(c => "Can " + c + ".")),
            });
        }

        _extensionsChecked = true;
        OnPropertyChanged(nameof(ExtensionsNotChecked));

        Status = found.Count == 0
            ? "No browser extensions found. Nexus reads Chrome, Edge, Brave, Vivaldi and Opera; " +
              "Firefox stores its extensions differently and is not covered."
            : $"Found {found.Count} browser extension(s), listed below with what each one is able " +
              "to do. Nexus does not remove extensions — your browser's own extensions page does " +
              "that in two clicks.";
    }

    // ---- System settings ----

    /// <summary>
    /// Check the hosts file, proxy and DNS — the settings malware changes to cut a
    /// machine off from help. Nothing here involves a running program, so no other
    /// part of Sentinel would ever notice it.
    /// </summary>
    /// <summary>
    /// Firewall, UAC, SmartScreen, Secure Boot, encryption, updates.
    ///
    /// Findings here describe configuration, not infection, and the wording says so.
    /// A user who reads "your firewall is off" as "you have a virus" has been misled
    /// by the tool, not informed by it.
    /// </summary>
    private void AuditPosture()
    {
        int found = _sentinel.AuditSecurityPosture();

        Status = found == 0
            ? "Checked the firewall, UAC, SmartScreen, Secure Boot, drive encryption and Windows " +
              "Update. Everything is set up sensibly."
            : $"Checked your Windows security settings and found {found} worth knowing about — " +
              "they are in the findings list below. These describe how the machine is set up, not " +
              "anything infecting it, and nothing was changed.";
    }

    private void AuditSystemSettings()
    {
        int found = _sentinel.AuditSystemSettings();

        Status = found == 0
            ? "Checked the hosts file, proxy and DNS servers. Nothing out of place."
            : $"Checked the hosts file, proxy and DNS servers and found {found} thing(s) worth a " +
              "look — they are in the findings list below. Nothing was changed.";
    }

    /// <summary>
    /// Withdraw a trust decision.
    ///
    /// Trusting a file is a lasting security decision, and one the user makes in a
    /// hurry from a dialog. A list they can never review or undo would be an
    /// allowlist that only grows — so this needs no confirmation and no consent
    /// token, because unlike everything else in this tab it only ever adds scrutiny.
    /// </summary>
    private void RevokeTrust(TrustedFileRow? row)
    {
        if (row is null)
            return;

        Status = _trust.Revoke(row.IdentityKey)
            ? $"{row.Name} is no longer trusted. Nexus will report on it again."
            : "That entry was already gone.";

        RefreshTrusted();
        RefreshFindings();
    }

    /// <summary>
    /// Check the folders where new files actually arrive — Downloads, the temp
    /// folders, the startup locations and the Desktop. Deliberately not a full-disk
    /// scan: that takes hours, finds nothing extra, and people cancel it.
    /// </summary>
    private async Task QuickScanAsync()
    {
        IsScanning = true;
        var started = DateTimeOffset.Now;
        int before = _sentinel.Alerts.Count;

        try
        {
            Status = "Checking your download, temp and startup folders…";
            await _scheduledScan.RunNowAsync();
            Status = "Quick check finished. Anything worth a look is in the findings list below.";
        }
        finally
        {
            IsScanning = false;
            RefreshFindings();

            // The scheduled scan does not report a file count, so this records what
            // can honestly be known: how long it took and what it raised. Claiming a
            // file count that was never measured would make the history fiction.
            Record(ScanKind.QuickCheck, "downloads, temp and startup",
                started, filesScanned: 0, findings: Math.Max(0, _sentinel.Alerts.Count - before),
                completed: true);
        }
    }

    /// <summary>Defender is the thing that actually blocks. Sentinel reports on it
    /// rather than replacing it, so its state belongs at the top of this tab.</summary>
    public string DefenderStatus
    {
        get => _defenderStatus;
        private set => Set(ref _defenderStatus, value);
    }

    private void RefreshDefenderStatus() => DefenderStatus = _sentinel.DefenderSummary;

    private void CheckDefender()
    {
        _sentinel.ReportDefenderHealth();
        RefreshDefenderStatus();
        Status = "Re-checked Microsoft Defender. Anything wrong with it is in the findings list.";
        RefreshFindings();
    }

    private void CheckConnections()
    {
        int count = _sentinel.AuditConnections();

        Application.Current?.Dispatcher.Invoke(() =>
        {
            Connections.Clear();

            // Grouped by program rather than listed per socket: a browser holds
            // dozens of connections and listing each one buries everything else.
            foreach (var connection in _sentinel.GetConnections()
                         .OrderBy(c => c.ProcessName, StringComparer.OrdinalIgnoreCase)
                         .ThenBy(c => c.RemoteAddress, StringComparer.Ordinal))
            {
                Connections.Add(connection);
            }
        });

        Status = $"{count} established connection(s) right now. Anything unusual is in the findings " +
                 "list. This is a snapshot, not a running record — a connection that opens and closes " +
                 "between checks will not appear.";

        RefreshFindings();
    }

    // ---- Scanning ----

    private async Task ScanFolderAsync(string? folder)
    {
        if (folder is not { Length: > 0 } || !Directory.Exists(folder))
        {
            Status = "Pick a folder that exists.";
            return;
        }

        IsScanning = true;
        _scanCancellation = new CancellationTokenSource();

        var started = DateTimeOffset.Now;
        bool completed = true;
        int scanned = 0;
        int notable = 0;

        var token = _scanCancellation.Token;

        try
        {
            ScanIsCounting = true;
            ScanProgress = 0;
            Status = $"Counting the files in {folder}…";

            int total = await Task.Run(
                () => _sentinel.EnumerateScannable(folder, recursive: true).TakeWhile(
                    _ => !token.IsCancellationRequested).Count(), token).ConfigureAwait(true);

            ScanIsCounting = false;
            Status = $"Scanning {total:N0} files in {folder}…";

            // Off the UI thread, for the same reason as the full scan: resuming there
            // on every file made the dispatcher the bottleneck for the whole pipeline.
            var lastUpdate = Stopwatch.StartNew();

            await foreach (var verdict in _sentinel
                .ScanFolderAsync(folder, recursive: true, token)
                .ConfigureAwait(false))
            {
                scanned++;
                if (verdict.WarrantsAlert)
                    notable++;

                if (lastUpdate.ElapsedMilliseconds >= ProgressUpdateMs || scanned == total)
                {
                    lastUpdate.Restart();
                    PublishProgress(scanned, total, notable, DateTimeOffset.Now - started);
                }
            }

            PublishProgress(scanned, total, notable, DateTimeOffset.Now - started);

            OnUi(() =>
            {
                ScanProgress = 100;

                Status = notable == 0
                    ? $"Scanned {scanned:N0} files. Nothing worth flagging. Nothing was changed."
                    : $"Scanned {scanned:N0} files and found {notable} worth a look. Nothing was " +
                      "changed — read the reasons and decide for yourself.";
            });
        }
        catch (OperationCanceledException)
        {
            completed = false;
            OnUi(() => Status = $"Stopped after {scanned:N0} files. Nothing was changed.");
        }
        finally
        {
            OnUi(() =>
            {
                IsScanning = false;
                ScanIsCounting = false;
                ScanDetail = "";
            });

            _scanCancellation?.Dispose();
            _scanCancellation = null;
            RefreshFindings();

            Record(ScanKind.Folder, folder, started, scanned, notable, completed);
        }
    }

    private void AuditStartup()
    {
        IsScanning = true;
        try
        {
            var verdicts = _sentinel.AuditStartupItems();
            int notable = verdicts.Count(v => v.WarrantsAlert);

            Status = notable == 0
                ? $"Checked {verdicts.Count} startup items. Nothing unusual."
                : $"Checked {verdicts.Count} startup items; {notable} worth a look. Nothing was disabled.";
        }
        finally
        {
            IsScanning = false;
            RefreshFindings();
        }
    }

    // ---- Actions, each gated on an explicit confirmation ----

    private void Quarantine(FindingRow? row)
    {
        if (row is null)
            return;

        if (QuarantineService.RefusalReason(row.Verdict) is { } refusal)
        {
            MessageBox.Show(refusal, "Nexus Security", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirmed = MessageBox.Show(
            $"Move {row.Name} into quarantine?\n\n{row.Verdict.Headline}\n\n{row.Reasons}\n\n" +
            "The file is moved, not deleted, and you can put it back from this tab at any time.",
            "Nexus Security — quarantine this file?",
            MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);

        if (confirmed != MessageBoxResult.Yes)
            return;

        // The gesture just happened; this is the only place a consent is minted.
        var consent = UserConsent.FromUserGesture("quarantine", row.Verdict.Target.IdentityKey, DateTimeOffset.Now);
        var result = _quarantine.Quarantine(row.Verdict, consent);

        Status = result.Message;
        RefreshQuarantine();
        RefreshFindings();
    }

    private void Trust(FindingRow? row)
    {
        if (row is null)
            return;

        if (row.Verdict.Target.Sha256 is null)
        {
            Status = "This finding has no file hash, so there is nothing stable to trust.";
            return;
        }

        var confirmed = MessageBox.Show(
            $"Stop warning about {row.Name}?\n\n{row.Reasons}\n\n" +
            "Nexus will keep analysing it and will still show its findings — it just will not " +
            "raise alerts. If the file's contents ever change, this is revoked automatically.",
            "Nexus Security — trust this file?",
            MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);

        if (confirmed != MessageBoxResult.Yes)
            return;

        var consent = UserConsent.FromUserGesture("trust", row.Verdict.Target.IdentityKey, DateTimeOffset.Now);

        Status = _trust.Trust(row.Verdict.Target, consent, DateTimeOffset.Now)
            ? $"{row.Name} is now trusted. Findings for it stay visible; alerts stop."
            : "That confirmation could not be matched to the file. Please try again.";

        RefreshFindings();
    }

    private void Restore(QuarantineRow? row)
    {
        if (row is null)
            return;

        var confirmed = MessageBox.Show(
            $"Put {row.Name} back at {row.OriginalPath}?\n\nIt was quarantined because: {row.Reason}",
            "Nexus Security — restore this file?",
            MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);

        if (confirmed != MessageBoxResult.Yes)
            return;

        Status = _quarantine.Restore(row.Id).Message;
        RefreshQuarantine();
    }

    // ---- Refresh ----

    private void RefreshFindings()
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            Findings.Clear();

            foreach (var alert in _sentinel.Alerts)
            {
                Findings.Add(new FindingRow
                {
                    Verdict = alert.Verdict,
                    Name = alert.Verdict.Target.FileName,
                    Location = alert.Verdict.Target.Path ?? "(running process)",
                    Level = Describe(alert.Verdict.Level),
                    Score = alert.Verdict.Score,
                    Origin = alert.Origin,
                    Reasons = string.Join(Environment.NewLine,
                        alert.Verdict.Reasons.Select(r => "• " + r.Explanation)),
                });
            }
        });
    }

    private void RefreshTrusted()
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            TrustedFiles.Clear();

            foreach (var decision in _trust.All())
            {
                TrustedFiles.Add(new TrustedFileRow
                {
                    IdentityKey = decision.IdentityKey,
                    Name = decision.DisplayName,
                    When = decision.DecidedAt.ToLocalTime().ToString("g"),
                });
            }
        });
    }

    private void RefreshQuarantine()
    {
        Application.Current?.Dispatcher.Invoke(() =>
        {
            Quarantined.Clear();

            foreach (var entry in _journal.Held())
            {
                Quarantined.Add(new QuarantineRow
                {
                    Id = entry.Id,
                    Name = Path.GetFileName(entry.OriginalPath),
                    OriginalPath = entry.OriginalPath,
                    When = entry.QuarantinedAt.ToLocalTime().ToString("g"),
                    Reason = entry.Reason,
                });
            }
        });
    }

    private static string Describe(ThreatLevel level) => level switch
    {
        ThreatLevel.Trusted => "Trusted",
        ThreatLevel.Clean => "Clean",
        ThreatLevel.Unknown => "Unknown",
        ThreatLevel.Suspicious => "Worth a look",
        ThreatLevel.LikelyMalicious => "Likely malicious",
        ThreatLevel.Malicious => "Known malware",
        _ => level.ToString(),
    };
}
