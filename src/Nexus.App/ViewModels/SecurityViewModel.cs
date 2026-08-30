using System.Collections.ObjectModel;
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
        ToggleProtectionCommand = new RelayCommand(ToggleProtection);
        AddExclusionCommand = new RelayCommand(AddExclusion);
        RemoveExclusionCommand = new RelayCommand(p => RemoveExclusion(p as ExclusionRow));
        BrowseExclusionCommand = new RelayCommand(BrowseForExclusion);
        AuditSystemSettingsCommand = new RelayCommand(AuditSystemSettings);
        AuditPostureCommand = new RelayCommand(AuditPosture);
        AuditExtensionsCommand = new RelayCommand(AuditExtensions);
        ScanRunningCommand = new RelayCommand(async _ => await ScanRunningAsync(), _ => !IsScanning);
        RefreshConnectionLogCommand = new RelayCommand(RefreshConnectionLog);
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
            if (Set(ref _isScanning, value))
                OnPropertyChanged(nameof(CanScan));
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

    private void ToggleProtection()
    {
        if (_sentinel.IsProtectionOn)
        {
            _sentinel.StopProtection();
            Status = "Protection is off. Nothing is being watched. Turn it back on whenever you like.";
        }
        else
        {
            _sentinel.StartProtection();
            Status = "Protection is on.";
        }

        RefreshProtection();
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
    /// Scan every fixed drive.
    ///
    /// This takes a long time — tens of minutes on a large disk — so the progress
    /// line names the file being read rather than only counting. A progress display
    /// that sits on "scanning…" for half an hour is indistinguishable from one that
    /// has hung, and the user's only recourse is to kill the program.
    /// </summary>
    private async Task FullScanAsync()
    {
        IsScanning = true;
        _scanCancellation = new CancellationTokenSource();

        var started = DateTimeOffset.Now;
        bool completed = true;
        int scanned = 0;
        int notable = 0;

        try
        {
            var drives = string.Join(", ", SentinelService.FixedDriveRoots());
            Status = $"Full scan of {drives} — this takes a while. You can keep using the machine, " +
                     "and you can stop it at any time.";

            await foreach (var verdict in _sentinel.ScanEverythingAsync(_scanCancellation.Token))
            {
                scanned++;
                if (verdict.WarrantsAlert)
                    notable++;

                if (scanned % 50 == 0)
                {
                    var elapsed = Clock(DateTimeOffset.Now - started);
                    Status = $"Full scan: {scanned:N0} files, {notable} worth a look, " +
                             $"{elapsed} elapsed. Currently in " +
                             $"{ShortFolder(verdict.Target.Path)}.";
                }
            }

            var total = Clock(DateTimeOffset.Now - started);
            Status = notable == 0
                ? $"Full scan finished: {scanned:N0} files in {total}. Nothing worth flagging."
                : $"Full scan finished: {scanned:N0} files in {total}, {notable} worth a look. " +
                  "Nothing was changed — read the reasons and decide for yourself.";
        }
        catch (OperationCanceledException)
        {
            completed = false;
            Status = $"Full scan stopped after {scanned:N0} files. Nothing was changed.";
        }
        finally
        {
            IsScanning = false;
            _scanCancellation?.Dispose();
            _scanCancellation = null;
            RefreshFindings();

            Record(ScanKind.FullDisk, string.Join(", ", SentinelService.FixedDriveRoots()),
                started, scanned, notable, completed);
        }
    }

    private static string Clock(TimeSpan elapsed) => elapsed.ToString(@"hh\:mm\:ss");

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
            Status = $"Looking at {Path.GetFileName(path)}…";

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

        try
        {
            Status = $"Scanning {folder}…";

            await foreach (var verdict in _sentinel.ScanFolderAsync(folder, recursive: true, _scanCancellation.Token))
            {
                scanned++;
                if (verdict.WarrantsAlert)
                    notable++;

                if (scanned % 25 == 0)
                    Status = $"Scanned {scanned} files, {notable} worth a look…";
            }

            Status = notable == 0
                ? $"Scanned {scanned} files. Nothing worth flagging. Nothing was changed."
                : $"Scanned {scanned} files and found {notable} worth a look. Nothing was changed — " +
                  "read the reasons and decide for yourself.";
        }
        catch (OperationCanceledException)
        {
            completed = false;
            Status = $"Stopped after {scanned} files. Nothing was changed.";
        }
        finally
        {
            IsScanning = false;
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
