using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using Nexus.App.Services.Security;
using Nexus.Core.Security;

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

    private CancellationTokenSource? _scanCancellation;
    private string _status = "Nexus watches, explains, and leaves the decisions to you. Nothing here is changed without you clicking it.";
    private bool _isScanning;

    public ObservableCollection<FindingRow> Findings { get; } = [];
    public ObservableCollection<QuarantineRow> Quarantined { get; } = [];

    public SecurityViewModel(
        SentinelService sentinel,
        QuarantineService quarantine,
        QuarantineJournal journal,
        TrustStore trust)
    {
        _sentinel = sentinel;
        _quarantine = quarantine;
        _journal = journal;
        _trust = trust;

        _sentinel.AlertsChanged += RefreshFindings;
        _journal.Changed += RefreshQuarantine;

        ScanFolderCommand = new RelayCommand(async p => await ScanFolderAsync(p as string), _ => !IsScanning);
        AuditStartupCommand = new RelayCommand(AuditStartup, () => !IsScanning);
        CancelScanCommand = new RelayCommand(() => _scanCancellation?.Cancel(), () => IsScanning);
        QuarantineCommand = new RelayCommand(p => Quarantine(p as FindingRow));
        TrustCommand = new RelayCommand(p => Trust(p as FindingRow));
        RestoreCommand = new RelayCommand(p => Restore(p as QuarantineRow));
        ClearFindingsCommand = new RelayCommand(() => _sentinel.ClearAlerts());

        RefreshQuarantine();
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
            Status = $"Stopped after {scanned} files. Nothing was changed.";
        }
        finally
        {
            IsScanning = false;
            _scanCancellation?.Dispose();
            _scanCancellation = null;
            RefreshFindings();
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
