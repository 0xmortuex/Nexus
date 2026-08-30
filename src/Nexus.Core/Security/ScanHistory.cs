using System.Text;
using Nexus.Core.Persistence;

namespace Nexus.Core.Security;

/// <summary>What kind of scan produced a history entry.</summary>
public enum ScanKind
{
    Folder,
    QuickCheck,
    FullDisk,
    RemovableDrive,
    SingleFile,
    RunningPrograms,
}

/// <summary>
/// One completed scan.
///
/// Properties are settable rather than init-only on purpose: this record is written
/// by the JSON source generator, and with init-only properties a file saved by an
/// older build silently overwrites every default with null.
/// </summary>
public sealed record ScanRun
{
    public DateTimeOffset StartedAt { get; set; }
    public ScanKind Kind { get; set; }
    public string Target { get; set; } = "";
    public int FilesScanned { get; set; }
    public int Findings { get; set; }
    public double DurationSeconds { get; set; }

    /// <summary>False when the user stopped it, or it hit a limit. A history that
    /// records a cancelled scan as if it had finished is worse than no history.</summary>
    public bool Completed { get; set; } = true;

    public string Description => Kind switch
    {
        ScanKind.Folder => $"Folder: {Target}",
        ScanKind.QuickCheck => "Quick check (downloads, temp, startup)",
        ScanKind.FullDisk => $"Full scan: {Target}",
        ScanKind.RemovableDrive => $"USB drive {Target}",
        ScanKind.SingleFile => $"One file: {Target}",
        ScanKind.RunningPrograms => "Programs running at the time",
        _ => Target,
    };

    public string Outcome
    {
        get
        {
            string files = FilesScanned == 1 ? "1 file" : $"{FilesScanned:N0} files";
            string result = Findings == 0 ? "nothing flagged" : $"{Findings} worth a look";
            string ending = Completed ? "" : ", stopped early";

            return $"{files}, {result}{ending}";
        }
    }

    public string When => StartedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm");

    public string Duration => TimeSpan.FromSeconds(DurationSeconds).ToString(@"hh\:mm\:ss");
}

public sealed record ScanHistoryState
{
    private IReadOnlyList<ScanRun> _runs = [];

    public IReadOnlyList<ScanRun> Runs
    {
        get => _runs;
        set => _runs = value ?? [];
    }
}

/// <summary>
/// A record of what has actually been scanned, and when.
///
/// Every antivirus has this, and the reason is not bookkeeping: without it the only
/// answer to "has this machine been checked recently?" is a feeling. It also makes
/// the tool's own quietness legible — "500,000 files, nothing flagged" is a
/// different statement from "nothing has run in three weeks", and they look
/// identical from an empty findings list.
/// </summary>
public sealed class ScanHistory
{
    /// <summary>Past this the list stops being a history and becomes a log file.</summary>
    public const int MaxRuns = 100;

    private readonly JsonStore<ScanHistoryState> _store;
    private readonly List<ScanRun> _runs;
    private readonly object _gate = new();

    public event Action? Changed;

    public ScanHistory(NexusPaths paths)
        : this(new JsonStore<ScanHistoryState>(
            paths.SecurityHistoryFile, NexusJsonContext.Default.ScanHistoryState, static () => new ScanHistoryState()))
    {
    }

    public ScanHistory(JsonStore<ScanHistoryState> store)
    {
        _store = store;
        _runs = [.. _store.Load().Runs];
    }

    /// <summary>Newest first, because that is the one being looked for.</summary>
    public IReadOnlyList<ScanRun> All
    {
        get
        {
            lock (_gate)
                return _runs.OrderByDescending(r => r.StartedAt).ToArray();
        }
    }

    public int Count
    {
        get
        {
            lock (_gate)
                return _runs.Count;
        }
    }

    public ScanRun? Latest => All.FirstOrDefault();

    public void Record(ScanRun run)
    {
        lock (_gate)
        {
            _runs.Add(run);

            // Drop the oldest, not the last added: entries can arrive out of order
            // when a long full scan finishes after a quick check started later.
            if (_runs.Count > MaxRuns)
            {
                _runs.Sort((a, b) => b.StartedAt.CompareTo(a.StartedAt));
                _runs.RemoveRange(MaxRuns, _runs.Count - MaxRuns);
            }

            Save();
        }

        Changed?.Invoke();
    }

    public void Clear()
    {
        lock (_gate)
        {
            _runs.Clear();
            Save();
        }

        Changed?.Invoke();
    }

    private void Save() => _store.Save(new ScanHistoryState { Runs = _runs.ToArray() });

    /// <summary>
    /// A plain-text report of everything scanned. Plain text on purpose: it can be
    /// pasted into an email or a forum post by someone asking for help, which is what
    /// this actually gets used for.
    /// </summary>
    public string BuildReport(DateTimeOffset now)
    {
        var runs = All;
        var report = new StringBuilder();

        report.AppendLine("Nexus — scan history");
        report.AppendLine($"Generated {now.LocalDateTime:yyyy-MM-dd HH:mm}");
        report.AppendLine();

        if (runs.Count == 0)
        {
            report.AppendLine("No scans have been run yet.");
            return report.ToString();
        }

        long totalFiles = runs.Sum(r => (long)r.FilesScanned);
        int totalFindings = runs.Sum(r => r.Findings);

        report.AppendLine($"{runs.Count} scan(s), {totalFiles:N0} file(s) examined, " +
                          $"{totalFindings} finding(s) reported.");
        report.AppendLine("Nexus never acts on its own — nothing below was changed, moved or deleted.");
        report.AppendLine();

        foreach (var run in runs)
        {
            report.AppendLine($"{run.When}  {run.Duration}  {run.Description}");
            report.AppendLine($"                        {run.Outcome}");
        }

        return report.ToString();
    }
}
