using System.IO;
using Nexus.App.Interop.Security;
using Nexus.Core.Logging;
using Nexus.Core.Persistence;
using Nexus.Core.Security;
using Nexus.Core.Security.Behavior;
using Nexus.Core.Security.Persistence;
using Nexus.Core.Security.Ransomware;

namespace Nexus.App.Services.Security;

/// <summary>An alert Sentinel wants a human to see.</summary>
public sealed record SecurityAlert(Verdict Verdict, DateTimeOffset RaisedAt, string Origin);

/// <summary>One part of the security module and whether it is actually working.</summary>
/// <param name="Detail">Why it is off, when it is off. "Disabled in Settings" and
/// "tried to start and failed" are very different situations and must not look the
/// same in the UI.</param>
public sealed record ProtectionComponent(string Name, bool Active, string Detail);

/// <summary>
/// The security module's front door: collects evidence from every engine, fuses it,
/// and reports.
///
/// What it deliberately does not do is act. There is no code path from a verdict to
/// a mutation anywhere in this class — quarantine lives in
/// <see cref="QuarantineService"/> and is reachable only with a
/// <see cref="UserConsent"/> token minted by a button. When Sentinel finds malware it
/// tells you, writes it to the log, and waits.
///
/// That is the whole design brief, and it is also what makes the module honest about
/// its own limits: it observes after the fact, through user-mode interfaces, without
/// a driver. It could not block an execution if it wanted to, so it does not claim to.
/// </summary>
public sealed class SentinelService : IDisposable
{
    private readonly ActivityLog _log;
    private readonly FileIdentityService _identity;
    private readonly AuthenticodeVerifier _signatures;
    private readonly ReputationService _reputation;
    private readonly ScannerHost _scanner;
    private readonly AutorunEnumerator _autoruns;
    private readonly ProcessDetailWatcher _behaviour;
    private readonly TrustStore _trust;
    private readonly VerdictCache _cache;
    private readonly RansomwareGuardService _ransomware;
    private readonly MassChangeDetector _massChange;
    private readonly DefenderHealthService _defender;
    private readonly NetworkMonitorService _network;
    private readonly SystemIntegrityService _integrity;
    private readonly SettingsService _settings;
    private readonly KnownGoodBaselineService _baseline;
    private readonly HashFeedImportService _feeds;
    private readonly DownloadWatcherService _downloads;
    private readonly RemovableDriveWatcherService _removableDrives;
    private readonly ScanHistory _history;

    /// <summary>Findings kept in memory. Past this the list is a haystack, not a report.</summary>
    public const int MaxAlerts = 500;

    private readonly List<SecurityAlert> _alerts = [];
    private readonly object _gate = new();

    /// <summary>Raised when something crosses the alert threshold and is not trusted.</summary>
    public event Action<SecurityAlert>? AlertRaised;

    public event Action? AlertsChanged;

    public SentinelService(
        ActivityLog log,
        FileIdentityService identity,
        AuthenticodeVerifier signatures,
        ReputationService reputation,
        ScannerHost scanner,
        AutorunEnumerator autoruns,
        ProcessDetailWatcher behaviour,
        TrustStore trust,
        VerdictCache cache,
        RansomwareGuardService ransomware,
        MassChangeDetector massChange,
        DefenderHealthService defender,
        NetworkMonitorService network,
        SystemIntegrityService integrity,
        SettingsService settings,
        KnownGoodBaselineService baseline,
        HashFeedImportService feeds,
        ScanHistory history,
        Func<bool> isGameModeActive)
    {
        _log = log;
        _identity = identity;
        _signatures = signatures;
        _reputation = reputation;
        _scanner = scanner;
        _autoruns = autoruns;
        _behaviour = behaviour;
        _trust = trust;
        _cache = cache;
        _ransomware = ransomware;
        _massChange = massChange;
        _defender = defender;
        _network = network;
        _integrity = integrity;
        _settings = settings;
        _baseline = baseline;
        _feeds = feeds;
        _downloads = new DownloadWatcherService(log, ScanDownloadAsync, isGameModeActive);
        _removableDrives = new RemovableDriveWatcherService(log, ScanDriveAsync);
        _history = history;
    }

    /// <summary>The alerts raised this session, newest first.</summary>
    public IReadOnlyList<SecurityAlert> Alerts
    {
        get
        {
            lock (_gate)
            {
                return _alerts.OrderByDescending(a => a.RaisedAt).ToArray();
            }
        }
    }

    /// <summary>
    /// Bring the module up.
    ///
    /// Every step is individually guarded because this runs inside App.OnStartup:
    /// anything that escapes here stops Nexus launching at all. A security module
    /// that cannot start should cost the user its features, never the application —
    /// and the optimizer half has nothing to do with any of this.
    /// </summary>
    /// <summary>True while protection is actually running.</summary>
    public bool IsProtectionOn { get; private set; }

    /// <summary>Raised whenever protection is switched on or off, so the UI and the
    /// tray can follow without polling.</summary>
    public event Action? ProtectionStateChanged;

    /// <summary>
    /// Turn protection off without closing Nexus.
    ///
    /// Every monitor is genuinely stopped — the WMI subscription is cancelled, the
    /// filesystem watchers are torn down, the download watcher stops. "Off" has to
    /// mean off, or the switch is decoration. The optimizer half is untouched: this
    /// is one half of the product, not the product.
    /// </summary>
    public void StopProtection()
    {
        if (!IsProtectionOn)
            return;

        _behaviour.FindingRaised -= OnBehaviourFinding;
        _ransomware.Detected -= OnRansomwareFinding;

        TryStart("stopping behaviour monitoring", _behaviour.Stop);
        TryStart("stopping the ransomware watch", _ransomware.Stop);
        TryStart("stopping download checks", _downloads.Stop);
        TryStart("stopping USB drive checks", _removableDrives.Stop);

        IsProtectionOn = false;
        _log.Warn("Sentinel",
            "Protection is OFF. Nexus is no longer watching for anything until you turn it back on.");

        ProtectionStateChanged?.Invoke();
    }

    /// <summary>Turn protection back on, honouring the per-feature switches.</summary>
    public void StartProtection() => Start();

    public void Start()
    {
        if (IsProtectionOn)
            return;

        var options = _settings.Current.Security;

        TryStart("hash reputation", _reputation.Load);
        TryStart("the file scanner", _scanner.QueryEngines);

        // Each feature is opt-out. Two of them are not passive — the ransomware watch
        // writes files into the user's own folders and behaviour monitoring runs a
        // WMI subscription — so honouring the switch matters more than convenience.
        if (options.BehaviourMonitoring)
        {
            _behaviour.FindingRaised += OnBehaviourFinding;
            TryStart("behaviour monitoring", _behaviour.Start);
        }

        if (options.RansomwareWatch)
        {
            _ransomware.Detected += OnRansomwareFinding;
            TryStart("the ransomware watch", _ransomware.Start);
        }

        if (options.ScanDownloads)
            TryStart("download checks", _downloads.Start);

        if (options.ScanRemovableDrives)
            TryStart("USB drive checks", _removableDrives.Start);

        if (options.CheckDefenderHealth)
            TryStart("the Defender health check", ReportDefenderHealth);

        IsProtectionOn = true;

        _log.Info("Sentinel",
            _scanner.IsAvailable
                ? "Security monitoring is on. Nexus will report what it finds and never act on its own."
                : "Security monitoring is on, without the file scanner. Signature checks, startup " +
                  "auditing and behaviour monitoring are running.");

        ProtectionStateChanged?.Invoke();
    }

    private void TryStart(string what, Action start)
    {
        try
        {
            start();
        }
        catch (Exception ex)
        {
            _log.Warn("Sentinel",
                $"Could not start {what}: {ex.Message}. The rest of Nexus is unaffected, and the " +
                "Security tab shows which parts are running.");
        }
    }

    // ---- File scanning ----

    /// <summary>
    /// Examine one file with every available engine and report a verdict.
    /// Reads the file; changes nothing.
    /// </summary>
    public async Task<Verdict> ScanFileAsync(
        string path, CancellationToken cancellationToken = default, string origin = "file scan")
    {
        // Cheapest possible check first: if this exact path, size and timestamp were
        // scanned recently under the same rules, reuse that conclusion without even
        // reading the file. Without this the cache was write-only — every rescan of a
        // folder redid the hashing, the signature check and the worker round trip.
        //
        // A reused verdict is still reported. Skipping that would mean a user who
        // clears the findings list and rescans sees nothing at all, which reads as
        // "it found nothing" rather than "it already told you". Report() dedupes, so
        // reporting here does not produce a second entry either.
        // The user's own exclusions come first: if they said not to look, do not look,
        // and do not spend the hashing to find that out.
        if (Exclusions.IsExcluded(path))
            return SkippedVerdict(path);

        if (TryReuseCachedVerdict(path, out var cached))
        {
            Report(cached, origin);
            return cached;
        }

        var target = _identity.Identify(path, cancellationToken);
        var signals = new List<SecuritySignal>();
        var engines = new HashSet<SignalSource>();

        // Reputation: cheapest, and decisive in both directions.
        var reputation = _reputation.Evaluate(target);
        if (reputation.Count > 0)
        {
            signals.AddRange(reputation);
            if (_reputation.HasData)
                engines.Add(SignalSource.Reputation);
        }

        // Signature.
        var signature = _signatures.Verify(path);
        if (signature.State != SignatureState.Unknown)
        {
            signals.AddRange(AuthenticodeVerifier.ToSignals(signature));
            engines.Add(SignalSource.CodeSignature);
        }

        // Static analysis, out of process.
        var (staticSignals, staticEngines) = await _scanner.ScanAsync(path, cancellationToken).ConfigureAwait(false);
        signals.AddRange(staticSignals);
        foreach (var engine in staticEngines)
            engines.Add(engine);

        var verdict = VerdictEngine.Evaluate(new VerdictInput
        {
            Target = target,
            Signals = signals,
            EnginesConsulted = engines,
            UserTrusted = _trust.IsTrusted(target),
        }, DateTimeOffset.Now);

        _cache.Store(verdict, path, ReadLastWriteTicks(path));
        Report(verdict, origin);

        return verdict;
    }

    /// <summary>
    /// Rebuild a verdict from the cache, or return false to do the real work.
    ///
    /// A cache hit deliberately does NOT re-raise an alert. The user has already been
    /// told about this file; repeating the warning every time a folder is rescanned is
    /// how an advisory tool trains people to ignore it. It also re-reads the trust
    /// store rather than caching that decision, so trusting a file takes effect at
    /// once instead of after the entry expires.
    /// </summary>
    private bool TryReuseCachedVerdict(string path, out Verdict verdict)
    {
        verdict = null!;

        FileInfo info;
        try
        {
            info = new FileInfo(path);
            if (!info.Exists)
                return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }

        var entry = _cache.TryGetByStamp(
            path, info.Length, info.LastWriteTimeUtc.Ticks, DateTimeOffset.Now);

        if (entry is null)
            return false;

        var target = new ScanTarget
        {
            Path = path,
            Sha256 = entry.IdentityKey.StartsWith("sha256:", StringComparison.Ordinal)
                ? entry.IdentityKey["sha256:".Length..]
                : null,
            SizeBytes = entry.SizeBytes,
        };

        verdict = new Verdict
        {
            Target = target,
            Level = entry.Level,
            Score = entry.Score,
            Signals = [],
            EvaluatedAt = entry.EvaluatedAt,
            UserTrusted = _trust.IsTrusted(target),
        };

        return true;
    }

    private static long ReadLastWriteTicks(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists ? info.LastWriteTimeUtc.Ticks : 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }

    /// <summary>
    /// Scan a folder. Yields each verdict as it is produced so a long scan can fill
    /// the UI progressively instead of freezing it until the end.
    /// </summary>
    public async IAsyncEnumerable<Verdict> ScanFolderAsync(
        string folder,
        bool recursive,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = recursive,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint, // don't follow junctions into loops
        };

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(folder, "*", options);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.Warn("Sentinel", $"Could not read {folder}: {ex.Message}");
            yield break;
        }

        try
        {
            foreach (var file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (ScanTargeting.IsNoiseDirectory(file)
                    || !ScanTargeting.IsWorthScanning(file)
                    || Exclusions.IsExcluded(file))
                {
                    continue;
                }

                yield return await ScanFileAsync(file, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            // Cache writes are buffered; a cancelled scan should still keep the work
            // it already did, or stopping a long scan halfway would throw it away.
            _cache.Flush();
        }
    }

    /// <summary>
    /// Scan every fixed drive on the machine.
    ///
    /// This is the "full scan" every antivirus has, and it is the same walk as
    /// <see cref="ScanFolderAsync"/> repeated per drive — the filtering that keeps a
    /// folder scan sane (noise directories, uninteresting file types, the user's
    /// exclusions) is exactly what keeps a full scan finishing this side of an hour.
    ///
    /// Removable and network drives are left out on purpose. A network share can be
    /// enormous and belongs to someone else, and a full scan that silently pulls a
    /// terabyte across a VPN is not a feature. USB drives are handled separately,
    /// when they are plugged in, which is when it is actually useful.
    /// </summary>
    public async IAsyncEnumerable<Verdict> ScanEverythingAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        foreach (var root in FixedDriveRoots())
        {
            cancellationToken.ThrowIfCancellationRequested();

            _log.Info("Sentinel", $"Full scan: starting on {root}.");

            await foreach (var verdict in ScanFolderAsync(root, recursive: true, cancellationToken)
                               .ConfigureAwait(false))
            {
                yield return verdict;
            }
        }
    }

    /// <summary>
    /// Scan one drive, stopping after <paramref name="maxFiles"/>.
    ///
    /// The cap exists because this runs unattended when a drive is plugged in, and
    /// an unbounded scan the user never asked for is exactly the behaviour that gets
    /// security software uninstalled. Hitting the cap is reported, not hidden.
    /// </summary>
    /// <returns>How many files were worth reporting.</returns>
    public async Task<int> ScanDriveAsync(string root, int maxFiles, CancellationToken cancellationToken = default)
    {
        var started = DateTimeOffset.Now;
        int scanned = 0;
        int notable = 0;
        bool completed = true;

        await foreach (var verdict in ScanFolderAsync(root, recursive: true, cancellationToken)
                           .ConfigureAwait(false))
        {
            scanned++;

            if (verdict.WarrantsAlert)
                notable++;

            if (scanned >= maxFiles)
            {
                _log.Info("Sentinel",
                    $"Stopped after {maxFiles:N0} files on {root}. There is more on the drive than " +
                    "an automatic check should read without being asked — use Scan folder to go " +
                    "through the rest.");

                completed = false;
                break;
            }
        }

        _history.Record(new ScanRun
        {
            StartedAt = started,
            Kind = ScanKind.RemovableDrive,
            Target = root,
            FilesScanned = scanned,
            Findings = notable,
            DurationSeconds = (DateTimeOffset.Now - started).TotalSeconds,
            Completed = completed,
        });

        return notable;
    }

    /// <summary>The drives a full scan covers. Anything not ready is skipped rather
    /// than throwing — an empty card reader should not end a scan.</summary>
    public static IReadOnlyList<string> FixedDriveRoots()
    {
        var roots = new List<string>();

        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (drive.DriveType == DriveType.Fixed && drive.IsReady)
                    roots.Add(drive.RootDirectory.FullName);
            }
            catch (IOException)
            {
                // A drive that disappeared between enumeration and the question.
            }
        }

        return roots;
    }

    /// <summary>
    /// Skip file types no engine here has an opinion about. Scanning a user's photo
    /// library to conclude "unknown" 40,000 times wastes their disk and teaches them
    /// the report is noise.
    /// </summary>
    // ---- Startup / persistence audit ----

    /// <summary>Audit every autorun on the machine. Read-only.</summary>
    public IReadOnlyList<Verdict> AuditStartupItems(CancellationToken cancellationToken = default)
    {
        var verdicts = new List<Verdict>();

        foreach (var entry in _autoruns.EnumerateAll(cancellationToken))
        {
            var signals = AutorunAudit.Evaluate(entry);

            var target = entry.ImagePath is { Length: > 0 } imagePath
                ? _identity.Identify(imagePath, cancellationToken)
                : ScanTarget.ForFile(entry.Name);

            var verdict = VerdictEngine.Evaluate(new VerdictInput
            {
                Target = target,
                Signals = signals,
                EnginesConsulted = new HashSet<SignalSource> { SignalSource.Persistence },
                UserTrusted = _trust.IsTrusted(target),
            }, DateTimeOffset.Now);

            verdicts.Add(verdict);
            Report(verdict, origin: "startup audit");
        }

        _log.Info("Sentinel",
            $"Checked {verdicts.Count} startup items; {verdicts.Count(v => v.WarrantsAlert)} worth a look.");

        return verdicts;
    }

    // ---- What is actually running ----

    /// <summary>
    /// The true state of each component.
    ///
    /// This exists because several of these can fail to start for ordinary reasons —
    /// WMI unavailable, a redirected Documents folder, the worker missing from the
    /// install — and until now that only appeared as one line in the log at startup.
    /// A security tool that looks enabled while silently doing nothing is worse than
    /// one that is honestly switched off, so the state is shown rather than assumed.
    /// </summary>
    public IReadOnlyList<ProtectionComponent> ProtectionStatus()
    {
        var options = _settings.Current.Security;

        return
        [
            new ProtectionComponent(
                "File scanning",
                _scanner.IsAvailable,
                _scanner.IsAvailable
                    ? $"Ready. Engines: {string.Join(", ", _scanner.EngineNames)}."
                    : "The scanner program is missing or stopped responding. Signature checks and the " +
                      "startup audit still work."),

            new ProtectionComponent(
                "Behaviour monitoring",
                _behaviour.IsRunning,
                !options.BehaviourMonitoring
                    ? "Turned off in Settings."
                    : _behaviour.IsRunning ? "Watching process launches." : "Could not start — see the Log tab."),

            new ProtectionComponent(
                "Ransomware watch",
                _ransomware.IsRunning,
                !options.RansomwareWatch
                    ? "Turned off in Settings."
                    : _ransomware.IsRunning
                        ? $"{_ransomware.CanaryCount} tripwire file(s) planted."
                        : "Could not start — see the Log tab."),

            new ProtectionComponent(
                "Download checks",
                _downloads.IsRunning,
                !options.ScanDownloads
                    ? "Turned off in Settings."
                    : _downloads.IsRunning ? "Watching your Downloads folder." : "No Downloads folder found."),

            new ProtectionComponent(
                "USB drive checks",
                _removableDrives.IsRunning,
                !options.ScanRemovableDrives
                    ? "Turned off in Settings."
                    : _removableDrives.IsRunning
                        ? "A drive plugged in from now on gets looked at. It stays usable while that happens."
                        : "Could not start — see the Log tab."),

            new ProtectionComponent(
                "Known-good hashes",
                _reputation.KnownGoodCount > 0,
                _reputation.KnownGoodCount > 0
                    ? $"{_reputation.KnownGoodCount:N0} hashes. Ordinary signed files can be recognised."
                    : _baseline.BaselineExists
                        ? "A baseline exists but has not been loaded yet — restart Nexus."
                        : "None yet, so nothing can come back \"clean\", only \"unknown\". " +
                          "Use \"Build baseline from this PC\" above."),

            new ProtectionComponent(
                "Known-bad hashes",
                _reputation.KnownBadCount > 0,
                _reputation.KnownBadCount > 0
                    ? $"{_reputation.KnownBadCount:N0} hashes. An exact match is identified outright."
                    : _feeds.FeedImported
                        ? "A list was imported but has not been loaded yet — restart Nexus."
                        : "None yet. Import one below; malware can still be caught by its behaviour " +
                          "and structure, just not recognised by name."),
        ];
    }

    // ---- Downloads ----

    /// <summary>
    /// Scan a file that has just arrived. Only speaks up when there is something to
    /// say: a download that turns out to be unremarkable should be silent, or the
    /// feature becomes a notification the user learns to dismiss.
    /// </summary>
    private async Task ScanDownloadAsync(string path, CancellationToken cancellationToken)
    {
        // Reports through the normal channel, tagged as a download. It used to log a
        // second line of its own, which meant every flagged download appeared twice
        // in the log — the sort of duplication that makes a log feel like noise.
        await ScanFileAsync(path, cancellationToken, origin: "new download").ConfigureAwait(false);
    }

    // ---- Ransomware ----

    private void OnRansomwareFinding(RansomwareFinding finding)
    {
        var target = finding.ExamplePaths.Count > 0
            ? ScanTarget.ForFile(finding.ExamplePaths[0])
            : ScanTarget.ForFile("your documents");

        var verdict = VerdictEngine.Evaluate(new VerdictInput
        {
            Target = target,
            Signals = finding.Signals,
            EnginesConsulted = new HashSet<SignalSource> { SignalSource.Behavior },
        }, finding.DetectedAt);

        Report(verdict, origin: "ransomware watch");
    }

    // ---- Microsoft Defender ----

    /// <summary>The current state of the protection that actually blocks things.</summary>
    public DefenderStatus DefenderStatus { get; private set; } = new() { Available = false };

    public string DefenderSummary => DefenderHealthService.Describe(DefenderStatus);

    /// <summary>Re-read Defender's state and report anything wrong with it.</summary>
    public void ReportDefenderHealth()
    {
        DefenderStatus = _defender.Query();

        var signals = DefenderHealthService.Evaluate(DefenderStatus);
        if (signals.Count == 0)
            return;

        var verdict = VerdictEngine.Evaluate(new VerdictInput
        {
            Target = ScanTarget.ForFile("Microsoft Defender"),
            Signals = signals,
            EnginesConsulted = new HashSet<SignalSource> { SignalSource.Persistence },
        }, DateTimeOffset.Now);

        Report(verdict, origin: "Defender health");
    }

    /// <summary>The user's exclusions, read fresh so edits take effect immediately
    /// rather than at the next restart.</summary>
    public ExclusionList Exclusions => new(_settings.Current.Security.Exclusions);

    /// <summary>
    /// Add a path or extension Nexus will skip.
    ///
    /// Nothing is rejected for being too broad. Excluding a whole drive is a bad
    /// idea, but it is the user's machine and the alternative — a tool that argues
    /// with the person operating it — is how people end up turning the whole thing
    /// off. What Nexus does instead is say so, every time, through
    /// <see cref="ExclusionList.Audit"/>, and refuse to call an excluded file clean.
    /// </summary>
    /// <returns>A sentence for the UI to show. Never throws.</returns>
    public string AddExclusion(string? pattern, string? note = null)
    {
        pattern = pattern?.Trim() ?? "";

        if (pattern.Length == 0)
            return "Type a folder path, or an extension like .log, first.";

        var existing = _settings.Current.Security.Exclusions;

        if (existing.Any(e => string.Equals(e.Pattern, pattern, StringComparison.OrdinalIgnoreCase)))
            return $"{pattern} is already on the list.";

        _settings.Update(settings =>
        {
            settings.Security.Exclusions = [.. existing, new Exclusion(pattern, note)];
            return settings;
        });

        _log.Info("Sentinel", $"You asked Nexus to skip {pattern}.");

        // Report the exclusion straight back if it is wide enough to matter.
        var concerns = Exclusions.Audit();
        string warning = concerns.Count > 0
            ? " That is a broad exclusion — see the warning below it."
            : "";

        return $"Nexus will now skip {pattern}.{warning}";
    }

    /// <summary>Stop skipping something. Removing an exclusion never needs a warning.</summary>
    public string RemoveExclusion(string? pattern)
    {
        if (pattern is not { Length: > 0 })
            return "Pick an exclusion to remove.";

        var existing = _settings.Current.Security.Exclusions;
        var remaining = existing
            .Where(e => !string.Equals(e.Pattern, pattern, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (remaining.Length == existing.Count)
            return $"{pattern} was not on the list.";

        _settings.Update(settings =>
        {
            settings.Security.Exclusions = remaining;
            return settings;
        });

        _log.Info("Sentinel", $"Nexus will scan {pattern} again.");
        return $"Nexus will scan {pattern} again.";
    }

    /// <summary>
    /// A verdict for a file the user asked Nexus not to look at.
    ///
    /// Deliberately "unknown" rather than "clean": Nexus did not examine it and must
    /// not imply otherwise. An exclusion silences the scan, not the truth.
    /// </summary>
    private static Verdict SkippedVerdict(string path) => new()
    {
        Target = ScanTarget.ForFile(path),
        Level = ThreatLevel.Unknown,
        Score = 0,
        Signals =
        [
            new SecuritySignal(SignalSource.Reputation, SignalWeight.Informational, "excluded-by-user",
                "You have asked Nexus to skip this file, so it was not examined."),
        ],
        EvaluatedAt = DateTimeOffset.Now,
    };

    // ---- System settings ----

    /// <summary>
    /// Check the machine settings malware changes to cut you off or redirect you:
    /// the hosts file, the proxy, and the DNS servers.
    ///
    /// None of this involves a program running, so nothing else in Sentinel would
    /// notice it. Blackholing a security vendor in the hosts file is the sharpest
    /// signal the whole module has — there is no innocent version of a machine
    /// blocking its own antivirus.
    /// </summary>
    public int AuditSystemSettings()
    {
        var facts = _integrity.Collect();
        var signals = SystemIntegrityAudit.Evaluate(facts);

        if (signals.Count > 0)
        {
            var verdict = VerdictEngine.Evaluate(new VerdictInput
            {
                Target = ScanTarget.ForFile("Windows network settings"),
                Signals = signals,
                EnginesConsulted = new HashSet<SignalSource> { SignalSource.Persistence },
            }, DateTimeOffset.Now);

            Report(verdict, origin: "system settings");
        }

        _log.Info("Sentinel",
            $"Checked the hosts file, proxy and DNS settings; {signals.Count} thing(s) worth a look.");

        return signals.Count;
    }

    // ---- Network ----

    /// <summary>Who is talking to the internet right now.</summary>
    public IReadOnlyList<ConnectionInfo> GetConnections() => _network.GetConnections();

    /// <summary>
    /// Tell the ransomware watch that a burst was expected.
    ///
    /// Restoring a backup, bulk-converting photos or unpacking a large archive all
    /// look like the early stage of an encryption run, and the user is the only one
    /// who knows which it is. Without a way to say so, the honest response to a false
    /// alarm is to turn the whole feature off.
    /// </summary>
    public void DismissRansomwareAlarm()
    {
        _massChange.Reset();
        _log.Info("Sentinel", "Ransomware watch reset — you confirmed that file activity was expected.");
    }

    /// <summary>Check current connections and report anything odd.</summary>
    public int AuditConnections()
    {
        var connections = _network.GetConnections();
        var signals = _network.Evaluate(connections, ResolveImagePath);

        if (signals.Count > 0)
        {
            var verdict = VerdictEngine.Evaluate(new VerdictInput
            {
                Target = ScanTarget.ForFile("network connections"),
                Signals = signals,
                EnginesConsulted = new HashSet<SignalSource> { SignalSource.Behavior },
            }, DateTimeOffset.Now);

            Report(verdict, origin: "network check");
        }

        return connections.Count;
    }

    private static string? ResolveImagePath(int pid)
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(pid);
            return process.MainModule?.FileName;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException
                                       or System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }

    // ---- Behaviour ----

    private void OnBehaviourFinding(BehaviorFinding finding)
    {
        var verdict = VerdictEngine.Evaluate(new VerdictInput
        {
            Target = finding.Target,
            Signals = finding.Signals,
            EnginesConsulted = new HashSet<SignalSource> { SignalSource.Behavior },
            UserTrusted = _trust.IsTrusted(finding.Target),
        }, finding.Trigger.At);

        Report(verdict, origin: "behaviour");
    }

    // ---- Reporting ----

    private void Report(Verdict verdict, string origin)
    {
        if (verdict.Level <= ThreatLevel.Clean)
            return;

        if (!verdict.WarrantsAlert)
        {
            // Unknown files are the overwhelming majority and are not news. They stay
            // out of the log so the log keeps meaning something.
            return;
        }

        // One alert object, one timestamp. Building it twice gave the copy in the
        // list and the copy handed to subscribers different times, so the tray and
        // the Security tab could disagree about when something was found.
        var alert = new SecurityAlert(verdict, DateTimeOffset.Now, origin);

        lock (_gate)
        {
            // Deduplicate on identity. The same file gets re-examined by the
            // scheduled check, by a folder scan, and on every cache hit, and listing
            // it once per look would bury the findings under repeats of themselves.
            bool alreadyListed = _alerts.Any(existing =>
                existing.Verdict.Target.IdentityKey == verdict.Target.IdentityKey
                && existing.Verdict.Level == verdict.Level);

            if (alreadyListed)
                return;

            _alerts.Add(alert);

            // Bound the list. A machine with thousands of findings has a problem no
            // list length will fix, and an unbounded one is a slow memory leak.
            if (_alerts.Count > MaxAlerts)
                _alerts.RemoveRange(0, _alerts.Count - MaxAlerts);
        }

        var reasons = string.Join(" ", verdict.Reasons.Take(2).Select(r => r.Explanation));
        var message = $"{verdict.Headline} {reasons} (score {verdict.Score}/100, nothing was changed)";

        if (verdict.Level >= ThreatLevel.LikelyMalicious)
            _log.Warn("Sentinel", message);
        else
            _log.Info("Sentinel", message);

        AlertRaised?.Invoke(alert);
        AlertsChanged?.Invoke();
    }

    public void ClearAlerts()
    {
        lock (_gate)
        {
            _alerts.Clear();
        }
        AlertsChanged?.Invoke();
    }

    public void Dispose()
    {
        _behaviour.FindingRaised -= OnBehaviourFinding;
        _behaviour.Dispose();
        _ransomware.Detected -= OnRansomwareFinding;
        _ransomware.Dispose();
        _downloads.Dispose();
        _scanner.Dispose();
        _cache.Flush();
    }
}
