using System.IO;
using Nexus.App.Interop.Security;
using Nexus.Core.Logging;
using Nexus.Core.Security;
using Nexus.Core.Security.Behavior;
using Nexus.Core.Security.Persistence;

namespace Nexus.App.Services.Security;

/// <summary>An alert Sentinel wants a human to see.</summary>
public sealed record SecurityAlert(Verdict Verdict, DateTimeOffset RaisedAt, string Origin);

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
        VerdictCache cache)
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

    public void Start()
    {
        _reputation.Load();

        _behaviour.FindingRaised += OnBehaviourFinding;
        _behaviour.Start();

        _log.Info("Sentinel",
            _scanner.IsAvailable
                ? "Security monitoring is on. Nexus will report what it finds and never act on its own."
                : "Security monitoring is on, without the file scanner. Signature checks, startup " +
                  "auditing and behaviour monitoring are running.");
    }

    // ---- File scanning ----

    /// <summary>
    /// Examine one file with every available engine and report a verdict.
    /// Reads the file; changes nothing.
    /// </summary>
    public async Task<Verdict> ScanFileAsync(string path, CancellationToken cancellationToken = default)
    {
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

        _cache.Store(verdict);
        Report(verdict, origin: "file scan");

        return verdict;
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

        foreach (var file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!IsWorthScanning(file))
                continue;

            yield return await ScanFileAsync(file, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Skip file types no engine here has an opinion about. Scanning a user's photo
    /// library to conclude "unknown" 40,000 times wastes their disk and teaches them
    /// the report is noise.
    /// </summary>
    private static bool IsWorthScanning(string path)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();

        return extension is ".exe" or ".dll" or ".sys" or ".scr" or ".ocx" or ".cpl" or ".drv"
            or ".com" or ".pif" or ".bat" or ".cmd" or ".ps1" or ".psm1" or ".vbs" or ".vbe"
            or ".js" or ".jse" or ".wsf" or ".wsh" or ".hta" or ".msi" or ".msp" or ".jar"
            or ".lnk" or ".reg" or "";
    }

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

        lock (_gate)
        {
            _alerts.Add(new SecurityAlert(verdict, DateTimeOffset.Now, origin));
        }

        var reasons = string.Join(" ", verdict.Reasons.Take(2).Select(r => r.Explanation));
        var message = $"{verdict.Headline} {reasons} (score {verdict.Score}/100, nothing was changed)";

        if (verdict.Level >= ThreatLevel.LikelyMalicious)
            _log.Warn("Sentinel", message);
        else
            _log.Info("Sentinel", message);

        AlertRaised?.Invoke(new SecurityAlert(verdict, DateTimeOffset.Now, origin));
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
        _scanner.Dispose();
    }
}
