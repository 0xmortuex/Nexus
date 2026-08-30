using System.IO;
using Nexus.Core.Logging;
using Nexus.Core.Persistence;
using Nexus.Core.Security;

namespace Nexus.App.Services.Security;

/// <summary>
/// Hash reputation from local lists: a known-good set (NIST NSRL, or a hash set the
/// user maintains) and a known-bad set (an abuse.ch MalwareBazaar export, refreshed
/// out of band).
///
/// Local-only on purpose, and there is deliberately no per-file online lookup here.
/// Sending a hash of every file the user runs to a third-party service is a privacy
/// cost they did not ask for, and an advisory tool that phones home about your
/// machine is worse than the problem it solves. The one network request Sentinel
/// makes downloads a public hash list; it never uploads anything about your files.
/// See <see cref="HashFeedImportService"/>.
/// </summary>
public sealed class ReputationService
{
    private readonly ActivityLog _log;
    private readonly NexusPaths _paths;
    private readonly HashSet<string> _knownGood = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _knownBad = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public ReputationService(ActivityLog log, NexusPaths paths)
    {
        _log = log;
        _paths = paths;
    }

    public int KnownGoodCount
    {
        get
        {
            lock (_gate)
            {
                return _knownGood.Count;
            }
        }
    }

    public int KnownBadCount
    {
        get
        {
            lock (_gate)
            {
                return _knownBad.Count;
            }
        }
    }

    /// <summary>True when at least one list loaded; the UI shows this so a user is
    /// never misled into thinking reputation ran when no data was present.</summary>
    public bool HasData => KnownGoodCount > 0 || KnownBadCount > 0;

    /// <summary>
    /// Load hash lists from the assets folder. Each file is one lowercase hex SHA-256
    /// per line; blank lines and lines starting with '#' are ignored, so a list can
    /// carry provenance comments.
    /// </summary>
    public void Load()
    {
        // Two sources for known-good: a curated list shipped with the app, and the
        // baseline built from this machine's own validly-signed binaries. The local
        // one matters most — without any known-good data at all, reputation never
        // counts as an engine consulted and every ordinary file reads "unknown".
        LoadInto(NexusPaths.KnownGoodHashFile, _knownGood, "known-good", replace: true);
        LoadInto(_paths.GeneratedKnownGoodFile, _knownGood, "known-good (this machine)", replace: false);
        LoadInto(Path.Combine(NexusPaths.AssetsDirectory, "known-bad.txt"), _knownBad, "known-bad", replace: true);
        LoadInto(_paths.ImportedKnownBadFile, _knownBad, "known-bad (imported feed)", replace: false);

        if (!HasData)
        {
            _log.Info("Sentinel",
                "No hash reputation data yet, so files can only come back \"unknown\" rather than " +
                "\"clean\". Build a known-good baseline from the Security tab to fix that.");
        }
        else
        {
            _log.Info("Sentinel",
                $"Hash reputation ready: {KnownGoodCount:N0} known-good, {KnownBadCount:N0} known-bad.");
        }
    }

    private void LoadInto(string path, HashSet<string> destination, string label, bool replace)
    {
        if (!File.Exists(path))
            return;

        try
        {
            var loaded = HashListFile.Parse(File.ReadLines(path));

            lock (_gate)
            {
                if (replace)
                    destination.Clear();

                foreach (var hash in loaded)
                    destination.Add(hash);
            }

            _log.Info("Sentinel", $"Loaded {loaded.Count:N0} {label} hashes from {Path.GetFileName(path)}.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.Warn("Sentinel", $"Could not read the {label} hash list: {ex.Message}");
        }
    }

    public IReadOnlyList<SecuritySignal> Evaluate(ScanTarget target)
    {
        if (target.Sha256 is not { Length: 64 } hash)
            return [];

        lock (_gate)
        {
            if (_knownBad.Contains(hash))
            {
                return
                [
                    new SecuritySignal(SignalSource.Reputation, SignalWeight.Decisive, "rep-known-bad",
                        "This file's contents exactly match a sample in the malware hash list."),
                ];
            }

            if (_knownGood.Contains(hash))
            {
                return
                [
                    new SecuritySignal(SignalSource.Reputation, SignalWeight.Decisive, "rep-known-good",
                        "This file's contents exactly match a known-good reference hash.",
                        Exonerating: true),
                ];
            }
        }

        return
        [
            new SecuritySignal(SignalSource.Reputation, SignalWeight.Informational, "rep-unknown",
                "This file is in neither the known-good nor the known-bad list."),
        ];
    }
}
