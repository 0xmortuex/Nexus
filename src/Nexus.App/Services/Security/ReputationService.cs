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
/// Local-only on purpose. Sending every hash on the machine to a third-party service
/// is a privacy cost the user did not ask for, and an advisory tool that phones home
/// about every file the user runs is worse than the problem it solves. An online
/// lookup exists, but it is opt-in and one file at a time — see
/// <see cref="ILookupOnline"/>.
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

/// <summary>
/// Optional per-file online reputation lookup.
///
/// Kept behind an interface with no implementation wired in by default: an online
/// lookup sends a hash of the user's file to a third party, which is a disclosure,
/// and it must stay something the user turns on for one file at a time rather than
/// something a background scan does to everything.
/// </summary>
public interface ILookupOnline
{
    string ServiceName { get; }

    Task<IReadOnlyList<SecuritySignal>> LookupAsync(string sha256, CancellationToken cancellationToken);
}
