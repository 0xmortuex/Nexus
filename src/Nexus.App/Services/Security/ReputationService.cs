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
    private readonly HashSet<string> _knownGood = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _knownBad = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public ReputationService(ActivityLog log)
    {
        _log = log;
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
        LoadInto(NexusPaths.KnownGoodHashFile, _knownGood, "known-good");
        LoadInto(Path.Combine(NexusPaths.AssetsDirectory, "known-bad.txt"), _knownBad, "known-bad");

        if (!HasData)
        {
            _log.Info("Sentinel",
                "No hash reputation lists found. Sentinel will still check signatures and behaviour, " +
                "but it cannot recognise known files by hash until a list is supplied.");
        }
        else
        {
            _log.Info("Sentinel",
                $"Hash reputation ready: {KnownGoodCount:N0} known-good, {KnownBadCount:N0} known-bad.");
        }
    }

    private void LoadInto(string path, HashSet<string> destination, string label)
    {
        if (!File.Exists(path))
            return;

        try
        {
            int loaded = 0;
            lock (_gate)
            {
                destination.Clear();
                foreach (var raw in File.ReadLines(path))
                {
                    var line = raw.Trim();
                    if (line.Length == 0 || line[0] == '#')
                        continue;

                    // Tolerate "hash,name" and "hash name" exports.
                    int separator = line.IndexOfAny([',', ' ', '\t']);
                    var hash = separator > 0 ? line[..separator] : line;

                    if (hash.Length == 64)
                    {
                        destination.Add(hash);
                        loaded++;
                    }
                }
            }

            _log.Info("Sentinel", $"Loaded {loaded:N0} {label} hashes from {Path.GetFileName(path)}.");
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
