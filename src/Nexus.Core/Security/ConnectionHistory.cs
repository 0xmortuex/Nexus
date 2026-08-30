namespace Nexus.Core.Security;

/// <summary>One connection, as the history stores it.</summary>
/// <param name="ProcessName">The program that owns the socket.</param>
/// <param name="RemoteAddress">Where it is talking to.</param>
/// <param name="RemotePort">Which port.</param>
public sealed record ConnectionObservation(string ProcessName, string RemoteAddress, int RemotePort)
{
    /// <summary>Identity for deduplication. Deliberately excludes the PID: the same
    /// program restarting is the same conversation, not a new one.</summary>
    public string Key => $"{ProcessName}|{RemoteAddress}|{RemotePort}";
}

/// <summary>A connection that has been seen at least once, with when and how often.</summary>
public sealed record ConnectionRecord
{
    public required ConnectionObservation Connection { get; init; }
    public required DateTimeOffset FirstSeen { get; set; }
    public required DateTimeOffset LastSeen { get; set; }
    /// <summary>How many separate samples still showed this conversation. Counted
    /// per snapshot, not per socket.</summary>
    public int TimesSeen { get; set; }

    public string ProcessName => Connection.ProcessName;
    public string Endpoint => $"{Connection.RemoteAddress}:{Connection.RemotePort}";

    public string When => FirstSeen == LastSeen
        ? FirstSeen.LocalDateTime.ToString("HH:mm:ss")
        : $"{FirstSeen.LocalDateTime:HH:mm:ss} – {LastSeen.LocalDateTime:HH:mm:ss}";
}

/// <summary>
/// Accumulates the connections seen across repeated snapshots.
///
/// <c>GetExtendedTcpTable</c> answers "what is connected right now", which means a
/// connection that opens and closes between two looks never existed as far as Nexus
/// is concerned. A great deal of what is worth seeing is exactly that short: a beacon
/// checking in, a downloader fetching a payload. Sampling and keeping the results
/// turns a photograph into something closer to a record.
///
/// <para>
/// Held in memory only, and deliberately. Writing every address this machine has
/// talked to into a file would be building a browsing history on the user's disk, and
/// creating that record is a bigger risk to them than the one it helps with. It lives
/// as long as the session and no longer.
/// </para>
/// </summary>
public sealed class ConnectionHistory
{
    /// <summary>
    /// Distinct conversations kept. A busy browser produces a lot; past this the list
    /// stops being reviewable, and the oldest are dropped first.
    /// </summary>
    public const int MaxRecords = 500;

    private readonly Dictionary<string, ConnectionRecord> _records = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    /// <summary>Most recently active first, because that is what is being looked for.</summary>
    public IReadOnlyList<ConnectionRecord> All
    {
        get
        {
            lock (_gate)
                return _records.Values.OrderByDescending(r => r.LastSeen).ToArray();
        }
    }

    public int Count
    {
        get
        {
            lock (_gate)
                return _records.Count;
        }
    }

    /// <summary>
    /// Fold one snapshot into the record.
    ///
    /// Observations are deduplicated within the snapshot first. A program frequently
    /// holds several simultaneous sockets to the same endpoint, and counting each row
    /// separately made <see cref="ConnectionRecord.TimesSeen"/> meaningless: six polls
    /// of a browser reported it as seen 156 times, which reads as persistence and is
    /// really just parallelism. Counted per snapshot, the number answers the question
    /// it looks like it answers — how many times this conversation was still going.
    /// </summary>
    public void Record(IEnumerable<ConnectionObservation> observations, DateTimeOffset now)
    {
        lock (_gate)
        {
            foreach (var observation in observations.DistinctBy(o => o.Key, StringComparer.OrdinalIgnoreCase))
            {
                if (_records.TryGetValue(observation.Key, out var existing))
                {
                    existing.LastSeen = now;
                    existing.TimesSeen++;
                    continue;
                }

                _records[observation.Key] = new ConnectionRecord
                {
                    Connection = observation,
                    FirstSeen = now,
                    LastSeen = now,
                    TimesSeen = 1,
                };
            }

            Trim();
        }
    }

    /// <summary>
    /// Drop the least recently active. Not the least *frequent*: a connection seen
    /// once an hour ago is more worth keeping than one seen four hundred times by a
    /// browser in the last minute, and frequency-based eviction would throw away
    /// exactly the entries this exists to preserve.
    /// </summary>
    private void Trim()
    {
        if (_records.Count <= MaxRecords)
            return;

        var doomed = _records.Values
            .OrderBy(r => r.LastSeen)
            .Take(_records.Count - MaxRecords)
            .Select(r => r.Connection.Key)
            .ToArray();

        foreach (var key in doomed)
            _records.Remove(key);
    }

    public void Clear()
    {
        lock (_gate)
            _records.Clear();
    }
}
