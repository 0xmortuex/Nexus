using Nexus.Core.Security;
using Xunit;

namespace Nexus.Core.Tests;

public class ConnectionHistoryTests
{
    private static readonly DateTimeOffset Start = new(2026, 8, 31, 12, 0, 0, TimeSpan.Zero);

    private static ConnectionObservation Seen(
        string process = "chrome.exe", string address = "203.0.113.5", int port = 443) =>
        new(process, address, port);

    [Fact]
    public void A_new_history_is_empty()
    {
        Assert.Empty(new ConnectionHistory().All);
    }

    [Fact]
    public void The_first_sighting_is_recorded_once()
    {
        var history = new ConnectionHistory();
        history.Record([Seen()], Start);

        var record = Assert.Single(history.All);
        Assert.Equal("chrome.exe", record.ProcessName);
        Assert.Equal("203.0.113.5:443", record.Endpoint);
        Assert.Equal(1, record.TimesSeen);
        Assert.Equal(Start, record.FirstSeen);
        Assert.Equal(Start, record.LastSeen);
    }

    /// <summary>
    /// The same conversation seen across several polls is one entry, not several.
    /// Otherwise a connection held open for an hour would fill the entire history by
    /// itself and evict everything worth keeping.
    /// </summary>
    [Fact]
    public void Seeing_the_same_connection_again_updates_it_rather_than_duplicating()
    {
        var history = new ConnectionHistory();

        history.Record([Seen()], Start);
        history.Record([Seen()], Start.AddSeconds(5));
        history.Record([Seen()], Start.AddSeconds(10));

        var record = Assert.Single(history.All);
        Assert.Equal(3, record.TimesSeen);
        Assert.Equal(Start, record.FirstSeen);
        Assert.Equal(Start.AddSeconds(10), record.LastSeen);
    }

    /// <summary>
    /// Identity ignores the PID on purpose: a program that restarts is continuing the
    /// same conversation, and keying on PID would turn one entry into a new one every
    /// time the process was restarted.
    /// </summary>
    [Fact]
    public void The_same_program_and_endpoint_is_one_entry_across_restarts()
    {
        var history = new ConnectionHistory();

        history.Record([Seen()], Start);
        history.Record([Seen()], Start.AddMinutes(5));

        Assert.Single(history.All);
    }

    [Fact]
    public void Different_endpoints_are_different_entries()
    {
        var history = new ConnectionHistory();

        history.Record(
        [
            Seen(address: "203.0.113.5"),
            Seen(address: "203.0.113.6"),
            Seen(port: 80),
            Seen(process: "firefox.exe"),
        ], Start);

        Assert.Equal(4, history.Count);
    }

    [Fact]
    public void The_most_recently_active_come_first()
    {
        var history = new ConnectionHistory();

        history.Record([Seen(address: "198.51.100.1")], Start);
        history.Record([Seen(address: "198.51.100.2")], Start.AddSeconds(30));
        history.Record([Seen(address: "198.51.100.1")], Start.AddSeconds(60));

        Assert.Equal("198.51.100.1:443", history.All[0].Endpoint);
    }

    // ---- Eviction ----

    /// <summary>
    /// The entry this history exists to preserve is the one seen once, briefly. A
    /// browser holding four hundred connections open must not be able to evict it, so
    /// eviction is by last-seen and never by frequency.
    /// </summary>
    [Fact]
    public void A_chatty_process_cannot_evict_a_recent_rare_connection()
    {
        var history = new ConnectionHistory();

        // One quiet, recent connection.
        var quiet = new ConnectionObservation("odd.exe", "203.0.113.99", 4444);
        history.Record([quiet], Start.AddHours(1));

        // A browser floods the history, all of it older.
        var flood = Enumerable.Range(0, ConnectionHistory.MaxRecords + 100)
            .Select(i => new ConnectionObservation("chrome.exe", $"198.51.100.{i % 250}", 40000 + i))
            .ToArray();

        for (int pass = 0; pass < 5; pass++)
            history.Record(flood, Start.AddMinutes(pass));

        Assert.Equal(ConnectionHistory.MaxRecords, history.Count);
        Assert.Contains(history.All, r => r.Connection == quiet);
    }

    [Fact]
    public void The_history_stays_within_its_cap()
    {
        var history = new ConnectionHistory();

        var many = Enumerable.Range(0, ConnectionHistory.MaxRecords * 2)
            .Select(i => new ConnectionObservation("app.exe", $"203.0.113.{i % 250}", 1000 + i));

        history.Record(many, Start);

        Assert.Equal(ConnectionHistory.MaxRecords, history.Count);
    }

    [Fact]
    public void Clearing_empties_it()
    {
        var history = new ConnectionHistory();
        history.Record([Seen()], Start);
        history.Clear();

        Assert.Empty(history.All);
    }

    // ---- Display ----

    [Fact]
    public void A_single_sighting_shows_one_time_rather_than_a_range()
    {
        var history = new ConnectionHistory();
        history.Record([Seen()], Start);

        Assert.DoesNotContain("–", history.All[0].When);
    }

    [Fact]
    public void A_connection_seen_over_a_period_shows_the_range()
    {
        var history = new ConnectionHistory();
        history.Record([Seen()], Start);
        history.Record([Seen()], Start.AddMinutes(3));

        Assert.Contains("–", history.All[0].When);
    }

    /// <summary>
    /// A program commonly holds several simultaneous sockets to the same endpoint.
    /// Counting each as a separate sighting made the number meaningless: six polls of
    /// a browser reported it as seen 156 times, which reads as persistence and is
    /// really parallelism.
    /// </summary>
    [Fact]
    public void Several_sockets_to_one_endpoint_count_as_one_sighting()
    {
        var history = new ConnectionHistory();

        history.Record([Seen(), Seen(), Seen(), Seen()], Start);

        var record = Assert.Single(history.All);
        Assert.Equal(1, record.TimesSeen);
    }

    [Fact]
    public void Times_seen_counts_snapshots()
    {
        var history = new ConnectionHistory();

        for (int poll = 0; poll < 6; poll++)
            history.Record([Seen(), Seen(), Seen()], Start.AddSeconds(poll * 10));

        Assert.Equal(6, Assert.Single(history.All).TimesSeen);
    }

    [Fact]
    public void Recording_nothing_is_harmless()
    {
        var history = new ConnectionHistory();
        history.Record([], Start);

        Assert.Empty(history.All);
    }
}
