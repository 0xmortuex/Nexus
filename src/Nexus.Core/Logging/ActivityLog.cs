namespace Nexus.Core.Logging;

public enum LogLevel
{
    Info,
    Warning,
    Error,
}

public sealed record LogEntry(DateTimeOffset Timestamp, LogLevel Level, string Category, string Message);

/// <summary>
/// Plain-language activity log: appends to a daily file and keeps a bounded
/// in-memory ring for the UI. Logging must never take the app down, so all IO
/// failures are swallowed.
/// </summary>
public sealed class ActivityLog
{
    private readonly string? _directory;
    private readonly int _capacity;
    private readonly Queue<LogEntry> _ring;
    private readonly object _gate = new();

    public event Action<LogEntry>? EntryAdded;

    /// <param name="directory">Directory for daily log files; null disables file output (tests).</param>
    public ActivityLog(string? directory, int capacity = 2000)
    {
        _directory = directory;
        _capacity = capacity;
        _ring = new Queue<LogEntry>(capacity);
    }

    public void Info(string category, string message) => Add(LogLevel.Info, category, message);
    public void Warn(string category, string message) => Add(LogLevel.Warning, category, message);
    public void Error(string category, string message) => Add(LogLevel.Error, category, message);

    public IReadOnlyList<LogEntry> Snapshot()
    {
        lock (_gate)
        {
            return _ring.ToArray();
        }
    }

    private void Add(LogLevel level, string category, string message)
    {
        var entry = new LogEntry(DateTimeOffset.Now, level, category, message);

        lock (_gate)
        {
            if (_ring.Count >= _capacity)
                _ring.Dequeue();
            _ring.Enqueue(entry);

            if (_directory is not null)
            {
                try
                {
                    Directory.CreateDirectory(_directory);
                    var file = Path.Combine(_directory, $"activity-{entry.Timestamp:yyyyMMdd}.log");
                    File.AppendAllText(file,
                        $"{entry.Timestamp:yyyy-MM-dd HH:mm:ss} [{level}] [{category}] {message}{Environment.NewLine}");
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                }
            }
        }

        EntryAdded?.Invoke(entry);
    }
}
