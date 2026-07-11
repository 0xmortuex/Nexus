using System.Collections.ObjectModel;
using System.Windows;
using Nexus.Core.Logging;

namespace Nexus.App.ViewModels;

public sealed class LogViewModel : ViewModelBase
{
    private const int MaxRows = 2000;
    private readonly ActivityLog _log;

    public ObservableCollection<LogEntry> Entries { get; } = [];

    private string _filter = "";
    public string Filter
    {
        get => _filter;
        set
        {
            if (Set(ref _filter, value))
                Rebuild();
        }
    }

    public LogViewModel(ActivityLog log)
    {
        _log = log;
        Rebuild();
        log.EntryAdded += OnEntryAdded;
    }

    private void OnEntryAdded(LogEntry entry)
    {
        var app = Application.Current;
        if (app is null)
            return;
        app.Dispatcher.BeginInvoke(() =>
        {
            if (Matches(entry))
            {
                Entries.Insert(0, entry); // newest on top
                while (Entries.Count > MaxRows)
                    Entries.RemoveAt(Entries.Count - 1);
            }
        });
    }

    private void Rebuild()
    {
        Entries.Clear();
        foreach (var entry in _log.Snapshot().Where(Matches).Reverse())
            Entries.Add(entry);
    }

    private bool Matches(LogEntry entry)
    {
        var filter = Filter.Trim();
        return filter.Length == 0
            || entry.Category.Contains(filter, StringComparison.OrdinalIgnoreCase)
            || entry.Message.Contains(filter, StringComparison.OrdinalIgnoreCase);
    }
}
