using System.Collections.Concurrent;

namespace Nexus.App.Services;

/// <summary>
/// Remembers PIDs Nexus itself terminated (disallowed list, instance limits,
/// watchdog, user action) so restart-if-exited rules never resurrect them.
/// Entries expire after a few minutes; PIDs get recycled.
/// </summary>
public sealed class KillTracker
{
    private readonly ConcurrentDictionary<int, DateTimeOffset> _killed = new();

    public void MarkKilled(int pid) => _killed[pid] = DateTimeOffset.Now;

    public bool WasKilledByNexus(int pid)
    {
        Prune();
        return _killed.TryGetValue(pid, out _);
    }

    private void Prune()
    {
        var cutoff = DateTimeOffset.Now.AddMinutes(-5);
        foreach (var (pid, at) in _killed)
        {
            if (at < cutoff)
                _killed.TryRemove(pid, out _);
        }
    }
}
