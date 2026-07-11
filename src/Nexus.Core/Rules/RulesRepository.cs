using Nexus.Core.Models;
using Nexus.Core.Persistence;

namespace Nexus.Core.Rules;

/// <summary>
/// Persistent per-exe rules, stored as rules.json. Lookup is case-insensitive on
/// the image name. Every mutation saves immediately.
/// </summary>
public sealed class RulesRepository
{
    private readonly JsonStore<List<ProcessRule>> _store;
    private readonly Dictionary<string, ProcessRule> _byName;
    private readonly object _gate = new();

    public event Action? Changed;

    public RulesRepository(NexusPaths paths)
        : this(new JsonStore<List<ProcessRule>>(
            paths.RulesFile, NexusJsonContext.Default.ListProcessRule, static () => []))
    {
    }

    public RulesRepository(JsonStore<List<ProcessRule>> store)
    {
        _store = store;
        _byName = new Dictionary<string, ProcessRule>(StringComparer.Ordinal);
        foreach (var rule in _store.Load())
            _byName[rule.NormalizedName] = rule;
    }

    public IReadOnlyList<ProcessRule> All()
    {
        lock (_gate)
        {
            return _byName.Values.ToArray();
        }
    }

    public ProcessRule? Find(string exeName)
    {
        lock (_gate)
        {
            return _byName.TryGetValue(ProcessRule.Normalize(exeName), out var rule) ? rule : null;
        }
    }

    public void Upsert(ProcessRule rule)
    {
        lock (_gate)
        {
            _byName[rule.NormalizedName] = rule;
            _store.Save(_byName.Values.ToList());
        }
        Changed?.Invoke();
    }

    public bool Remove(string exeName)
    {
        bool removed;
        lock (_gate)
        {
            removed = _byName.Remove(ProcessRule.Normalize(exeName));
            if (removed)
                _store.Save(_byName.Values.ToList());
        }
        if (removed)
            Changed?.Invoke();
        return removed;
    }

    public void Clear()
    {
        lock (_gate)
        {
            _byName.Clear();
            _store.Save([]);
        }
        Changed?.Invoke();
    }
}
