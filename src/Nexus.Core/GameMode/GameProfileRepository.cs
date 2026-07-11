using Nexus.Core.Models;
using Nexus.Core.Persistence;

namespace Nexus.Core.GameMode;

/// <summary>Per-game profiles in games.json. Also serves as the user game list:
/// any profile here makes its exe count as a game for the detector.</summary>
public sealed class GameProfileRepository
{
    private readonly JsonStore<List<GameProfile>> _store;
    private readonly Dictionary<string, GameProfile> _byName;
    private readonly object _gate = new();

    public event Action? Changed;

    public GameProfileRepository(NexusPaths paths)
        : this(new JsonStore<List<GameProfile>>(
            paths.GamesFile, NexusJsonContext.Default.ListGameProfile, static () => []))
    {
    }

    public GameProfileRepository(JsonStore<List<GameProfile>> store)
    {
        _store = store;
        _byName = new Dictionary<string, GameProfile>(StringComparer.Ordinal);
        foreach (var profile in _store.Load())
            _byName[profile.NormalizedName] = profile;
    }

    public IReadOnlyList<GameProfile> All()
    {
        lock (_gate)
        {
            return _byName.Values.ToArray();
        }
    }

    public IReadOnlyList<string> GameExeNames()
    {
        lock (_gate)
        {
            return _byName.Keys.ToArray();
        }
    }

    public GameProfile? Find(string exeName)
    {
        lock (_gate)
        {
            return _byName.TryGetValue(ProcessRule.Normalize(exeName), out var profile) ? profile : null;
        }
    }

    /// <summary>Existing profile, or defaults for a newly auto-detected game.</summary>
    public GameProfile FindOrDefault(string exeName) =>
        Find(exeName) ?? new GameProfile { ExeName = ProcessRule.Normalize(exeName) };

    public void Upsert(GameProfile profile)
    {
        lock (_gate)
        {
            _byName[profile.NormalizedName] = profile;
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
}
