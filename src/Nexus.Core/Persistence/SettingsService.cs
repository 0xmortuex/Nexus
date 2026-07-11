using Nexus.Core.Models;

namespace Nexus.Core.Persistence;

/// <summary>Loads settings.json once, saves on every update, notifies listeners.</summary>
public sealed class SettingsService
{
    private readonly JsonStore<AppSettings> _store;
    private readonly object _gate = new();

    public event Action<AppSettings>? Changed;

    public AppSettings Current { get; private set; }

    public SettingsService(NexusPaths paths)
        : this(new JsonStore<AppSettings>(paths.SettingsFile, NexusJsonContext.Default.AppSettings, static () => new AppSettings()))
    {
    }

    public SettingsService(JsonStore<AppSettings> store)
    {
        _store = store;
        Current = _store.Load();
    }

    public void Update(Func<AppSettings, AppSettings> mutate)
    {
        AppSettings updated;
        lock (_gate)
        {
            updated = mutate(Current);
            Current = updated;
            _store.Save(updated);
        }
        Changed?.Invoke(updated);
    }
}
