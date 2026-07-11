namespace Nexus.Core.Persistence;

/// <summary>All on-disk locations, rooted at an injectable directory
/// (%APPDATA%\Nexus in production, a temp dir in tests).</summary>
public sealed class NexusPaths
{
    public NexusPaths(string root)
    {
        Root = root;
    }

    public static NexusPaths Default() => new(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Nexus"));

    public string Root { get; }
    public string SettingsFile => Path.Combine(Root, "settings.json");
    public string RulesFile => Path.Combine(Root, "rules.json");
    public string GamesFile => Path.Combine(Root, "games.json");
    public string TweaksStateFile => Path.Combine(Root, "tweaks-state.json");
    public string IntendedStateFile => Path.Combine(Root, "intended-state.json");
    public string LogsDirectory => Path.Combine(Root, "logs");
    public string RegistryBackupDirectory => Path.Combine(Root, "backups", "registry");
}
