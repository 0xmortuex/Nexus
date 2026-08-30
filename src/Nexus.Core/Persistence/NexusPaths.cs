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

    // ---- Sentinel (security module) ----
    public string SecurityDirectory => Path.Combine(Root, "security");
    public string SecurityTrustFile => Path.Combine(SecurityDirectory, "trusted.json");
    public string QuarantineJournalFile => Path.Combine(SecurityDirectory, "quarantine.json");

    /// <summary>Where quarantined file copies are held. Kept out of the logs and
    /// backups trees so a cleanup routine can never sweep it by accident.</summary>
    public string QuarantineDirectory => Path.Combine(Root, "quarantine");

    /// <summary>Cached verdicts, keyed by content hash.</summary>
    public string VerdictCacheFile => Path.Combine(SecurityDirectory, "verdict-cache.json");

    // ---- Performance measurement ----
    public string BaselinesFile => Path.Combine(Root, "baselines.json");

    /// <summary>YARA rule files and the ONNX model ship beside the executable, not in
    /// %APPDATA% — they are program assets, and keeping them out of a user-writable
    /// directory means a non-admin cannot swap the detection logic.</summary>
    public static string AssetsDirectory => Path.Combine(AppContext.BaseDirectory, "assets");
    public static string YaraRulesDirectory => Path.Combine(AssetsDirectory, "yara");
    public static string ModelFile => Path.Combine(AssetsDirectory, "pe-classifier.onnx");
    public static string KnownGoodHashFile => Path.Combine(AssetsDirectory, "known-good.txt");
}
