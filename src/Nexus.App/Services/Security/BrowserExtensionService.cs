using System.IO;
using System.Text.Json;
using Nexus.Core.Logging;
using Nexus.Core.Security.Persistence;

namespace Nexus.App.Services.Security;

/// <summary>
/// Finds the extensions installed in the Chromium-family browsers on this machine and
/// reads what each one is allowed to do.
///
/// Read-only. Nexus never disables or removes an extension: the browser owns that
/// list, editing it behind the browser's back corrupts its own bookkeeping, and the
/// user can remove one in two clicks from a page they already know.
///
/// Firefox is not read. Its extensions live in signed .xpi archives with the manifest
/// inside, and its permission model does not map cleanly onto Chromium's. Reading it
/// badly and reporting confident nonsense would be worse than saying it is not
/// covered, which the UI does.
/// </summary>
public sealed class BrowserExtensionService
{
    /// <summary>A manifest larger than this is not a manifest.</summary>
    private const long MaxManifestBytes = 512 * 1024;

    /// <summary>Chromium-family browsers, by the folder they keep under LocalAppData.</summary>
    private static readonly (string Name, string RelativePath)[] Browsers =
    [
        ("Chrome", @"Google\Chrome\User Data"),
        ("Edge", @"Microsoft\Edge\User Data"),
        ("Brave", @"BraveSoftware\Brave-Browser\User Data"),
        ("Vivaldi", @"Vivaldi\User Data"),
        ("Opera", @"Programs\Opera\User Data"),
    ];

    private readonly ActivityLog _log;

    public BrowserExtensionService(ActivityLog log)
    {
        _log = log;
    }

    public IReadOnlyList<BrowserExtension> Collect()
    {
        var found = new List<BrowserExtension>();
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        foreach (var (name, relativePath) in Browsers)
        {
            var root = Path.Combine(localAppData, relativePath);
            if (!Directory.Exists(root))
                continue;

            foreach (var profile in ProfileDirectories(root))
                found.AddRange(ReadProfile(name, profile));
        }

        return found;
    }

    /// <summary>
    /// Chromium keeps each profile in its own directory: "Default", then "Profile 1",
    /// "Profile 2" and so on. Reading only Default misses every extension belonging to
    /// a second signed-in account, which is where a family machine keeps them.
    /// </summary>
    private static IEnumerable<string> ProfileDirectories(string root)
    {
        IEnumerable<string> directories;

        try
        {
            directories = Directory.EnumerateDirectories(root);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        foreach (var directory in directories)
        {
            var name = Path.GetFileName(directory);

            if (name.Equals("Default", StringComparison.OrdinalIgnoreCase)
                || name.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase))
            {
                yield return directory;
            }
        }
    }

    private IEnumerable<BrowserExtension> ReadProfile(string browser, string profileDirectory)
    {
        var extensionsRoot = Path.Combine(profileDirectory, "Extensions");
        if (!Directory.Exists(extensionsRoot))
            yield break;

        var profileName = Path.GetFileName(profileDirectory);

        IEnumerable<string> extensionDirectories;
        try
        {
            extensionDirectories = Directory.EnumerateDirectories(extensionsRoot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            yield break;
        }

        foreach (var extensionDirectory in extensionDirectories)
        {
            // Each extension holds one directory per installed version. The newest is
            // the one actually loaded; reporting an old version's permissions would
            // describe something the browser is not running.
            var versionDirectory = NewestVersionDirectory(extensionDirectory);
            if (versionDirectory is null)
                continue;

            var extension = ReadManifest(
                browser, profileName, Path.GetFileName(extensionDirectory), versionDirectory);

            if (extension is not null)
                yield return extension;
        }
    }

    private static string? NewestVersionDirectory(string extensionDirectory)
    {
        try
        {
            return Directory.EnumerateDirectories(extensionDirectory)
                .OrderByDescending(d => ParseVersion(Path.GetFileName(d)))
                .FirstOrDefault();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Chromium version folders look like "1.2.3_0"; anything unparseable
    /// sorts last rather than throwing.</summary>
    private static Version ParseVersion(string name)
    {
        var trimmed = name.Split('_')[0];
        return Version.TryParse(trimmed, out var version) ? version : new Version(0, 0);
    }

    private BrowserExtension? ReadManifest(
        string browser, string profile, string id, string versionDirectory)
    {
        var manifestPath = Path.Combine(versionDirectory, "manifest.json");

        try
        {
            if (!File.Exists(manifestPath) || new FileInfo(manifestPath).Length > MaxManifestBytes)
                return null;

            using var stream = File.OpenRead(manifestPath);
            using var document = JsonDocument.Parse(stream, new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip,
            });

            var root = document.RootElement;

            return new BrowserExtension
            {
                Browser = browser,
                Profile = profile,
                Id = id,
                Name = ReadName(root, versionDirectory),
                Version = ReadString(root, "version") ?? "",
                Permissions = ReadStringArray(root, "permissions"),
                HostPermissions = ReadStringArray(root, "host_permissions"),
                FromStore = ReadFromStore(root),
                InstalledPath = versionDirectory,
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            _log.Info("Sentinel", $"Could not read the manifest for {id}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Extension names are frequently a localisation placeholder like "__MSG_appName__",
    /// because the real name lives in a per-locale messages file.
    ///
    /// Those are resolved rather than discarded. Against a real browser, four of
    /// fifteen extensions named themselves this way, including Adobe Acrobat and
    /// Google Docs Offline; showing the user a thirty-two character id and asking them
    /// to decide whether they trust it is not a question anyone can answer.
    /// </summary>
    private string ReadName(JsonElement root, string versionDirectory)
    {
        var name = ReadString(root, "name") ?? "";

        if (!name.StartsWith("__MSG_", StringComparison.Ordinal))
            return name;

        // __MSG_appName__ -> appName
        var key = name.Trim('_');
        if (key.StartsWith("MSG_", StringComparison.Ordinal))
            key = key["MSG_".Length..];

        var locale = ReadString(root, "default_locale") ?? "en";

        return ReadLocalisedName(versionDirectory, locale, key)
               ?? ReadLocalisedName(versionDirectory, "en", key)
               ?? ReadLocalisedName(versionDirectory, "en_US", key)
               ?? "";
    }

    /// <summary>
    /// Look one string up in _locales/&lt;locale&gt;/messages.json, whose shape is
    /// { "appName": { "message": "Adobe Acrobat" } }.
    /// </summary>
    private string? ReadLocalisedName(string versionDirectory, string locale, string key)
    {
        var path = Path.Combine(versionDirectory, "_locales", locale, "messages.json");

        try
        {
            if (!File.Exists(path) || new FileInfo(path).Length > MaxManifestBytes)
                return null;

            using var stream = File.OpenRead(path);
            using var document = JsonDocument.Parse(stream, new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip,
            });

            // Message keys are matched case-insensitively by Chromium itself.
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (!property.NameEquals(key)
                    && !string.Equals(property.Name, key, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (property.Value.ValueKind == JsonValueKind.Object
                    && property.Value.TryGetProperty("message", out var message)
                    && message.ValueKind == JsonValueKind.String)
                {
                    return message.GetString();
                }
            }

            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Chromium records where an extension came from in "update_url". A store-installed
    /// extension points at the vendor's update service; one loaded from a folder has no
    /// update_url at all.
    ///
    /// An unrecognised update_url returns null rather than false. Enterprise and
    /// self-hosted extensions use their own update servers legitimately, and calling
    /// those sideloaded would accuse every managed machine.
    /// </summary>
    private static bool? ReadFromStore(JsonElement root)
    {
        var updateUrl = ReadString(root, "update_url");

        if (updateUrl is not { Length: > 0 })
            return false;

        string[] storeHosts =
        [
            "clients2.google.com",
            "edge.microsoft.com",
            "extensionupdate.brave.com",
            "update.googleapis.com",
        ];

        foreach (var host in storeHosts)
        {
            if (updateUrl.Contains(host, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return null;
    }

    private static string? ReadString(JsonElement root, string property) =>
        root.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static IReadOnlyList<string> ReadStringArray(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var value) || value.ValueKind != JsonValueKind.Array)
            return [];

        var items = new List<string>();

        foreach (var element in value.EnumerateArray())
        {
            // Manifest v2 permissions arrays mix plain strings with objects; only the
            // strings are permissions.
            if (element.ValueKind == JsonValueKind.String && element.GetString() is { Length: > 0 } item)
                items.Add(item);
        }

        return items;
    }
}
