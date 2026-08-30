namespace Nexus.Core.Security.Persistence;

/// <summary>One installed browser extension, as read from its manifest.</summary>
public sealed record BrowserExtension
{
    public required string Browser { get; init; }
    public required string Profile { get; init; }
    public required string Id { get; init; }
    public required string Name { get; init; }

    public string Version { get; init; } = "";
    public IReadOnlyList<string> Permissions { get; init; } = [];
    public IReadOnlyList<string> HostPermissions { get; init; } = [];

    /// <summary>
    /// False when the extension was loaded from a folder rather than installed from a
    /// store. Null when it could not be determined — an unknown provenance must not be
    /// reported as a sideload.
    /// </summary>
    public bool? FromStore { get; init; }

    public string? InstalledPath { get; init; }

    public string DisplayName => Name.Length > 0 ? Name : Id;

    public string Where => Profile.Length > 0 ? $"{Browser} ({Profile})" : Browser;
}

/// <summary>
/// Explains what the extensions installed in a browser are able to do.
///
/// Browser extensions are the most-overlooked way a machine gets compromised without
/// a single file being written to disk: one that can read every page can read a bank
/// session, and people install them years ago and forget. Nothing on disk looks wrong,
/// so no file scan will ever mention it.
///
/// This is an inventory first and a judgement second. The permissions an ad blocker
/// needs — read and change every site, intercept every request — are exactly the
/// permissions spyware needs, and no static rule can separate them. Reporting every
/// extension with broad access as suspicious would flag uBlock Origin on every machine
/// on earth, and that is the behaviour that teaches people to ignore the tool.
///
/// So capabilities are described plainly and scored at zero. Exactly one thing here
/// carries weight: an extension that was not installed from a store, because store
/// review is a real gate and bypassing it is how unwanted extensions arrive. Every
/// other candidate was tried against a real browser and dropped for firing on
/// ordinary software.
/// </summary>
public static class BrowserExtensionAudit
{
    /// <summary>Host patterns that amount to "every website".</summary>
    private static readonly string[] AllSitesPatterns =
        ["<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*.*/*"];

    /// <summary>Permissions worth saying out loud, in plain language.</summary>
    private static readonly (string Permission, string Meaning)[] NotableCapabilities =
    [
        ("nativeMessaging", "start and talk to a program installed on this machine"),
        ("debugger", "attach to pages the way developer tools do, which bypasses most page protections"),
        ("proxy", "redirect where your browser sends traffic"),
        ("cookies", "read the cookies that keep you signed in to sites"),
        ("webRequest", "see every request the browser makes"),
        ("webRequestBlocking", "block or alter requests before they are sent"),
        ("management", "install, disable or remove your other extensions"),
        ("history", "read your full browsing history"),
        ("downloads", "start downloads and read where they went"),
        ("clipboardRead", "read whatever you have copied"),
        ("tabs", "see the address of every tab you have open"),
        ("privacy", "change your browser's privacy settings"),
    ];

    public static bool CanReadEverySite(BrowserExtension extension)
    {
        foreach (var host in extension.HostPermissions.Concat(extension.Permissions))
        {
            foreach (var pattern in AllSitesPatterns)
            {
                if (string.Equals(host, pattern, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
    }

    /// <summary>
    /// What this extension can do, in words a person can act on. Returned for display
    /// whether or not anything here is worth a signal.
    /// </summary>
    public static IReadOnlyList<string> Capabilities(BrowserExtension extension)
    {
        var capabilities = new List<string>();

        if (CanReadEverySite(extension))
            capabilities.Add("read and change everything on every website you visit");

        var held = new HashSet<string>(extension.Permissions, StringComparer.OrdinalIgnoreCase);

        foreach (var (permission, meaning) in NotableCapabilities)
        {
            if (held.Contains(permission))
                capabilities.Add(meaning);
        }

        return capabilities;
    }

    public static IReadOnlyList<SecuritySignal> Evaluate(IEnumerable<BrowserExtension> extensions)
    {
        var signals = new List<SecuritySignal>();
        var all = extensions.ToArray();

        foreach (var extension in all)
        {
            AddSideloadSignal(extension, signals);
            AddReachSignal(extension, signals);
        }

        return signals;
    }

    /// <summary>
    /// An extension loaded from a folder never passed a store review, and this is how
    /// malicious extensions are installed by other software — quietly, from a
    /// directory, without the user visiting a store at all.
    /// </summary>
    private static void AddSideloadSignal(BrowserExtension extension, List<SecuritySignal> signals)
    {
        if (extension.FromStore != false)
            return;

        signals.Add(new SecuritySignal(
            SignalSource.Persistence,
            CanReadEverySite(extension) ? SignalWeight.Moderate : SignalWeight.Weak,
            "extension-sideloaded",
            $"\"{extension.DisplayName}\" in {extension.Where} was not installed from a browser store. " +
            (CanReadEverySite(extension)
                ? "It can also read and change every website you visit. Extensions installed this way " +
                  "have not been reviewed by anyone, and it is how unwanted ones usually arrive."
                : "Extensions installed this way have not been reviewed by anyone. Developer builds " +
                  "and some corporate tools are installed like this legitimately.")));
    }

    /// <summary>
    /// Records the extensions that hold the most reach, without scoring them.
    ///
    /// This was originally weighted, on the theory that reading every page *and* being
    /// able to launch a program on the machine was an unusual combination. Running it
    /// against a real browser settled that: Adobe Acrobat, Chrome Remote Desktop and
    /// two others held exactly that pair, and every one of them was installed from a
    /// store and doing its job. Four findings out of fifteen extensions, none of them
    /// actionable.
    ///
    /// A signal that fires on the background is not a signal. What is left is worth
    /// showing rather than scoring: the user learns which of their extensions can see
    /// the most, and decides for themselves whether they still want it.
    /// </summary>
    private static void AddReachSignal(BrowserExtension extension, List<SecuritySignal> signals)
    {
        bool everySite = CanReadEverySite(extension);
        bool nativeMessaging = extension.Permissions
            .Contains("nativeMessaging", StringComparer.OrdinalIgnoreCase);

        if (!everySite || !nativeMessaging)
            return;

        signals.Add(new SecuritySignal(
            SignalSource.Persistence,
            SignalWeight.Informational,
            "extension-broad-reach",
            $"\"{extension.DisplayName}\" in {extension.Where} can read and change every website you " +
            "visit, and can also start and talk to a program installed on this machine. Plenty of " +
            "ordinary extensions need both — password managers, document tools, remote desktop " +
            "clients — so this is worth knowing rather than worth worrying about. It is listed " +
            "because it is the most an extension can reach, not because anything is wrong."));
    }
}
