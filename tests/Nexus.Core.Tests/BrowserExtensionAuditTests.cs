using Nexus.Core.Security;
using Nexus.Core.Security.Persistence;
using Xunit;

namespace Nexus.Core.Tests;

public class BrowserExtensionAuditTests
{
    private static BrowserExtension Extension(
        string name = "Some Extension",
        string[]? permissions = null,
        string[]? hosts = null,
        bool? fromStore = true) =>
        new()
        {
            Browser = "Chrome",
            Profile = "Default",
            Id = "abcdefghijklmnopabcdefghijklmnop",
            Name = name,
            Version = "1.0.0",
            Permissions = permissions ?? [],
            HostPermissions = hosts ?? [],
            FromStore = fromStore,
        };

    private static string[] Codes(params BrowserExtension[] extensions) =>
        BrowserExtensionAudit.Evaluate(extensions).Select(s => s.Code).ToArray();

    // ---- Reach detection ----

    [Theory]
    [InlineData("<all_urls>")]
    [InlineData("*://*/*")]
    [InlineData("http://*/*")]
    [InlineData("https://*/*")]
    public void Every_way_of_asking_for_all_sites_is_recognised(string pattern)
    {
        Assert.True(BrowserExtensionAudit.CanReadEverySite(Extension(hosts: [pattern])));
    }

    [Fact]
    public void All_sites_is_recognised_in_the_permissions_list_too()
    {
        // Manifest v2 put host patterns in "permissions"; v3 moved them to
        // "host_permissions". Checking only one misses half the extensions installed.
        Assert.True(BrowserExtensionAudit.CanReadEverySite(Extension(permissions: ["<all_urls>"])));
    }

    [Fact]
    public void An_extension_scoped_to_one_site_is_not_treated_as_reading_everything()
    {
        Assert.False(BrowserExtensionAudit.CanReadEverySite(
            Extension(hosts: ["https://mail.google.com/*", "https://*.example.com/*"])));
    }

    // ---- The central calibration ----

    /// <summary>
    /// An ad blocker needs to read every page and intercept every request. So does
    /// spyware. No static rule separates them, and flagging the first would flag
    /// uBlock Origin on every machine on earth — which is exactly how a tool teaches
    /// people to ignore it.
    /// </summary>
    [Fact]
    public void A_store_installed_ad_blocker_is_not_reported()
    {
        var adBlocker = Extension(
            name: "uBlock Origin",
            permissions: ["webRequest", "webRequestBlocking", "storage", "tabs"],
            hosts: ["<all_urls>"],
            fromStore: true);

        Assert.Empty(Codes(adBlocker));
    }

    [Fact]
    public void An_ordinary_narrow_extension_is_not_reported()
    {
        Assert.Empty(Codes(Extension(permissions: ["storage"], hosts: ["https://example.com/*"])));
    }

    // ---- What does get reported ----

    [Fact]
    public void An_extension_not_installed_from_a_store_is_reported()
    {
        Assert.Contains("extension-sideloaded", Codes(Extension(fromStore: false)));
    }

    [Fact]
    public void A_sideloaded_extension_that_reads_everything_is_weighted_higher()
    {
        var narrow = BrowserExtensionAudit.Evaluate([Extension(fromStore: false)]);
        var broad = BrowserExtensionAudit.Evaluate([Extension(fromStore: false, hosts: ["<all_urls>"])]);

        Assert.Equal(SignalWeight.Weak, Assert.Single(narrow).Weight);
        Assert.Equal(SignalWeight.Moderate,
            Assert.Single(broad, s => s.Code == "extension-sideloaded").Weight);
    }

    /// <summary>
    /// Unknown provenance must not be reported as a sideload. Same rule as everywhere
    /// else: not knowing is not evidence.
    /// </summary>
    [Fact]
    public void An_extension_of_unknown_provenance_is_not_accused_of_being_sideloaded()
    {
        Assert.DoesNotContain("extension-sideloaded", Codes(Extension(fromStore: null)));
    }

    /// <summary>
    /// Listed, but worth nothing. Measured against a real browser, four of fifteen
    /// extensions held exactly this pair -- Adobe Acrobat and Chrome Remote Desktop
    /// among them -- and every one was store-installed and doing its job. Showing it
    /// is useful; scoring it would flag ordinary software on every machine.
    /// </summary>
    [Fact]
    public void The_most_capable_extensions_are_listed_but_not_scored()
    {
        var extension = Extension(
            permissions: ["nativeMessaging", "tabs"],
            hosts: ["<all_urls>"],
            fromStore: true);

        var signal = Assert.Single(BrowserExtensionAudit.Evaluate([extension]),
            s => s.Code == "extension-broad-reach");

        Assert.Equal(SignalWeight.Informational, signal.Weight);
        Assert.Equal(0, signal.Points);
    }

    [Fact]
    public void A_browser_full_of_capable_extensions_never_raises_an_alert()
    {
        BrowserExtension[] capable =
        [
            Extension("Adobe Acrobat", ["nativeMessaging", "tabs"], ["<all_urls>"]),
            Extension("Chrome Remote Desktop", ["nativeMessaging"], ["<all_urls>"]),
            Extension("Some Assistant", ["nativeMessaging", "debugger"], ["<all_urls>"]),
        ];

        var verdict = VerdictEngine.Evaluate(new VerdictInput
        {
            Target = ScanTarget.ForFile("Browser extensions"),
            Signals = BrowserExtensionAudit.Evaluate(capable),
            EnginesConsulted = new HashSet<SignalSource> { SignalSource.Persistence },
        }, DateTimeOffset.UnixEpoch);

        Assert.False(verdict.WarrantsAlert,
            $"ordinary extensions scored {verdict.Score}/100 as {verdict.Level}");
    }

    [Fact]
    public void Either_capability_alone_is_not_reported()
    {
        // A password manager pattern without the wide host access, and wide host
        // access without the native bridge. Neither on its own is notable.
        Assert.DoesNotContain("extension-broad-reach",
            Codes(Extension(permissions: ["nativeMessaging"], hosts: ["https://x.com/*"])));
        Assert.DoesNotContain("extension-broad-reach",
            Codes(Extension(permissions: ["tabs"], hosts: ["<all_urls>"])));
    }

    // ---- Plain-language capabilities ----

    [Fact]
    public void Capabilities_are_described_in_words_a_person_can_act_on()
    {
        var capabilities = BrowserExtensionAudit.Capabilities(Extension(
            permissions: ["cookies", "nativeMessaging", "history"],
            hosts: ["<all_urls>"]));

        Assert.Contains(capabilities, c => c.Contains("every website you visit"));
        Assert.Contains(capabilities, c => c.Contains("keep you signed in"));
        Assert.Contains(capabilities, c => c.Contains("program installed on this machine"));
        Assert.Contains(capabilities, c => c.Contains("browsing history"));

        // No jargon leaks through to the user.
        Assert.DoesNotContain(capabilities, c => c.Contains("nativeMessaging"));
    }

    [Fact]
    public void An_extension_with_nothing_notable_lists_no_capabilities()
    {
        Assert.Empty(BrowserExtensionAudit.Capabilities(Extension(permissions: ["storage", "alarms"])));
    }

    [Fact]
    public void An_extension_with_no_name_is_identified_by_its_id()
    {
        var extension = Extension(name: "");

        Assert.Equal("abcdefghijklmnopabcdefghijklmnop", extension.DisplayName);
    }

    // ---- Overall ----

    [Fact]
    public void A_typical_browser_full_of_ordinary_extensions_produces_nothing()
    {
        BrowserExtension[] typical =
        [
            Extension("uBlock Origin", ["webRequest", "webRequestBlocking"], ["<all_urls>"]),
            Extension("Bitwarden", ["nativeMessaging"], ["https://vault.bitwarden.com/*"]),
            Extension("Dark Reader", ["storage"], ["<all_urls>"]),
            Extension("Grammarly", ["tabs", "cookies"], ["<all_urls>"]),
        ];

        Assert.Empty(BrowserExtensionAudit.Evaluate(typical));
    }
}
