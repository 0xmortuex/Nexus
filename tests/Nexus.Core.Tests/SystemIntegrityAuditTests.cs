using Nexus.Core.Security;
using Nexus.Core.Security.Persistence;
using Xunit;

namespace Nexus.Core.Tests;

public class SystemIntegrityAuditTests
{
    private static string[] Codes(SystemIntegrityFacts facts) =>
        SystemIntegrityAudit.Evaluate(facts).Select(s => s.Code).ToArray();

    // ---- Hosts file parsing ----

    [Fact]
    public void The_default_windows_hosts_file_yields_no_entries()
    {
        // Windows ships this file as nothing but comments.
        string[] lines =
        [
            "# Copyright (c) 1993-2009 Microsoft Corp.",
            "#",
            "#      102.54.94.97     rhino.acme.com          # source server",
            "",
            "\t# localhost name resolution is handled within DNS itself.",
        ];

        Assert.Empty(SystemIntegrityAudit.ParseHosts(lines));
    }

    [Fact]
    public void Trailing_comments_are_stripped_from_real_entries()
    {
        var entries = SystemIntegrityAudit.ParseHosts(["127.0.0.1  example.com  # blocked"]);

        var entry = Assert.Single(entries);
        Assert.Equal("127.0.0.1", entry.Address);
        Assert.Equal("example.com", entry.Hostname);
    }

    [Fact]
    public void One_line_can_map_several_names()
    {
        var entries = SystemIntegrityAudit.ParseHosts(["0.0.0.0 a.com b.com c.com"]);

        Assert.Equal(3, entries.Count);
        Assert.All(entries, e => Assert.Equal("0.0.0.0", e.Address));
    }

    // ---- The sharp signal ----

    /// <summary>There is no innocent reason for a machine to blackhole its own
    /// antivirus vendor.</summary>
    [Fact]
    public void Blackholing_security_vendors_is_strong_evidence()
    {
        var facts = new SystemIntegrityFacts
        {
            HostsEntries = SystemIntegrityAudit.ParseHosts(
            [
                "127.0.0.1 www.malwarebytes.com",
                "0.0.0.0 update.microsoft.com",
                "127.0.0.1 www.kaspersky.com",
            ]),
        };

        var signal = Assert.Single(SystemIntegrityAudit.Evaluate(facts), s => s.Code == "hosts-blocks-security");
        Assert.Equal(SignalWeight.Strong, signal.Weight);
    }

    [Fact]
    public void Blocking_ordinary_sites_is_not_reported_as_a_security_block()
    {
        // Ad-blocking hosts files are extremely common and entirely legitimate.
        var facts = new SystemIntegrityFacts
        {
            HostsEntries = SystemIntegrityAudit.ParseHosts(
            [
                "0.0.0.0 ads.example.com",
                "0.0.0.0 tracker.example.net",
            ]),
        };

        Assert.DoesNotContain("hosts-blocks-security", Codes(facts));
    }

    [Fact]
    public void A_redirection_to_a_real_machine_is_reported()
    {
        var facts = new SystemIntegrityFacts
        {
            HostsEntries = SystemIntegrityAudit.ParseHosts(["203.0.113.9 www.mybank.example"]),
        };

        Assert.Contains("hosts-redirects-elsewhere", Codes(facts));
    }

    [Fact]
    public void A_local_development_redirect_is_not_reported_as_one()
    {
        var facts = new SystemIntegrityFacts
        {
            HostsEntries = SystemIntegrityAudit.ParseHosts(
            [
                "127.0.0.1 myapp.local",
                "192.168.1.50 staging.internal",
            ]),
        };

        Assert.DoesNotContain("hosts-redirects-elsewhere", Codes(facts));
    }

    // ---- Proxy ----

    [Fact]
    public void A_configured_proxy_is_reported()
    {
        Assert.Contains("proxy-configured",
            Codes(new SystemIntegrityFacts { ProxyEnabled = true, ProxyServer = "203.0.113.5:8080" }));
    }

    [Fact]
    public void A_disabled_proxy_setting_is_not_reported()
    {
        Assert.DoesNotContain("proxy-configured",
            Codes(new SystemIntegrityFacts { ProxyEnabled = false, ProxyServer = "203.0.113.5:8080" }));
    }

    [Fact]
    public void A_proxy_autoconfig_url_is_reported()
    {
        Assert.Contains("proxy-autoconfig",
            Codes(new SystemIntegrityFacts { AutoConfigUrl = "http://203.0.113.5/proxy.pac" }));
    }

    // ---- DNS ----

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.1.1.1")]
    [InlineData("9.9.9.9")]
    [InlineData("192.168.1.1")]
    public void Ordinary_dns_servers_are_not_reported(string server)
    {
        Assert.DoesNotContain("dns-unrecognised",
            Codes(new SystemIntegrityFacts { DnsServers = [server] }));
    }

    [Fact]
    public void An_unrecognised_dns_server_is_weak_evidence_only()
    {
        var signals = SystemIntegrityAudit.Evaluate(
            new SystemIntegrityFacts { DnsServers = ["203.0.113.99"] });

        var signal = Assert.Single(signals, s => s.Code == "dns-unrecognised");
        Assert.Equal(SignalWeight.Weak, signal.Weight);
    }

    /// <summary>Nexus can set the DNS itself from the Tools tab; reporting its own
    /// change as a hijack would be the self-flagging problem again.</summary>
    [Fact]
    public void Dns_that_nexus_set_itself_is_not_reported()
    {
        Assert.DoesNotContain("dns-unrecognised",
            Codes(new SystemIntegrityFacts { DnsServers = ["203.0.113.99"], DnsSetByNexus = true }));
    }

    [Fact]
    public void A_clean_machine_produces_nothing()
    {
        Assert.Empty(SystemIntegrityAudit.Evaluate(new SystemIntegrityFacts
        {
            HostsEntries = [],
            ProxyEnabled = false,
            DnsServers = ["192.168.1.1", "8.8.8.8"],
        }));
    }
}
