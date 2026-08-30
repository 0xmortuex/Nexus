namespace Nexus.Core.Security.Persistence;

/// <summary>One line of the hosts file, already parsed.</summary>
public sealed record HostsEntry(string Address, string Hostname);

/// <summary>The machine-level settings this audit looks at, collected by the App layer.</summary>
public sealed record SystemIntegrityFacts
{
    public IReadOnlyList<HostsEntry> HostsEntries { get; init; } = [];

    /// <summary>WinINET proxy server, when one is configured.</summary>
    public string? ProxyServer { get; init; }

    public bool ProxyEnabled { get; init; }

    /// <summary>A proxy auto-config URL, if set.</summary>
    public string? AutoConfigUrl { get; init; }

    /// <summary>DNS servers currently configured, across all adapters.</summary>
    public IReadOnlyList<string> DnsServers { get; init; } = [];

    /// <summary>True when Nexus itself set the DNS, so its own change is not reported
    /// as a hijack.</summary>
    public bool DnsSetByNexus { get; init; }
}

/// <summary>
/// Checks the handful of machine settings that malware changes to cut you off or
/// redirect you.
///
/// These are old techniques and still current, because they work and almost nobody
/// looks: blackhole your antivirus vendor's domains in the hosts file so it can never
/// update, point the system at a proxy that can read your traffic, or set a DNS
/// server that answers whatever it likes. None of it involves running a program, so
/// nothing else in Sentinel would notice.
///
/// The blocked-security-vendor check is the sharpest signal here. There is no
/// innocent reason for a machine to have its own antivirus vendor redirected to
/// 127.0.0.1, and it is a strong indicator the machine is already compromised.
/// </summary>
public static class SystemIntegrityAudit
{
    /// <summary>Addresses that mean "send this nowhere".</summary>
    private static readonly string[] BlackholeAddresses = ["127.0.0.1", "0.0.0.0", "::1", "localhost"];

    /// <summary>
    /// Security vendors whose domains malware blackholes so updates cannot arrive.
    /// Matched as substrings against the hostname, which is why they are bare names.
    /// </summary>
    private static readonly string[] SecurityDomains =
    [
        "microsoft.com", "windowsupdate.com", "update.microsoft", "defender",
        "avast", "avg.com", "avira", "bitdefender", "eset", "f-secure", "gdata",
        "kaspersky", "malwarebytes", "mcafee", "norton", "symantec", "sophos",
        "trendmicro", "virustotal", "clamav", "comodo", "drweb", "emsisoft",
        "panda", "webroot", "sucuri", "spybot", "safer-networking",
    ];

    public static IReadOnlyList<SecuritySignal> Evaluate(SystemIntegrityFacts facts)
    {
        var signals = new List<SecuritySignal>();

        AddHostsSignals(facts, signals);
        AddProxySignals(facts, signals);
        AddDnsSignals(facts, signals);

        return signals;
    }

    private static void AddHostsSignals(SystemIntegrityFacts facts, List<SecuritySignal> signals)
    {
        var blocked = facts.HostsEntries
            .Where(e => IsBlackhole(e.Address) && IsSecurityDomain(e.Hostname))
            .Select(e => e.Hostname)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (blocked.Length > 0)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Strong,
                "hosts-blocks-security",
                $"Your hosts file redirects {blocked.Length} security or update address(es) to nowhere, " +
                $"including {string.Join(", ", blocked.Take(3))}. That stops antivirus and Windows " +
                "updates from reaching their servers, and it is a standard step for malware trying to " +
                "stay installed."));
        }

        // Redirections to a real address are how phishing pages replace real sites.
        var redirected = facts.HostsEntries
            .Where(e => !IsBlackhole(e.Address) && !IsLocalAddress(e.Address))
            .ToArray();

        if (redirected.Length > 0)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Moderate,
                "hosts-redirects-elsewhere",
                $"Your hosts file sends {redirected.Length} address(es) to a specific machine rather " +
                $"than blocking them — for example {redirected[0].Hostname} to {redirected[0].Address}. " +
                "Development setups do this deliberately; so does anything wanting you on a different " +
                "site than the one you typed."));
        }
    }

    private static void AddProxySignals(SystemIntegrityFacts facts, List<SecuritySignal> signals)
    {
        if (facts.ProxyEnabled && facts.ProxyServer is { Length: > 0 } proxy)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Moderate,
                "proxy-configured",
                $"Your web traffic is routed through a proxy at {proxy}. Workplaces set these " +
                "deliberately; malware sets them to read or alter what you browse. If you did not set " +
                "it up, it should not be there."));
        }

        if (facts.AutoConfigUrl is { Length: > 0 } autoConfig)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Moderate,
                "proxy-autoconfig",
                $"A proxy auto-configuration script at {autoConfig} decides how your traffic is " +
                "routed. That script can send individual sites anywhere it likes."));
        }
    }

    private static void AddDnsSignals(SystemIntegrityFacts facts, List<SecuritySignal> signals)
    {
        if (facts.DnsSetByNexus || facts.DnsServers.Count == 0)
            return;

        // Only report DNS pointing somewhere odd — a public resolver is a normal
        // choice and reporting it would be noise.
        var suspicious = facts.DnsServers
            .Where(server => !IsWellKnownResolver(server) && !IsLocalAddress(server))
            .ToArray();

        if (suspicious.Length > 0)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Weak,
                "dns-unrecognised",
                $"Name lookups go to {string.Join(", ", suspicious.Take(2))}, which is neither your " +
                "router nor a well-known public resolver. That is normal on a company network and is " +
                "also how traffic gets quietly redirected."));
        }
    }

    private static bool IsBlackhole(string address) =>
        BlackholeAddresses.Contains(address.Trim(), StringComparer.OrdinalIgnoreCase);

    private static bool IsSecurityDomain(string hostname) =>
        SecurityDomains.Any(domain => hostname.Contains(domain, StringComparison.OrdinalIgnoreCase));

    /// <summary>Router and private-range addresses, which are ordinary.</summary>
    private static bool IsLocalAddress(string address)
    {
        var trimmed = address.Trim();

        return trimmed.StartsWith("192.168.", StringComparison.Ordinal)
               || trimmed.StartsWith("10.", StringComparison.Ordinal)
               || trimmed.StartsWith("127.", StringComparison.Ordinal)
               || trimmed.StartsWith("172.16.", StringComparison.Ordinal)
               || trimmed.StartsWith("fe80:", StringComparison.OrdinalIgnoreCase)
               || trimmed == "::1";
    }

    private static bool IsWellKnownResolver(string address) =>
        address.Trim() is "8.8.8.8" or "8.8.4.4"          // Google
            or "1.1.1.1" or "1.0.0.1"                      // Cloudflare
            or "9.9.9.9" or "149.112.112.112"              // Quad9
            or "208.67.222.222" or "208.67.220.220"        // OpenDNS
            or "94.140.14.14" or "94.140.15.15"            // AdGuard
            or "76.76.2.0" or "76.76.10.0";                // Control D

    /// <summary>
    /// Parse hosts-file text. Comments and blank lines are ignored, and one line can
    /// map several names to one address.
    /// </summary>
    public static IReadOnlyList<HostsEntry> ParseHosts(IEnumerable<string> lines)
    {
        var entries = new List<HostsEntry>();

        foreach (var raw in lines)
        {
            var line = raw.Trim();

            int comment = line.IndexOf('#');
            if (comment >= 0)
                line = line[..comment].Trim();

            if (line.Length == 0)
                continue;

            var parts = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
                continue;

            for (int i = 1; i < parts.Length; i++)
                entries.Add(new HostsEntry(parts[0], parts[i]));
        }

        return entries;
    }
}
