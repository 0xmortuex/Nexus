using System.IO;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using Nexus.Core.Logging;
using Nexus.Core.Security.Persistence;

namespace Nexus.App.Services.Security;

/// <summary>
/// Reads the machine settings that malware changes to cut you off or redirect you:
/// the hosts file, the WinINET proxy, and the DNS servers in use.
///
/// Read-only. Nexus reports what it finds and does not rewrite the hosts file or
/// clear a proxy — those are settings a workplace may have set deliberately, and a
/// security tool that silently "fixes" them breaks people's machines with the best
/// of intentions. The one exception is DNS, which the Tools tab already changes with
/// an explicit undo, and which is excluded from the audit when Nexus set it.
/// </summary>
public sealed class SystemIntegrityService
{
    private const string ProxyKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    /// <summary>A hosts file bigger than this is an ad-blocking list with hundreds of
    /// thousands of entries. Parsing it fully would stall the audit for no benefit;
    /// the security-vendor check works fine on the first chunk.</summary>
    private const long MaxHostsBytes = 4 * 1024 * 1024;

    private readonly ActivityLog _log;
    private readonly Func<bool> _dnsSetByNexus;

    public SystemIntegrityService(ActivityLog log, Func<bool> dnsSetByNexus)
    {
        _log = log;
        _dnsSetByNexus = dnsSetByNexus;
    }

    public static string HostsFilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

    public SystemIntegrityFacts Collect()
    {
        return new SystemIntegrityFacts
        {
            HostsEntries = ReadHosts(),
            ProxyEnabled = ReadProxyEnabled(),
            ProxyServer = ReadProxyValue("ProxyServer"),
            AutoConfigUrl = ReadProxyValue("AutoConfigURL"),
            DnsServers = ReadDnsServers(),
            DnsSetByNexus = SafeDnsFlag(),
        };
    }

    private bool SafeDnsFlag()
    {
        try
        {
            return _dnsSetByNexus();
        }
        catch (Exception ex)
        {
            _log.Info("Sentinel", $"Could not tell whether Nexus set the DNS: {ex.Message}");
            return false;
        }
    }

    private IReadOnlyList<HostsEntry> ReadHosts()
    {
        try
        {
            var path = HostsFilePath;
            if (!File.Exists(path))
                return [];

            if (new FileInfo(path).Length > MaxHostsBytes)
            {
                _log.Info("Sentinel",
                    "The hosts file is very large — usually an ad-blocking list. Only the first part " +
                    "was checked.");
            }

            // Share.ReadWrite: the file is frequently held open by other tools.
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(stream);

            var lines = new List<string>();
            long read = 0;

            while (reader.ReadLine() is { } line && read < MaxHostsBytes)
            {
                read += line.Length;
                lines.Add(line);
            }

            return SystemIntegrityAudit.ParseHosts(lines);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.Info("Sentinel", $"Could not read the hosts file: {ex.Message}");
            return [];
        }
    }

    private bool ReadProxyEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(ProxyKey);
            return key?.GetValue("ProxyEnable") is int enabled && enabled != 0;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    private string? ReadProxyValue(string name)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(ProxyKey);
            return key?.GetValue(name) as string;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private IReadOnlyList<string> ReadDnsServers()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up
                            && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties().DnsAddresses)
                .Select(a => a.ToString())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException)
        {
            _log.Info("Sentinel", $"Could not read the DNS configuration: {ex.Message}");
            return [];
        }
    }
}
