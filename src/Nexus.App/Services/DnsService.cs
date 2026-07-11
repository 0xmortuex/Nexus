using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using Nexus.Core.Logging;
using Nexus.Core.Models;
using Nexus.Core.Persistence;

namespace Nexus.App.Services;

public sealed record DnsResolver(string Name, string Primary, string Secondary);

public sealed record DnsBenchmarkResult(DnsResolver Resolver, double? AverageMs);

/// <summary>
/// DNS latency benchmark + switcher (Hone-style network optimization, the honest
/// version): pings well-known public resolvers so the user can see real numbers
/// for THEIR connection, then sets the chosen resolver per adapter. The previous
/// per-adapter NameServer registry value is captured first — an empty value means
/// DHCP, so undo restores either the static servers or DHCP exactly.
/// </summary>
public sealed class DnsService
{
    public static IReadOnlyList<DnsResolver> WellKnownResolvers { get; } =
    [
        new("Cloudflare", "1.1.1.1", "1.0.0.1"),
        new("Google", "8.8.8.8", "8.8.4.4"),
        new("Quad9", "9.9.9.9", "149.112.112.112"),
        new("OpenDNS", "208.67.222.222", "208.67.220.220"),
    ];

    private const string InterfacesKey = @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

    private readonly ActivityLog _log;
    private readonly JsonStore<DnsBackupState> _backup;

    public DnsService(ActivityLog log, NexusPaths paths)
    {
        _log = log;
        _backup = new JsonStore<DnsBackupState>(
            Path.Combine(paths.Root, "dns-backup.json"),
            NexusJsonContext.Default.DnsBackupState,
            static () => new DnsBackupState());
    }

    public bool HasAppliedCustomDns => _backup.Load().Applied;

    /// <summary>Ping each well-known resolver 4× and average. Null = unreachable
    /// (some networks block ICMP — the UI says so instead of pretending).</summary>
    public async Task<IReadOnlyList<DnsBenchmarkResult>> BenchmarkAsync()
    {
        var results = new List<DnsBenchmarkResult>();
        foreach (var resolver in WellKnownResolvers)
        {
            var times = new List<long>();
            using var ping = new Ping();
            for (int i = 0; i < 4; i++)
            {
                try
                {
                    var reply = await ping.SendPingAsync(resolver.Primary, 1500);
                    if (reply.Status == IPStatus.Success)
                        times.Add(reply.RoundtripTime);
                }
                catch (Exception)
                {
                    // treated as a lost probe
                }
            }
            results.Add(new DnsBenchmarkResult(resolver, times.Count > 0 ? times.Average() : null));
        }

        _log.Info("DNS", "Benchmarked public DNS resolvers: " + string.Join(", ",
            results.Select(r => $"{r.Resolver.Name} {(r.AverageMs is { } ms ? $"{ms:F0} ms" : "no ICMP reply")}")));
        return results;
    }

    /// <summary>Set the resolver on every connected adapter, capturing originals once.</summary>
    public bool Apply(DnsResolver resolver, out string? error)
    {
        error = null;
        var adapters = GetActiveAdapters();
        if (adapters.Count == 0)
        {
            error = "no connected network adapters found";
            return false;
        }

        // Capture originals only once — re-applying a different resolver must not
        // overwrite the true pre-Nexus state.
        if (!_backup.Load().Applied)
        {
            var backups = adapters.Select(a => new AdapterDnsBackup(
                a.Guid, a.Name, ReadNameServer(a.Guid))).ToArray();
            _backup.Save(new DnsBackupState { Adapters = backups });
        }

        foreach (var adapter in adapters)
        {
            if (!RunNetsh($"interface ip set dns name=\"{adapter.Name}\" static {resolver.Primary} primary validate=no", out error)
                || !RunNetsh($"interface ip add dns name=\"{adapter.Name}\" {resolver.Secondary} index=2 validate=no", out error))
            {
                return false;
            }
        }

        _log.Info("DNS", $"Set DNS to {resolver.Name} ({resolver.Primary}, {resolver.Secondary}) on {adapters.Count} adapter(s). Undo restores the previous configuration.");
        return true;
    }

    /// <summary>Restore each adapter to its captured pre-Nexus state (static servers
    /// or DHCP).</summary>
    public bool Restore(out string? error)
    {
        error = null;
        var state = _backup.Load();
        if (!state.Applied)
        {
            error = "no DNS backup to restore";
            return false;
        }

        foreach (var adapter in state.Adapters)
        {
            bool ok = string.IsNullOrWhiteSpace(adapter.OriginalNameServer)
                ? RunNetsh($"interface ip set dns name=\"{adapter.AdapterName}\" dhcp", out error)
                : ApplyStaticList(adapter.AdapterName, adapter.OriginalNameServer, out error);
            if (!ok)
                return false;
        }

        _backup.Save(new DnsBackupState());
        _log.Info("DNS", "Restored the previous DNS configuration on all adapters.");
        return true;
    }

    private bool ApplyStaticList(string adapterName, string nameServerValue, out string? error)
    {
        error = null;
        var servers = nameServerValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        for (int i = 0; i < servers.Length; i++)
        {
            bool ok = i == 0
                ? RunNetsh($"interface ip set dns name=\"{adapterName}\" static {servers[0]} primary validate=no", out error)
                : RunNetsh($"interface ip add dns name=\"{adapterName}\" {servers[i]} index={i + 1} validate=no", out error);
            if (!ok)
                return false;
        }
        return true;
    }

    private static List<(string Guid, string Name)> GetActiveAdapters()
    {
        var result = new List<(string, string)>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus == OperationalStatus.Up
                && nic.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                && nic.Supports(NetworkInterfaceComponent.IPv4))
            {
                result.Add((nic.Id, nic.Name));
            }
        }
        return result;
    }

    /// <summary>The per-interface NameServer registry value: comma-separated static
    /// servers, or empty when DNS comes from DHCP.</summary>
    private static string ReadNameServer(string interfaceGuid)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"{InterfacesKey}\{interfaceGuid}");
        return key?.GetValue("NameServer") as string ?? "";
    }

    private bool RunNetsh(string arguments, out string? error)
    {
        error = null;
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (process is null)
            {
                error = "could not start netsh";
                return false;
            }
            var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            process.WaitForExit(15_000);
            if (process.ExitCode != 0)
            {
                error = $"netsh {arguments}: {output.Trim()}";
                _log.Warn("DNS", error);
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }
}
