using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using Nexus.Core.Logging;
using Nexus.Core.Security;
using Nexus.Core.Security.Behavior;

namespace Nexus.App.Services.Security;

/// <summary>One process's outbound connection.</summary>
public sealed record ConnectionInfo
{
    public required int Pid { get; init; }
    public required string ProcessName { get; init; }
    public required string RemoteAddress { get; init; }
    public required int RemotePort { get; init; }
    public required string State { get; init; }
}

/// <summary>
/// Lists who on this machine is talking to the internet, and flags the combinations
/// worth a second look.
///
/// Driver-free: <c>GetExtendedTcpTable</c> is the same documented API netstat uses.
/// It gives a point-in-time picture rather than a stream, which is the honest limit —
/// a connection that opens and closes between polls is invisible, so this is a tool
/// for answering "what is talking right now" rather than a complete audit trail.
///
/// The judgement here is deliberately narrow. Flagging every unusual port would bury
/// the user, so it reports the two combinations that are genuinely odd on a desktop:
/// a program in a temp folder talking to the internet at all, and a connection to a
/// bare IP address on a port associated with remote control.
/// </summary>
public sealed class NetworkMonitorService
{
    private const int AF_INET = 2;
    private const int TCP_TABLE_OWNER_PID_CONNECTIONS = 4;

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable, ref int size, bool order, int ipVersion, int tableClass, int reserved);

    /// <summary>Ports that carry remote control or file transfer. A browser never
    /// uses these; a remote-access tool does.</summary>
    private static readonly Dictionary<int, string> NotablePorts = new()
    {
        [3389] = "Remote Desktop",
        [5900] = "VNC remote control",
        [4444] = "a port commonly used by remote-access payloads",
        [1080] = "a SOCKS proxy",
        [6667] = "IRC, which older botnets use for control",
        [23] = "Telnet",
        [21] = "FTP",
        [445] = "Windows file sharing",
    };

    private readonly ActivityLog _log;

    public NetworkMonitorService(ActivityLog log)
    {
        _log = log;
    }

    /// <summary>Every established outbound TCP connection with its owning process.</summary>
    public IReadOnlyList<ConnectionInfo> GetConnections()
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);

        if (size <= 0)
            return [];

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            uint result = GetExtendedTcpTable(
                buffer, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);

            if (result != 0)
            {
                _log.Warn("Sentinel", $"Could not read the connection table (error {result}).");
                return [];
            }

            int rowCount = Marshal.ReadInt32(buffer);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            var connections = new List<ConnectionInfo>(rowCount);
            var nameCache = new Dictionary<int, string>();

            for (int i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(
                    buffer + sizeof(int) + i * rowSize);

                // 5 = ESTABLISHED. Listening sockets are not outbound traffic.
                if (row.state != 5)
                    continue;

                int pid = (int)row.owningPid;

                connections.Add(new ConnectionInfo
                {
                    Pid = pid,
                    ProcessName = ResolveName(pid, nameCache),
                    RemoteAddress = new IPAddress(row.remoteAddr).ToString(),
                    RemotePort = DecodePort(row.remotePort),
                    State = "established",
                });
            }

            return connections;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return [];
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Ports arrive with the bytes in network order packed into a DWORD.</summary>
    private static int DecodePort(uint port) =>
        ((int)(port & 0xFF) << 8) | (int)((port >> 8) & 0xFF);

    private static string ResolveName(int pid, Dictionary<int, string> cache)
    {
        if (cache.TryGetValue(pid, out var cached))
            return cached;

        string name;
        try
        {
            using var process = Process.GetProcessById(pid);
            name = process.ProcessName;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            name = $"pid {pid}";
        }

        cache[pid] = name;
        return name;
    }

    /// <summary>
    /// Look at the current connections and report anything genuinely odd.
    /// <paramref name="imagePathResolver"/> supplies the executable path for a PID,
    /// so the location check can run without this class taking a dependency on the
    /// process API.
    /// </summary>
    public IReadOnlyList<SecuritySignal> Evaluate(
        IReadOnlyList<ConnectionInfo> connections, Func<int, string?> imagePathResolver)
    {
        var signals = new List<SecuritySignal>();
        var reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var connection in connections)
        {
            var imagePath = imagePathResolver(connection.Pid);

            if (imagePath is { Length: > 0 } && RunsFromTempFolder(imagePath) && reported.Add(imagePath))
            {
                signals.Add(new SecuritySignal(
                    SignalSource.Behavior,
                    SignalWeight.Moderate,
                    "net-temp-folder-connection",
                    $"{connection.ProcessName} is running from a temporary folder and is connected to " +
                    $"{connection.RemoteAddress}. Installers do run from there, but they do not usually " +
                    "stay connected."));
            }

            if (NotablePorts.TryGetValue(connection.RemotePort, out var description)
                && reported.Add($"{connection.ProcessName}:{connection.RemotePort}"))
            {
                signals.Add(new SecuritySignal(
                    SignalSource.Behavior,
                    SignalWeight.Weak,
                    "net-notable-port",
                    $"{connection.ProcessName} is connected to {connection.RemoteAddress} on port " +
                    $"{connection.RemotePort} ({description})."));
            }
        }

        return signals;
    }

    private static bool RunsFromTempFolder(string imagePath) =>
        PathHelpers.ContainsSegment(imagePath, "AppData\\Local\\Temp")
        || PathHelpers.ContainsSegment(imagePath, "Windows\\Temp")
        || PathHelpers.ContainsSegment(imagePath, "$Recycle.Bin");
}
