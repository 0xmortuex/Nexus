using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using Nexus.Core.Logging;

namespace Nexus.App.Services;

/// <summary>
/// Carries a "scan this" request from a second Nexus launch to the one already
/// running.
///
/// Nexus holds a single-instance mutex, so a right-click "Scan with Nexus" would
/// otherwise start a process that immediately discovers it is a duplicate and exits,
/// having done nothing. The second process hands the path over this pipe and quits;
/// the running instance does the work and shows it in the window the user already
/// has.
///
/// The pipe name includes the user name, and the pipe is created with a security
/// descriptor granting only that user. Two people logged into the same machine get
/// separate pipes, and nobody can push scan requests into anybody else's session.
/// The request itself is only ever a path to read — no command, no action — so the
/// worst a malformed message can do is make Nexus look at a file.
/// </summary>
public sealed class ScanRequestChannel : IDisposable
{
    /// <summary>A path longer than Windows allows is not a path, it is a probe.</summary>
    private const int MaxRequestLength = 4096;

    /// <summary>How long one connection may take to send its line before it is dropped.</summary>
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(5);

    private readonly ActivityLog _log;
    private readonly Action<string> _onRequest;
    private CancellationTokenSource _shutdown = new();
    private Task? _listener;

    public ScanRequestChannel(ActivityLog log, Action<string> onRequest)
    {
        _log = log;
        _onRequest = onRequest;
    }

    private static string PipeName =>
        $"Nexus.ScanRequest.{Environment.UserName}";

    /// <summary>
    /// Send a path to the instance already running. Returns false when nothing is
    /// listening, which is the caller's cue that it is the first instance after all.
    /// </summary>
    public static bool TrySend(string path, TimeSpan timeout)
    {
        try
        {
            using var client = new NamedPipeClientStream(
                ".", PipeName, PipeDirection.Out, PipeOptions.None,
                TokenImpersonationLevel.Identification);

            client.Connect((int)timeout.TotalMilliseconds);

            using var writer = new StreamWriter(client) { AutoFlush = true };
            writer.WriteLine(path);

            return true;
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Whether a path that arrived over the pipe may be scanned.
    ///
    /// The pipe's default security restricts it to this user, which keeps other people
    /// on the machine out. It does not keep out an unprivileged process running as this
    /// user, and Nexus is elevated -- so whatever arrives here is a path an ordinary
    /// process, including malware with no rights of its own, can make an administrator
    /// open.
    ///
    /// Reading a local file is what the feature is for. Reaching out to a UNC path is
    /// not: it would make the elevated process authenticate to a server the sender
    /// chose, which is the setup for an NTLM relay and has nothing to do with checking
    /// a file the user right-clicked.
    /// </summary>
    private static bool IsAcceptablePath(string path)
    {
        try
        {
            var full = Path.GetFullPath(path.Trim());

            // UNC, and the device forms that can be aimed at one.
            if (full.StartsWith(@"\\", StringComparison.Ordinal))
                return false;

            return Path.IsPathRooted(full);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException
                                      or PathTooLongException or System.Security.SecurityException)
        {
            return false;
        }
    }

    public void Start()
    {
        _shutdown = new CancellationTokenSource();
        _listener = Task.Run(() => ListenAsync(_shutdown.Token));
    }

    private async Task ListenAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                // A fresh server stream per connection: reusing one after a client
                // disconnects leaves it in a state that never accepts again.
                using var server = CreateServer();

                await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

                using var reader = new StreamReader(server);

                // A connection that never sends a line would otherwise hold the single
                // server instance forever, and every later "Scan with Nexus" would fail
                // to connect and be told Nexus is already running. One local process
                // opening the pipe and going quiet must not cost the whole feature.
                using var readTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                readTimeout.CancelAfter(ReadTimeout);

                string? line;
                try
                {
                    line = await reader.ReadLineAsync(readTimeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    continue;
                }

                if (line is { Length: > 0 and <= MaxRequestLength } && IsAcceptablePath(line))
                    _onRequest(line);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                // One bad connection must not end the listener, or the right-click
                // entry stops working for the rest of the session with no sign why.
                _log.Warn("App", $"A scan request could not be read: {ex.Message}");

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
        }
    }

    /// <summary>
    /// Create the server end, restricted to the current user.
    /// </summary>
    private static NamedPipeServerStream CreateServer()
    {
        return new NamedPipeServerStream(
            PipeName,
            PipeDirection.In,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
    }

    public void Dispose()
    {
        try
        {
            _shutdown.Cancel();

            // Unblock WaitForConnectionAsync: cancellation alone does not always wake
            // a pipe that is parked waiting for a client.
            TrySend("", TimeSpan.FromMilliseconds(200));

            _listener?.Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception ex) when (ex is AggregateException or OperationCanceledException or ObjectDisposedException)
        {
            // Shutting down.
        }
        finally
        {
            _shutdown.Dispose();
            _listener = null;
        }
    }
}
