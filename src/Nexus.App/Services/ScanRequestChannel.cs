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
                var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);

                if (line is { Length: > 0 and <= MaxRequestLength })
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
