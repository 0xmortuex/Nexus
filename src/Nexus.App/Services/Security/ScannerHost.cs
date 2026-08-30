using System.Diagnostics;
using System.IO;
using System.Text.Json;
using Nexus.Core.Logging;
using Nexus.Core.Security;
using Nexus.Core.Security.Scanning;

namespace Nexus.App.Services.Security;

/// <summary>
/// Runs and talks to the scanner worker process.
///
/// The worker is treated as untrusted and unreliable on purpose: it parses hostile
/// files, so the assumption is that it will eventually be crashed or subverted by
/// one. Everything here follows from that — a hard timeout on every request, a kill
/// and restart on any misbehaviour, a cap on restarts so a reproducible crash turns
/// into a reported fault rather than an infinite respawn loop, and no data from the
/// worker ever being used as anything but text.
/// </summary>
public sealed class ScannerHost : IDisposable
{
    /// <summary>A single file should take milliseconds. Ten seconds means the worker
    /// is stuck — usually on a deliberately malformed file.</summary>
    public static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Past this many restarts, stop trying. A worker that dies every time
    /// is a bug to report, not something to keep respawning.</summary>
    public const int MaxRestarts = 5;

    private readonly ActivityLog _log;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private Process? _worker;
    private int _restarts;
    private bool _disabled;
    private bool _disposed;

    public ScannerHost(ActivityLog log)
    {
        _log = log;
    }

    /// <summary>False when the worker is missing or has failed too often.</summary>
    public bool IsAvailable => !_disabled && File.Exists(WorkerPath);

    public static string WorkerPath =>
        Path.Combine(AppContext.BaseDirectory, "Nexus.Scanner.exe");

    /// <summary>
    /// Analyse one file. Returns the signals the worker produced plus which engines
    /// ran, or an empty result if the worker is unavailable — never an exception,
    /// because a failed scan must degrade the report, not the application.
    /// </summary>
    public async Task<(IReadOnlyList<SecuritySignal> Signals, IReadOnlySet<SignalSource> Engines)> ScanAsync(
        string path, CancellationToken cancellationToken = default)
    {
        if (!IsAvailable)
            return ([], new HashSet<SignalSource>());

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var response = await ExchangeAsync(path, cancellationToken).ConfigureAwait(false);
            if (response is null)
                return ([], new HashSet<SignalSource>());

            if (response.Error is { Length: > 0 } error)
            {
                // Not a failure worth alarming anyone about: unreadable and oversized
                // files are ordinary. It just means this engine had no opinion.
                _log.Info("Sentinel", $"{Path.GetFileName(path)}: {error}");
                return ([], new HashSet<SignalSource>());
            }

            var signals = response.Signals.Select(s => s.ToSignal()).ToArray();

            var engines = new HashSet<SignalSource>();
            foreach (var name in response.EnginesConsulted)
            {
                if (Enum.TryParse<SignalSource>(name, ignoreCase: false, out var source))
                    engines.Add(source);
            }

            return (signals, engines);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<ScanResponse?> ExchangeAsync(string path, CancellationToken cancellationToken)
    {
        for (int attempt = 0; attempt < 2; attempt++)
        {
            var worker = EnsureRunning();
            if (worker is null)
                return null;

            try
            {
                var request = new ScanRequest { Id = Guid.NewGuid().ToString("n"), Path = path };
                var line = JsonSerializer.Serialize(request, ScanJsonContext.Default.ScanRequest);

                await worker.StandardInput.WriteLineAsync(line.AsMemory(), cancellationToken).ConfigureAwait(false);
                await worker.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);

                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(RequestTimeout);

                var reply = await worker.StandardOutput.ReadLineAsync(timeout.Token).ConfigureAwait(false);
                if (reply is null)
                {
                    // The worker closed its output: it has died.
                    Restart("the scanner stopped unexpectedly");
                    continue;
                }

                var response = JsonSerializer.Deserialize(reply, ScanJsonContext.Default.ScanResponse);
                if (response is null || response.Id != request.Id)
                {
                    // A reply that does not match the request means the stream is out
                    // of step; the only safe move is a fresh worker.
                    Restart("the scanner sent a reply that did not match the request");
                    continue;
                }

                return response;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                Restart($"the scanner took longer than {RequestTimeout.TotalSeconds:F0}s on {Path.GetFileName(path)}");
            }
            catch (Exception ex) when (ex is IOException or JsonException or InvalidOperationException)
            {
                Restart($"the scanner failed: {ex.Message}");
            }
        }

        return null;
    }

    private Process? EnsureRunning()
    {
        if (_worker is { HasExited: false })
            return _worker;

        // Never spawn during or after shutdown. Dispose kills the worker, which can
        // surface inside an in-flight ScanAsync as an ObjectDisposedException — caught
        // as InvalidOperationException, which routes into Restart() and would
        // otherwise start a fresh worker process nobody will ever clean up.
        if (_disposed || _disabled || !File.Exists(WorkerPath))
            return null;

        try
        {
            _worker = Process.Start(new ProcessStartInfo
            {
                FileName = WorkerPath,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = AppContext.BaseDirectory,
            });

            if (_worker is null)
                return null;

            // Scanning is background work; it must never compete with the game the
            // rest of Nexus exists to keep smooth.
            TrySetLowPriority(_worker);

            return _worker;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            _log.Warn("Sentinel", $"Could not start the file scanner: {ex.Message}");
            _disabled = true;
            return null;
        }
    }

    private static void TrySetLowPriority(Process process)
    {
        try
        {
            process.PriorityClass = ProcessPriorityClass.BelowNormal;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // Already exited, or we lack the right; neither is fatal.
        }
    }

    private void Restart(string reason)
    {
        Kill();

        _restarts++;
        if (_restarts > MaxRestarts)
        {
            _disabled = true;
            _log.Warn("Sentinel",
                $"File scanning is off for this session: {reason}. The scanner failed {_restarts} times. " +
                "Signature checks, startup auditing and behaviour monitoring are unaffected.");
            return;
        }

        _log.Info("Sentinel", $"Restarting the file scanner ({reason}).");
    }

    private void Kill()
    {
        if (_worker is null)
            return;

        try
        {
            if (!_worker.HasExited)
                _worker.Kill(entireProcessTree: true);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // Already gone.
        }

        _worker.Dispose();
        _worker = null;
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        Kill();
        _gate.Dispose();
    }
}
