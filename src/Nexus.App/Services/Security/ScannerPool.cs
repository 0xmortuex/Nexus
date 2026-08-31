using System.Threading.Channels;
using Nexus.Core.Logging;
using Nexus.Core.Security;

namespace Nexus.App.Services.Security;

/// <summary>
/// A small pool of scanner workers, so several files can be analysed at once.
///
/// <see cref="ScannerHost"/> is deliberately one process behind one gate: that is what
/// makes a crashed worker cost exactly one scan and nothing else. The cost is that it
/// serialises. With the host side scanning several files in parallel, a single worker
/// becomes the queue everything waits in.
///
/// So the answer is more workers rather than a shared one, which keeps the isolation
/// property intact — a worker that dies still takes down only its own scan, and the
/// pool simply hands out the next one.
///
/// The surface matches <see cref="ScannerHost"/> so nothing above it had to change.
/// </summary>
public sealed class ScannerPool : IDisposable
{
    private readonly ScannerHost[] _workers;
    private readonly Channel<ScannerHost> _available;
    private bool _disposed;

    public ScannerPool(ActivityLog log, int size)
    {
        size = Math.Max(1, size);

        _workers = new ScannerHost[size];
        _available = Channel.CreateUnbounded<ScannerHost>();

        for (int i = 0; i < size; i++)
        {
            _workers[i] = new ScannerHost(log);
            _available.Writer.TryWrite(_workers[i]);
        }
    }

    public int Size => _workers.Length;

    /// <summary>False when no worker is usable.</summary>
    public bool IsAvailable => _workers.Any(w => w.IsAvailable);

    public IReadOnlyList<string> EngineNames => _workers[0].EngineNames;

    /// <summary>
    /// Ask one worker what it can do. Only one is asked: they are identical processes,
    /// and starting all of them just to read the same answer would cost a process
    /// launch each for nothing.
    /// </summary>
    public void QueryEngines() => _workers[0].QueryEngines();

    /// <summary>
    /// Analyse a file on whichever worker is free, waiting for one if they are all
    /// busy. Never throws: a failed scan degrades the report, it does not fail.
    /// </summary>
    public async Task<(IReadOnlyList<SecuritySignal> Signals, IReadOnlySet<SignalSource> Engines)> ScanAsync(
        string path, CancellationToken cancellationToken = default)
    {
        if (_disposed || !IsAvailable)
            return ([], new HashSet<SignalSource>());

        ScannerHost worker;
        try
        {
            worker = await _available.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is ChannelClosedException or OperationCanceledException)
        {
            return ([], new HashSet<SignalSource>());
        }

        try
        {
            return await worker.ScanAsync(path, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Returned even when the scan failed. ScannerHost restarts its own process
            // on the next request, so a worker that just died is still usable; dropping
            // it here would shrink the pool to nothing over a long scan.
            if (!_disposed)
                _available.Writer.TryWrite(worker);
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _available.Writer.TryComplete();

        foreach (var worker in _workers)
            worker.Dispose();
    }
}
