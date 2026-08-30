using System.Text.Json;
using Nexus.Core.Security;
using Nexus.Core.Security.Scanning;
using Nexus.Core.Security.StaticAnalysis;
using Nexus.Scanner.Engines;

namespace Nexus.Scanner;

/// <summary>
/// The file-analysis worker.
///
/// It reads one JSON request per line from standard input, analyses that file, and
/// writes one JSON response per line to standard output. It never writes to disk,
/// never opens a network connection, never launches anything, and holds no handle
/// to the parent. If it crashes, the parent restarts it and loses one scan.
///
/// Everything dangerous in Sentinel happens in here, on purpose, so that when
/// something in here goes wrong it goes wrong in a process that can afford it.
/// </summary>
public static class Program
{
    /// <summary>
    /// Files larger than this are not read into memory. A scanner that can be made
    /// to allocate gigabytes by pointing it at a big file is a denial of service
    /// against the machine it is meant to protect.
    /// </summary>
    private const long MaxAnalysableBytes = 128L * 1024 * 1024;

    public static int Main(string[] args)
    {
        if (args.Contains("--self-test"))
            return SelfTest();

        var engines = BuildEngines();

        using var input = Console.In;
        using var output = Console.Out;

        while (input.ReadLine() is { } line)
        {
            if (line.Length == 0)
                continue;

            var response = Handle(line, engines);
            output.WriteLine(JsonSerializer.Serialize(response, ScanJsonContext.Default.ScanResponse));
            output.Flush();
        }

        return 0;
    }

    private static ScanResponse Handle(string line, IReadOnlyList<IStaticEngine> engines)
    {
        ScanRequest? request = null;

        try
        {
            request = JsonSerializer.Deserialize(line, ScanJsonContext.Default.ScanRequest);
        }
        catch (JsonException ex)
        {
            return new ScanResponse { Id = "", Error = "unreadable request: " + ex.Message };
        }

        if (request is null || request.Path.Length == 0)
            return new ScanResponse { Id = request?.Id ?? "", Error = "empty request" };

        return Analyse(request, engines);
    }

    private static ScanResponse Analyse(ScanRequest request, IReadOnlyList<IStaticEngine> engines)
    {
        byte[] bytes;

        try
        {
            var info = new FileInfo(request.Path);
            if (!info.Exists)
                return new ScanResponse { Id = request.Id, Error = "file not found" };

            if (info.Length == 0)
                return new ScanResponse { Id = request.Id, Error = "file is empty" };

            if (info.Length > MaxAnalysableBytes)
                return new ScanResponse { Id = request.Id, Error = "file is too large to analyse" };

            // FileShare.ReadWrite | Delete: never block another program's access to
            // its own file just because a background scan is looking at it.
            using var stream = new FileStream(
                request.Path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);

            bytes = new byte[info.Length];
            int read = stream.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
            if (read < bytes.Length)
                Array.Resize(ref bytes, read);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new ScanResponse { Id = request.Id, Error = "could not read the file: " + ex.Message };
        }

        var signals = new List<ScanSignal>();

        // A set, not a list: several engines share one SignalSource (PE structure and
        // byte patterns are both StaticRules), and reporting a source twice would
        // overstate how many independent opinions the host actually got.
        var consulted = new SortedSet<string>(StringComparer.Ordinal);

        foreach (var engine in engines)
        {
            if (!engine.IsAvailable)
                continue;

            try
            {
                foreach (var signal in engine.Analyse(bytes, request.Path))
                    signals.Add(ScanSignal.From(signal));

                consulted.Add(engine.SignalSource.ToString());
            }
            catch (Exception ex)
            {
                // One engine failing must not lose the other engines' findings. The
                // failure is reported rather than swallowed, so a systematically
                // broken engine is visible instead of silently scanning nothing.
                signals.Add(new ScanSignal
                {
                    Source = engine.SignalSource.ToString(),
                    Weight = SignalWeight.Informational.ToString(),
                    Code = "engine-error",
                    Explanation = $"The {engine.Name} engine failed on this file: {ex.Message}",
                });
            }
        }

        return new ScanResponse
        {
            Id = request.Id,
            Signals = signals,
            EnginesConsulted = consulted.ToArray(),
        };
    }

    private static IReadOnlyList<IStaticEngine> BuildEngines() =>
    [
        new PeStaticEngine(),
        new ScriptStaticEngine(),
        new ArchiveStaticEngine(),
        PatternSignatureEngine.Create(),
        YaraEngine.Create(),
        MachineLearningEngine.Create(),
    ];

    /// <summary>Lets the host verify the worker actually runs before relying on it.</summary>
    private static int SelfTest()
    {
        var available = BuildEngines()
            .Where(e => e.IsAvailable)
            .Select(e => e.Name);

        Console.WriteLine(string.Join(",", available));
        return 0;
    }
}
