using System.Diagnostics;
using Nexus.App.Interop.Security;
using Nexus.Core.Logging;
using Nexus.Core.Security;
using System.Text.Json;
using Nexus.Core.Security.Scanning;
using Nexus.Core.Security.StaticAnalysis;

namespace Nexus.Sweep;

/// <summary>
/// Runs Sentinel's scoring over a real folder and reports what would be flagged.
///
/// This exists because unit tests kept passing while the product was wrong. Every
/// false positive of consequence in this module was written with a plausible
/// rationale, covered by a test that agreed with it, and only fell over when pointed
/// at an actual disk:
///
/// - Minified JavaScript was exempted from the obfuscation rules, which looked
///   correct and fixed almost nothing: 1,988 of 18,889 files in one web project were
///   still reported, because <c>typescript.js</c> is not minified and a lexer calls
///   String.fromCharCode on every line.
/// - The "build timestamp is in the future" rule fired on nearly every modern DLL,
///   because deterministic builds put a content hash in that field.
/// - A .NET assembly with dense embedded resources was called "packed", which
///   surfaced only when a new dependency happened to include one.
///
/// A test proves a rule does what its author meant. This proves what the rule does to
/// the machine it is installed on, which is a different question and the one that
/// matters. Run it against a folder full of ordinary software: the right answer is
/// almost always zero.
///
///   dotnet run --project tools/Nexus.Sweep -- "C:\Users\me\Downloads"
///   dotnet run --project tools/Nexus.Sweep -- --running
///
/// It reads files and prints. It changes nothing, quarantines nothing, and needs no
/// elevation beyond what reading the target requires.
/// </summary>
public static class Program
{
    /// <summary>Extensions any engine here has an opinion about.</summary>
    private static readonly HashSet<string> Interesting = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx",
        ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".hta", ".htm", ".html",
        ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".jar",
    };

    /// <summary>Reading a file larger than this to reach a verdict is not worth the disk.</summary>
    private const long MaxBytes = 64L * 1024 * 1024;

    public static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("usage: Nexus.Sweep <folder> | --running");
            return 2;
        }

        var verifier = new AuthenticodeVerifier(new ActivityLog(null));
        var target = args[0];

        // The worker holds the engines this process cannot: archives, byte patterns,
        // and YARA when it is present. Without it the sweep measures half the product
        // and reports the other half as clean, which is the exact failure mode this
        // tool exists to prevent.
        using var worker = ScannerWorker.TryStart();

        Console.WriteLine(worker is null
            ? "Scanner worker not found; archive and pattern engines are NOT being measured. "
              + "Build the solution first."
            : $"Using scanner worker: {worker.Path}");

        var sources = target == "--running" ? RunningImages() : FilesUnder(target);

        int scanned = 0;
        int alerts = 0;
        var byExtension = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var worst = new List<(int Score, ThreatLevel Level, string Path, string Codes)>();
        var tally = new object();

        // Matches what the product does. Scanning serially measured 65 files a second
        // on this machine and made a full-disk sweep an overnight job; almost all of
        // that time is spent waiting on signature verification rather than computing,
        // so running several files at once turns the wait into throughput.
        int concurrency = Math.Clamp(Environment.ProcessorCount - 2, 2, 8);
        var stopwatch = Stopwatch.StartNew();

        Parallel.ForEach(
            sources.Where(path => Interesting.Contains(Path.GetExtension(path))),
            new ParallelOptions { MaxDegreeOfParallelism = concurrency },
            path =>
            {
                long size;
                try
                {
                    size = new FileInfo(path).Length;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    return;
                }

                if (size == 0 || size > MaxBytes)
                    return;

                var verdict = Judge(verifier, worker, path, size);
                if (verdict is null)
                    return;

                lock (tally)
                {
                    scanned++;

                    if (!verdict.WarrantsAlert)
                        return;

                    alerts++;
                    var extension = Path.GetExtension(path);
                    byExtension[extension] = byExtension.GetValueOrDefault(extension) + 1;

                    worst.Add((verdict.Score, verdict.Level, path,
                        string.Join(",", verdict.Signals.Where(s => !s.Exonerating).Select(s => s.Code).Distinct())));
                }
            });

        stopwatch.Stop();

        Console.WriteLine($"{scanned / Math.Max(stopwatch.Elapsed.TotalSeconds, 0.001):F0} files/sec " +
                          $"across {concurrency} at a time, {stopwatch.Elapsed.TotalSeconds:F1}s total.");

        Report(target, scanned, alerts, byExtension, worst);

        // Non-zero when anything was flagged, so this can gate a release if wanted.
        return alerts == 0 ? 0 : 1;
    }

    /// <summary>
    /// The whole pipeline: signature and PE/script analysis in this process, then the
    /// worker's engines — archives, byte patterns, and YARA where it is installed —
    /// fused exactly as SentinelService fuses them.
    ///
    /// Hash reputation is the one thing left out, because it depends on a baseline the
    /// user builds on their own machine. Its absence makes this sweep *more*
    /// pessimistic than the product rather than less: reputation only ever exonerates.
    /// </summary>
    private static Verdict? Judge(
        AuthenticodeVerifier verifier, ScannerWorker? worker, string path, long size)
    {
        var signals = new List<SecuritySignal>();
        var engines = new HashSet<SignalSource>();

        var signature = verifier.Verify(path);
        if (signature.State != SignatureState.Unknown)
        {
            signals.AddRange(AuthenticodeVerifier.ToSignals(signature));
            engines.Add(SignalSource.CodeSignature);
        }

        try
        {
            var bytes = File.ReadAllBytes(path);

            if (PeImage.TryParse(bytes) is { } image)
            {
                signals.AddRange(PeHeuristics.Evaluate(image));
                engines.Add(SignalSource.StaticRules);
            }
            else if (ScriptAnalyzer.KindFromExtension(path) is var kind and not ScriptKind.Unknown)
            {
                signals.AddRange(ScriptAnalyzer.Analyse(ScriptAnalyzer.DecodeText(bytes), kind));
                engines.Add(SignalSource.StaticRules);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        if (worker is not null)
        {
            var (workerSignals, workerEngines) = worker.Scan(path);
            signals.AddRange(workerSignals);
            foreach (var engine in workerEngines)
                engines.Add(engine);
        }

        return VerdictEngine.Evaluate(new VerdictInput
        {
            Target = ScanTarget.ForFile(path, null, size),
            Signals = signals,
            EnginesConsulted = engines,
        }, DateTimeOffset.Now);
    }

    private static IEnumerable<string> FilesUnder(string root)
    {
        if (!Directory.Exists(root))
        {
            Console.Error.WriteLine($"{root} is not a folder.");
            return [];
        }

        return Directory.EnumerateFiles(root, "*", new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
        });
    }

    /// <summary>The distinct files behind the processes running now. Protected
    /// processes refuse and are skipped, which is the normal case.</summary>
    private static IEnumerable<string> RunningImages()
    {
        var paths = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (process.MainModule?.FileName is { Length: > 0 } path && File.Exists(path))
                    paths.Add(path);
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception
                                          or InvalidOperationException or NotSupportedException)
            {
                // Protected, or gone between enumeration and the question.
            }
            finally
            {
                process.Dispose();
            }
        }

        Console.WriteLine($"{paths.Count} process image(s) could be read.");
        return paths;
    }

    /// <summary>
    /// Drives the real <c>Nexus.Scanner.exe</c> over the same line-delimited JSON
    /// protocol the product uses.
    ///
    /// Compiling its engines in instead was not an option: they are an executable's
    /// internals, and duplicating them would let this tool drift from what actually
    /// ships — reporting confidently on behaviour the product does not have.
    /// </summary>
    private sealed class ScannerWorker : IDisposable
    {
        private readonly Process _process;

        public string Path { get; }

        private ScannerWorker(Process process, string path)
        {
            _process = process;
            Path = path;
        }

        /// <summary>Find and start the worker, or return null if it has not been built.</summary>
        public static ScannerWorker? TryStart()
        {
            var candidates = new[]
            {
                System.IO.Path.Combine(AppContext.BaseDirectory, "Nexus.Scanner.exe"),
                System.IO.Path.Combine(AppContext.BaseDirectory,
                    @"..\..\..\..\..\src\Nexus.Scanner\bin\Release\net8.0\Nexus.Scanner.exe"),
                System.IO.Path.Combine(AppContext.BaseDirectory,
                    @"..\..\..\..\..\src\Nexus.Scanner\bin\Debug\net8.0\Nexus.Scanner.exe"),
            };

            foreach (var candidate in candidates)
            {
                var full = System.IO.Path.GetFullPath(candidate);
                if (!File.Exists(full))
                    continue;

                try
                {
                    var process = Process.Start(new ProcessStartInfo
                    {
                        FileName = full,
                        RedirectStandardInput = true,
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    });

                    if (process is not null)
                        return new ScannerWorker(process, full);
                }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or IOException)
                {
                    // Try the next candidate.
                }
            }

            return null;
        }

        private readonly object _exchange = new();

        public (IReadOnlyList<SecuritySignal> Signals, IReadOnlyList<SignalSource> Engines) Scan(string path)
        {
            // One worker, one request at a time. The sweep runs several files in
            // parallel, and two threads writing into the same pipe would interleave.
            lock (_exchange)
            try
            {
                var request = JsonSerializer.Serialize(
                    new ScanRequest { Id = "sweep", Path = path }, ScanJsonContext.Default.ScanRequest);

                _process.StandardInput.WriteLine(request);
                _process.StandardInput.Flush();

                var line = _process.StandardOutput.ReadLine();
                if (line is not { Length: > 0 })
                    return ([], []);

                var response = JsonSerializer.Deserialize(line, ScanJsonContext.Default.ScanResponse);
                if (response is null || response.Error is { Length: > 0 })
                    return ([], []);

                var engines = response.EnginesConsulted
                    .Select(name => Enum.TryParse<SignalSource>(name, out var source)
                        ? source
                        : SignalSource.StaticRules)
                    .Distinct()
                    .ToArray();

                return (response.Signals.Select(s => s.ToSignal()).ToArray(), engines);
            }
            catch (Exception ex) when (ex is IOException or JsonException or InvalidOperationException)
            {
                return ([], []);
            }
        }

        public void Dispose()
        {
            try
            {
                _process.StandardInput.Close();

                if (!_process.WaitForExit(3000))
                    _process.Kill();
            }
            catch (Exception ex) when (ex is InvalidOperationException or IOException
                                          or System.ComponentModel.Win32Exception)
            {
                // Shutting down.
            }
            finally
            {
                _process.Dispose();
            }
        }
    }

    private static void Report(
        string target,
        int scanned,
        int alerts,
        Dictionary<string, int> byExtension,
        List<(int Score, ThreatLevel Level, string Path, string Codes)> worst)
    {
        Console.WriteLine($"{target}: scanned {scanned:N0} file(s), {alerts:N0} would be reported.");

        if (alerts == 0)
        {
            Console.WriteLine("Nothing flagged.");
            return;
        }

        Console.WriteLine();
        foreach (var (extension, count) in byExtension.OrderByDescending(p => p.Value))
            Console.WriteLine($"  {count,6}  {extension}");

        Console.WriteLine();
        Console.WriteLine("Highest scoring:");

        foreach (var item in worst.OrderByDescending(w => w.Score).Take(20))
        {
            Console.WriteLine($"  {item.Score,3}/100  {item.Level,-16} {Path.GetFileName(item.Path)}");
            Console.WriteLine($"           {item.Codes}");
        }
    }
}
