using System.Diagnostics;
using Nexus.App.Interop.Security;
using Nexus.Core.Logging;
using Nexus.Core.Security;
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

        var sources = target == "--running" ? RunningImages() : FilesUnder(target);

        int scanned = 0;
        int alerts = 0;
        var byExtension = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var worst = new List<(int Score, ThreatLevel Level, string Path, string Codes)>();

        foreach (var path in sources)
        {
            if (!Interesting.Contains(Path.GetExtension(path)))
                continue;

            long size;
            try
            {
                size = new FileInfo(path).Length;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            if (size == 0 || size > MaxBytes)
                continue;

            var verdict = Judge(verifier, path, size);
            if (verdict is null)
                continue;

            scanned++;

            if (!verdict.WarrantsAlert)
                continue;

            alerts++;
            var extension = Path.GetExtension(path);
            byExtension[extension] = byExtension.GetValueOrDefault(extension) + 1;

            worst.Add((verdict.Score, verdict.Level, path,
                string.Join(",", verdict.Signals.Where(s => !s.Exonerating).Select(s => s.Code).Distinct())));
        }

        Report(target, scanned, alerts, byExtension, worst);

        // Non-zero when anything was flagged, so this can gate a release if wanted.
        return alerts == 0 ? 0 : 1;
    }

    /// <summary>
    /// The host-side pipeline: signature, then PE or script analysis, fused exactly as
    /// SentinelService fuses them.
    ///
    /// YARA and hash reputation are left out because both depend on data the user
    /// supplies. Their absence makes this sweep *more* pessimistic than the product,
    /// never less: reputation only ever exonerates.
    /// </summary>
    private static Verdict? Judge(AuthenticodeVerifier verifier, string path, long size)
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
