using Nexus.Core.Persistence;
using Nexus.Core.Security;
using Nexus.Core.Security.StaticAnalysis;

namespace Nexus.Scanner.Engines;

/// <summary>
/// Literal byte-pattern signatures loaded from assets/patterns.txt.
///
/// Available whenever a pattern file is present — no native dependency, no model,
/// no download. This is the engine that makes signature detection work out of the
/// box; YARA, when present, runs alongside it rather than replacing it.
/// </summary>
public sealed class PatternSignatureEngine : IStaticEngine
{
    private readonly PatternEngine? _engine;

    private PatternSignatureEngine(PatternEngine? engine)
    {
        _engine = engine;
    }

    public string Name => "byte patterns";

    public SignalSource SignalSource => SignalSource.StaticRules;

    public bool IsAvailable => _engine is { HasPatterns: true };

    public static PatternSignatureEngine Create()
    {
        var path = Path.Combine(NexusPaths.AssetsDirectory, "patterns.txt");
        if (!File.Exists(path))
            return new PatternSignatureEngine(null);

        try
        {
            var patterns = PatternEngine.ParseRules(File.ReadLines(path), out var errors);

            foreach (var error in errors)
                Console.Error.WriteLine($"patterns.txt: {error}");

            return new PatternSignatureEngine(new PatternEngine(patterns));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"could not read patterns.txt: {ex.Message}");
            return new PatternSignatureEngine(null);
        }
    }

    public IReadOnlyList<SecuritySignal> Analyse(ReadOnlySpan<byte> bytes, string path) =>
        _engine?.Scan(bytes) ?? [];
}

/// <summary>
/// YARA rule matching via YARA-X, active whenever the native library and a rule file
/// are both present beside the executable.
///
/// YARA is what a byte-pattern engine cannot be: conditions over PE structure, string
/// sets, wildcards, regular expressions, file-size guards. Nexus's own
/// <c>PatternEngine</c> does only literal bytes and says so; this is the step up.
///
/// It is optional rather than bundled because both pieces carry decisions that are
/// not Nexus's to make. The engine is BSD-3 but the DLL is ~21 MB, a third of the
/// whole download; rule sets range from MIT to GPL, and bundling a GPL set would
/// constrain how Nexus itself may be redistributed. Both are documented in
/// docs/sentinel.md.
///
/// One thing worth stating plainly: because Sentinel reports rather than blocks, it
/// can afford broader and noisier rule sets than an enforcing product could. A false
/// positive here costs a line in a report, not a deleted file.
///
/// An unavailable engine is excluded from the "engines consulted" count, so its
/// absence makes files come back "unknown" rather than falsely "clean".
/// </summary>
public sealed class YaraEngine : IStaticEngine, IDisposable
{
    /// <summary>Per-file scan ceiling. A pathological rule against a pathological file
    /// can run a long time, and this engine sits inside a scan whose host kills the
    /// worker after ten seconds.</summary>
    private const ulong ScanTimeoutSeconds = 5;

    /// <summary>Rules reported per file. A file that trips fifty has said everything
    /// it is going to.</summary>
    private const int MaxMatchesPerFile = 20;

    private readonly IntPtr _rules;

    // Held as a field so the GC cannot collect the delegate while native code still
    // holds the function pointer. That failure mode is rare and unreproducible, which
    // is considerably worse than a frequent one.
    private readonly YaraNative.RuleCallback _callback;

    private readonly List<string> _matches = [];
    private bool _disposed;

    private YaraEngine(IntPtr rules, int ruleFileCount)
    {
        _rules = rules;
        RuleFileCount = ruleFileCount;
        _callback = OnMatchingRule;
    }

    public string Name => "YARA";

    public SignalSource SignalSource => SignalSource.StaticRules;

    public bool IsAvailable => _rules != IntPtr.Zero && !_disposed;

    /// <summary>Rule files compiled into this engine.</summary>
    public int RuleFileCount { get; }

    /// <summary>Any .yar/.yara file under assets/yara beside the executable.</summary>
    public static string RulesDirectory => NexusPaths.YaraRulesDirectory;

    /// <summary>
    /// Compile whatever rules are present. Always returns an engine — never null, never
    /// throwing — because a missing library, an empty folder or rules that do not
    /// compile must not stop the other engines running.
    /// </summary>
    public static YaraEngine Create()
    {
        var inert = new YaraEngine(IntPtr.Zero, 0);

        if (!YaraNative.IsPresent() || !Directory.Exists(RulesDirectory))
            return inert;

        string[] files;
        try
        {
            files =
            [
                .. Directory.GetFiles(RulesDirectory, "*.yar", SearchOption.AllDirectories),
                .. Directory.GetFiles(RulesDirectory, "*.yara", SearchOption.AllDirectories),
            ];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"yara: could not read {RulesDirectory}: {ex.Message}");
            return inert;
        }

        if (files.Length == 0)
            return inert;

        var source = new System.Text.StringBuilder();
        foreach (var file in files)
        {
            try
            {
                source.AppendLine(File.ReadAllText(file));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"yara: skipped {Path.GetFileName(file)}: {ex.Message}");
            }
        }

        try
        {
            var result = YaraNative.yrx_compile(source.ToString(), out var rules);

            if (result != YaraNative.YrxResult.Success || rules == IntPtr.Zero)
            {
                // A rule-set problem, not a Nexus problem — but it has to be visible
                // rather than silently leaving the engine switched off.
                Console.Error.WriteLine($"yara: rules did not compile ({result}): {YaraNative.LastError()}");
                return inert;
            }

            return new YaraEngine(rules, files.Length);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException
                                       or BadImageFormatException)
        {
            return inert;
        }
    }

    public IReadOnlyList<SecuritySignal> Analyse(ReadOnlySpan<byte> bytes, string path)
    {
        if (!IsAvailable || bytes.Length == 0)
            return [];

        var data = bytes.ToArray();

        lock (_matches)
        {
            _matches.Clear();
            IntPtr scanner = IntPtr.Zero;

            try
            {
                if (YaraNative.yrx_scanner_create(_rules, out scanner) != YaraNative.YrxResult.Success)
                    return [];

                YaraNative.yrx_scanner_set_timeout(scanner, ScanTimeoutSeconds);
                YaraNative.yrx_scanner_on_matching_rule(scanner, _callback, IntPtr.Zero);

                var result = YaraNative.yrx_scanner_scan(scanner, data, (nuint)data.Length);

                if (result == YaraNative.YrxResult.ScanTimeout)
                {
                    return
                    [
                        new SecuritySignal(SignalSource.StaticRules, SignalWeight.Informational,
                            "yara-timeout",
                            "The YARA rules took too long on this file and were stopped, so their part " +
                            "of the check did not finish."),
                    ];
                }

                if (result != YaraNative.YrxResult.Success)
                    return [];
            }
            finally
            {
                // Always before the rules object, per the C API's contract.
                if (scanner != IntPtr.Zero)
                    YaraNative.yrx_scanner_destroy(scanner);
            }

            return _matches
                .Take(MaxMatchesPerFile)
                .Select(rule => new SecuritySignal(
                    SignalSource.StaticRules,
                    // Moderate, not Strong. A YARA hit is one opinion from one source,
                    // rule quality varies enormously between collections, and the
                    // fusion engine's per-source cap already stops a noisy rule set
                    // condemning a file alone. This weighting assumes nothing about
                    // whose rules are loaded.
                    SignalWeight.Moderate,
                    "yara-" + rule,
                    $"Matched the YARA rule {rule}."))
                .ToArray();
        }
    }

    private void OnMatchingRule(IntPtr rule, IntPtr userData)
    {
        // Runs on the native call stack. Letting anything escape unwinds through Rust,
        // which is undefined behaviour rather than an exception.
        try
        {
            if (_matches.Count < MaxMatchesPerFile)
                _matches.Add(YaraNative.RuleIdentifier(rule));
        }
        catch
        {
            // Deliberately swallowed: losing one rule name is not worth the process.
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        if (_rules != IntPtr.Zero)
            YaraNative.yrx_rules_destroy(_rules);
    }
}
