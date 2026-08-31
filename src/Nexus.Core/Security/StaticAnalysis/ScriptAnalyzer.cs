using System.Text;

namespace Nexus.Core.Security.StaticAnalysis;

/// <summary>Script languages this analyzer understands well enough to comment on.</summary>
public enum ScriptKind
{
    Unknown,
    PowerShell,

    /// <summary>
    /// A .psd1 module manifest: a hashtable literal describing what a module exports,
    /// not code. It names cmdlets rather than calling them.
    /// </summary>
    PowerShellData,
    BatchOrCmd,
    VBScript,
    JavaScript,
    Html,
}

/// <summary>
/// Reads script files and reports the shapes that mean "this is trying not to be
/// read".
///
/// Scripts are where most real intrusions actually execute, and unlike a compiled
/// binary the evidence is right there in plain text — which is why the interesting
/// samples go to such lengths to stop being plain text. So the strongest signals
/// here are not "this calls a dangerous function" but "this has been deliberately
/// mangled". Legitimate administrators write awkward one-liners; they very rarely
/// base64 them, and almost never assemble them character by character.
///
/// Two categories get graded harder than obfuscation, because they have no innocent
/// reading in a script a user just downloaded:
/// - turning off or carving holes in the machine's own defences
/// - allocating executable memory and running bytes out of it
/// </summary>
public static class ScriptAnalyzer
{
    /// <summary>Beyond this, a "script" is really a data blob and line-based
    /// heuristics stop meaning anything.</summary>
    public const int MaxAnalysableBytes = 8 * 1024 * 1024;

    /// <summary>A single line longer than this is either minified or hiding something.</summary>
    public const int SuspiciousLineLength = 1000;

    public static ScriptKind KindFromExtension(string path)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();

        return extension switch
        {
            ".ps1" or ".psm1" => ScriptKind.PowerShell,
            ".psd1" => ScriptKind.PowerShellData,
            ".bat" or ".cmd" => ScriptKind.BatchOrCmd,
            ".vbs" or ".vbe" or ".wsf" => ScriptKind.VBScript,
            ".js" or ".jse" => ScriptKind.JavaScript,
            ".hta" or ".htm" or ".html" => ScriptKind.Html,
            _ => ScriptKind.Unknown,
        };
    }

    /// <summary>Analyse script text. Returns nothing for a file that is not a script.</summary>
    public static IReadOnlyList<SecuritySignal> Analyse(string text, ScriptKind kind)
    {
        if (kind == ScriptKind.Unknown || text.Length == 0)
            return [];

        var signals = new List<SecuritySignal>();
        var lower = text.ToLowerInvariant();

        // Defence tampering and shellcode mean the same thing in any language.
        AddDefenceTamperingSignals(lower, signals);
        AddShellcodeSignals(lower, signals);

        if (kind is ScriptKind.JavaScript or ScriptKind.Html)
        {
            AddWebScriptSignals(lower, signals);
            AddWebScriptObservations(text, lower, signals);
            return signals;
        }

        // A .psd1 is only given the data-file treatment if it actually looks like one.
        // The extension alone is not a guarantee of anything: `powershell -File x.psd1`
        // and dot-sourcing both run it as an ordinary script, so renaming a dropper to
        // .psd1 would otherwise have bought it a free downgrade to zero points.
        if (kind == ScriptKind.PowerShellData && LooksLikeModuleManifest(text))
        {
            AddDataFileObservations(text, lower, signals);
            return signals;
        }

        AddObfuscationSignals(text, lower, signals);
        AddDownloadAndRunSignals(lower, signals);
        AddPersistenceSignals(lower, signals);

        return signals;
    }

    /// <summary>
    /// True when the text really is a module manifest: comments, then a single
    /// hashtable literal, and nothing that evaluates while it is being read.
    ///
    /// The earlier version of this trusted the extension, and the extension proves
    /// nothing. `powershell -File payload.psd1` runs the file as an ordinary script;
    /// the restricted data-only parsing people associate with .psd1 belongs to
    /// `Import-PowerShellDataFile`, not to the name. Without this check, renaming a
    /// dropper to .psd1 dropped its score by 35 points for free.
    ///
    /// `$(...)` is refused for the same reason: a subexpression inside the hashtable
    /// still runs when the file is dot-sourced, so a file containing one is not the
    /// inert data this exemption is meant for.
    /// </summary>
    public static bool LooksLikeModuleManifest(string text)
    {
        var stripped = StripPowerShellComments(text).Trim();

        if (stripped.Length < 3 || !stripped.StartsWith("@{", StringComparison.Ordinal)
            || !stripped.EndsWith("}", StringComparison.Ordinal))
        {
            return false;
        }

        // The real difference between a manifest and a script that has been renamed is
        // where the cmdlet names sit. A manifest only ever *quotes* them, in export
        // lists: CmdletsToExport = "Invoke-Expression", "Invoke-WebRequest". A script
        // invokes them as bare commands. So the quoted strings are removed and only
        // what is left counts.
        //
        // Rejecting "@(" outright, as an earlier attempt did, broke every genuine
        // manifest: CompatiblePSEditions = @('Desktop') is an array literal and appears
        // in the one that ships with Windows.
        var code = StripQuotedStrings(stripped);

        if (code.Contains("$(", StringComparison.Ordinal) || code.Contains('&'))
            return false;

        var lower = code.ToLowerInvariant();

        return !lower.Contains("invoke-expression", StringComparison.Ordinal)
               && !ContainsWholeToken(lower, "iex")
               && !lower.Contains("invoke-webrequest", StringComparison.Ordinal)
               && !lower.Contains("invoke-restmethod", StringComparison.Ordinal)
               && !lower.Contains("downloadstring", StringComparison.Ordinal)
               && !lower.Contains("start-process", StringComparison.Ordinal)
               && !lower.Contains("new-object", StringComparison.Ordinal);
    }

    /// <summary>
    /// Blank out the contents of quoted strings, keeping the quotes so the shape of the
    /// surrounding code is unchanged.
    /// </summary>
    private static string StripQuotedStrings(string text)
    {
        var builder = new System.Text.StringBuilder(text.Length);
        char quote = '\0';

        foreach (char c in text)
        {
            if (quote == '\0')
            {
                if (c == '"' || c == '\'')
                    quote = c;

                builder.Append(c);
                continue;
            }

            if (c == quote)
            {
                quote = '\0';
                builder.Append(c);
            }

            // Everything between the quotes is dropped.
        }

        return builder.ToString();
    }

    /// <summary>Remove block and line comments so the shape check sees the code.</summary>
    private static string StripPowerShellComments(string text)
    {
        var builder = new System.Text.StringBuilder(text.Length);
        bool inBlock = false;

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine;

            while (true)
            {
                if (inBlock)
                {
                    int close = line.IndexOf("#>", StringComparison.Ordinal);
                    if (close < 0)
                    {
                        line = "";
                        break;
                    }

                    line = line[(close + 2)..];
                    inBlock = false;
                    continue;
                }

                int open = line.IndexOf("<#", StringComparison.Ordinal);
                if (open >= 0)
                {
                    var head = line[..open];
                    line = line[(open + 2)..];
                    inBlock = true;

                    builder.Append(head);
                    continue;
                }

                break;
            }

            int hash = line.IndexOf('#');
            if (hash >= 0)
                line = line[..hash];

            builder.Append(line).Append('\n');
        }

        return builder.ToString();
    }

    /// <summary>
    /// Records what the rules noticed in a PowerShell *data* file, without scoring it.
    ///
    /// A .psd1 is a module manifest: a hashtable literal that lists what a module
    /// exports. It names cmdlets, it does not call them, and PowerShell loads it in a
    /// mode that permits data and nothing else.
    ///
    /// This was found on a real machine. Microsoft.PowerShell.Utility.psd1 — which
    /// ships with Windows and sits in System32 — came out at 25/100 as "downloads
    /// something from the internet and runs it immediately", because its export list
    /// contains both Invoke-WebRequest and Invoke-Expression. The rule requires a
    /// downloader *and* an executor, which is sound for a script and useless for a
    /// manifest that names both by definition.
    ///
    /// The observations are kept and shown, because a manifest is still a file worth
    /// being able to read about. They are simply worth nothing on their own.
    /// </summary>
    private static void AddDataFileObservations(string text, string lower, List<SecuritySignal> signals)
    {
        var observations = new List<SecuritySignal>();

        AddObfuscationSignals(text, lower, observations);
        AddDownloadAndRunSignals(lower, observations);
        AddPersistenceSignals(lower, observations);

        foreach (var observation in observations)
        {
            signals.Add(observation with
            {
                Weight = SignalWeight.Informational,
                Explanation = observation.Explanation +
                    " (Noted but not counted: this is a module manifest, which lists the commands a " +
                    "module provides rather than running any of them.)",
            });
        }
    }

    /// <summary>
    /// Records what the obfuscation, download and persistence rules noticed in a web
    /// script, without letting any of it affect the score.
    ///
    /// The first attempt at this fix only exempted *minified* files, on the theory
    /// that unreadability was the problem. Measuring it against a real Next.js
    /// project proved that wrong: 1,988 files still came out as findings, and the
    /// worst offenders were not minified at all. typescript.js is a compiler — it
    /// calls String.fromCharCode on nearly every line because that is what a lexer
    /// does. So do parsers, template engines, and encoding libraries.
    ///
    /// The honest conclusion is that these rules do not discriminate in JavaScript at
    /// all, minified or not. They were written for PowerShell, where building a
    /// string out of character codes really is unusual. In a language whose entire
    /// ecosystem is compiled, bundled and generated, the same pattern is background
    /// noise, and a signal that fires on the background is not a signal.
    ///
    /// The observations are kept and shown, because a user who opens a finding should
    /// see everything Nexus noticed. They are just worth zero points, so they cannot
    /// on their own turn an ordinary file into an alert.
    /// </summary>
    private static void AddWebScriptObservations(string text, string lower, List<SecuritySignal> signals)
    {
        var observations = new List<SecuritySignal>();

        AddObfuscationSignals(text, lower, observations);
        AddDownloadAndRunSignals(lower, observations);
        AddPersistenceSignals(lower, observations);

        if (observations.Count == 0)
            return;

        if (IsMinifiedWebScript(text, ScriptKind.JavaScript))
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Informational,
                "script-minified-bundle",
                "This is minified or bundled JavaScript, so its contents are unreadable because a " +
                "build tool compressed them, not because anything is hiding."));
        }

        foreach (var observation in observations)
        {
            signals.Add(observation with
            {
                Weight = SignalWeight.Informational,
                Explanation = observation.Explanation +
                    " (Noted but not counted: this pattern is ordinary in JavaScript, which is " +
                    "generated and bundled far more often than it is hand-written.)",
            });
        }
    }

    /// <summary>
    /// True for JavaScript that a build tool produced rather than a person wrote.
    ///
    /// This check exists because of a real and embarrassing result: scanning an
    /// ordinary web project reported jQuery, Next.js and html2canvas as malicious, at
    /// 68 out of 100. Every pattern that fired is normal in minified code — bundlers
    /// inline assets as base64, minifiers emit String.fromCharCode, module loaders
    /// call eval, and every single-page app fetches and executes. The rules were
    /// written for PowerShell, where those things are genuinely unusual, and applying
    /// them to build output was simply wrong.
    ///
    /// Minification is recognised by shape, not by filename: enormous average line
    /// length is what a minifier produces and what a hand-written script does not.
    /// </summary>
    public static bool IsMinifiedWebScript(string text, ScriptKind kind)
    {
        if (kind is not (ScriptKind.JavaScript or ScriptKind.Html))
            return false;

        if (text.Length < 500)
            return false;

        int lines = 1;
        foreach (char c in text)
        {
            if (c == '\n')
                lines++;
        }

        // Minified output packs thousands of characters onto very few lines. Source a
        // human wrote and formatted averages well under a hundred.
        return text.Length / lines > 200;
    }

    /// <summary>
    /// What is actually worth reporting in a JavaScript file on Windows.
    ///
    /// Malicious .js on Windows is run by Windows Script Host, and it gives itself
    /// away with APIs that only exist there — ActiveXObject, WScript.Shell, the
    /// FileSystemObject. Web bundles never touch those, no matter how minified, so
    /// this separates the two populations far better than any obfuscation heuristic.
    /// </summary>
    private static void AddWebScriptSignals(string lower, List<SecuritySignal> signals)
    {
        // These do something: run a program, write a file, save downloaded bytes.
        // No browser has ever been able to call them, so a .js file that does is
        // meant to be run by Windows Script Host.
        (string Needle, string Explanation)[] capableApis =
        [
            ("wscript.shell", "uses the Windows shell object to run programs"),
            ("wscript.createobject", "creates Windows automation objects"),
            ("scripting.filesystemobject", "reads and writes files through Windows Script Host"),
            ("shell.application", "drives the Windows shell directly"),
            ("adodb.stream", "writes raw bytes to disk, which is how a downloaded payload is saved"),
        ];

        // These only *might* mean Windows Script Host. Both are also how web code
        // spoke to Internet Explorer, and that code is still everywhere: core-js
        // constructs an ActiveXObject("htmlfile") and every pre-2015 XHR shim asks
        // for MSXML2.XMLHTTP. On a real project these two alone accounted for every
        // remaining false positive, so on their own they are worth nothing.
        (string Needle, string Explanation)[] ambiguousApis =
        [
            ("activexobject", "refers to ActiveXObject, which is both a Windows Script Host entry point and the way older web code detected Internet Explorer"),
            ("msxml2.xmlhttp", "refers to the MSXML HTTP object, used by Windows scripts and by Internet Explorer-era web code alike"),
        ];

        var capable = capableApis
            .Where(api => lower.Contains(api.Needle, StringComparison.Ordinal))
            .ToArray();

        if (capable.Length > 0)
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Strong,
                "script-windows-script-host",
                $"This script {capable[0].Explanation}. Web pages cannot use these; a script that " +
                "does is meant to be run by Windows itself, which is how script-based malware arrives."));
            return;
        }

        var ambiguous = ambiguousApis
            .Where(api => lower.Contains(api.Needle, StringComparison.Ordinal))
            .ToArray();

        if (ambiguous.Length > 0)
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Informational,
                "script-activex-reference",
                $"This script {ambiguous[0].Explanation}. Nothing here actually runs a program or " +
                "writes a file, so it is recorded rather than counted."));
        }
    }

    /// <summary>Decode bytes as text, honouring a BOM. Scripts are commonly UTF-16 on
    /// Windows, and reading one as UTF-8 turns it into unreadable noise that every
    /// keyword check then misses.</summary>
    public static string DecodeText(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > MaxAnalysableBytes)
            bytes = bytes[..MaxAnalysableBytes];

        if (bytes.Length >= 2)
        {
            if (bytes[0] == 0xFF && bytes[1] == 0xFE)
                return Encoding.Unicode.GetString(bytes[2..]);
            if (bytes[0] == 0xFE && bytes[1] == 0xFF)
                return Encoding.BigEndianUnicode.GetString(bytes[2..]);
        }

        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
            return Encoding.UTF8.GetString(bytes[3..]);

        // No BOM: a run of interleaved zero bytes means UTF-16 anyway.
        if (bytes.Length >= 16 && LooksLikeUtf16(bytes))
            return Encoding.Unicode.GetString(bytes);

        return Encoding.UTF8.GetString(bytes);
    }

    private static bool LooksLikeUtf16(ReadOnlySpan<byte> bytes)
    {
        int zeros = 0;
        int examined = Math.Min(bytes.Length, 256);

        for (int i = 1; i < examined; i += 2)
        {
            if (bytes[i] == 0)
                zeros++;
        }

        return zeros > examined / 4;
    }

    // ---- Defence tampering ----

    private static void AddDefenceTamperingSignals(string lower, List<SecuritySignal> signals)
    {
        (string Needle, string Explanation)[] tampering =
        [
            ("add-mppreference", "adds a Microsoft Defender exclusion, which tells Defender to stop looking at a file or folder"),
            ("set-mppreference", "changes Microsoft Defender's settings"),
            ("-disablerealtimemonitoring", "turns off Defender's real-time protection"),
            ("-exclusionpath", "excludes a path from Defender scanning"),
            ("-exclusionextension", "excludes a file type from Defender scanning"),
            ("-exclusionprocess", "excludes a process from Defender scanning"),
            ("uninstall-windowsfeature windows-defender", "removes Defender entirely"),
            ("netsh advfirewall set allprofiles state off", "turns the Windows firewall off"),
            ("set-executionpolicy unrestricted", "removes PowerShell's script execution restrictions machine-wide"),
        ];

        foreach (var (needle, explanation) in tampering)
        {
            if (!lower.Contains(needle, StringComparison.Ordinal))
                continue;

            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Strong,
                "script-defence-tampering",
                $"This script {explanation}. Legitimate installers occasionally do this; malware " +
                "does it first, before anything else."));
            return; // one is enough to make the point
        }
    }

    // ---- In-memory execution ----

    private static void AddShellcodeSignals(string lower, List<SecuritySignal> signals)
    {
        string[] allocators = ["virtualalloc", "virtualprotect", "ntallocatevirtualmemory"];
        string[] runners = ["createthread", "createremotethread", "queueuserapc", "callwindowproc"];

        bool allocates = allocators.Any(a => lower.Contains(a, StringComparison.Ordinal));
        bool runs = runners.Any(r => lower.Contains(r, StringComparison.Ordinal));

        if (allocates && runs)
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Strong,
                "script-shellcode",
                "This script allocates executable memory and starts a thread in it. That is how " +
                "shellcode is run from a script, and there is no ordinary scripting reason to do it."));
        }

        if (lower.Contains("[reflection.assembly]::load", StringComparison.Ordinal)
            || lower.Contains("system.reflection.assembly]::load", StringComparison.Ordinal))
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Moderate,
                "script-reflective-load",
                "This script loads a .NET assembly straight from memory, so the code it runs never " +
                "exists as a file anything can scan."));
        }
    }

    // ---- Obfuscation ----

    private static void AddObfuscationSignals(string text, string lower, List<SecuritySignal> signals)
    {
        if (lower.Contains("frombase64string", StringComparison.Ordinal)
            || lower.Contains("-encodedcommand", StringComparison.Ordinal)
            || lower.Contains("[convert]::frombase64", StringComparison.Ordinal)
            || lower.Contains("atob(", StringComparison.Ordinal))
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Strong,
                "script-base64-payload",
                "This script decodes base64 and runs the result, so what it actually does is not " +
                "visible in the file."));
        }

        if (CountOccurrences(lower, "[char]") >= 8
            || CountOccurrences(lower, "fromcharcode") >= 2
            || CountOccurrences(lower, "chr(") >= 8)
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Strong,
                "script-charcode-assembly",
                "This script builds its own text one character code at a time. That has exactly one " +
                "purpose: to stop the file being read or matched."));
        }

        // PowerShell backtick escaping used mid-word, e.g. i`e`x
        int backticks = CountOccurrences(text, "`");
        if (backticks >= 10)
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Moderate,
                "script-escape-obfuscation",
                $"This script uses {backticks} escape characters, which is a common way to break up " +
                "keywords so they are harder to spot."));
        }

        if (lower.Contains("invoke-expression", StringComparison.Ordinal)
            || ContainsWholeToken(lower, "iex")
            || lower.Contains("eval(", StringComparison.Ordinal)
            || lower.Contains("executeglobal", StringComparison.Ordinal))
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Moderate,
                "script-runs-constructed-code",
                "This script runs text it builds while running, so the file does not show what will " +
                "actually execute."));
        }

        int longestLine = LongestLineLength(text);
        if (longestLine > SuspiciousLineLength)
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Weak,
                "script-very-long-line",
                $"This script contains a single line {longestLine:N0} characters long. Minified and " +
                "generated files look like this too, so on its own it means little."));
        }
    }

    // ---- Download and run ----

    private static void AddDownloadAndRunSignals(string lower, List<SecuritySignal> signals)
    {
        string[] downloaders =
        [
            "downloadstring", "downloadfile", "downloaddata", "invoke-webrequest", "invoke-restmethod",
            "start-bitstransfer", "msxml2.xmlhttp", "winhttp.winhttprequest", "system.net.webclient",
            "xmlhttprequest",
        ];

        var found = downloaders.FirstOrDefault(d => lower.Contains(d, StringComparison.Ordinal));
        if (found is null)
            return;

        // Downloading is ordinary. Downloading and immediately executing is not.
        bool executes = lower.Contains("invoke-expression", StringComparison.Ordinal)
                        || ContainsWholeToken(lower, "iex")
                        || lower.Contains("start-process", StringComparison.Ordinal)
                        || lower.Contains(".run(", StringComparison.Ordinal)
                        || lower.Contains("wscript.shell", StringComparison.Ordinal);

        signals.Add(new SecuritySignal(
            SignalSource.StaticRules,
            executes ? SignalWeight.Strong : SignalWeight.Weak,
            executes ? "script-download-and-run" : "script-downloads",
            executes
                ? "This script downloads something from the internet and runs it immediately, without " +
                  "it ever being saved somewhere you could inspect it."
                : "This script downloads a file. Plenty of legitimate scripts do; it is noted for context."));
    }

    // ---- Persistence ----

    private static void AddPersistenceSignals(string lower, List<SecuritySignal> signals)
    {
        (string Needle, string Explanation)[] persistence =
        [
            ("currentversion\\run", "writes to a startup registry key"),
            ("schtasks /create", "creates a scheduled task"),
            ("register-scheduledtask", "creates a scheduled task"),
            ("new-service", "installs a Windows service"),
            ("sc.exe create", "installs a Windows service"),
            ("win32_startupcommand", "adds a startup entry"),
        ];

        foreach (var (needle, explanation) in persistence)
        {
            if (!lower.Contains(needle, StringComparison.Ordinal))
                continue;

            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Moderate,
                "script-persistence",
                $"This script {explanation}, so whatever it sets up will keep running after a restart."));
            return;
        }
    }

    // ---- Helpers ----

    private static int CountOccurrences(string haystack, string needle)
    {
        int count = 0;
        int index = 0;

        while ((index = haystack.IndexOf(needle, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += needle.Length;
        }

        return count;
    }

    /// <summary>Matches a token only when it stands alone, so "iex" does not fire on
    /// words like "index" — a false positive that would land on ordinary scripts.</summary>
    private static bool ContainsWholeToken(string haystack, string token)
    {
        int index = 0;

        while ((index = haystack.IndexOf(token, index, StringComparison.Ordinal)) >= 0)
        {
            bool leftClear = index == 0 || !char.IsLetterOrDigit(haystack[index - 1]);
            int after = index + token.Length;
            bool rightClear = after >= haystack.Length || !char.IsLetterOrDigit(haystack[after]);

            if (leftClear && rightClear)
                return true;

            index = after;
        }

        return false;
    }

    private static int LongestLineLength(string text)
    {
        int longest = 0;
        int current = 0;

        foreach (char c in text)
        {
            if (c == '\n')
            {
                if (current > longest)
                    longest = current;
                current = 0;
            }
            else if (c != '\r')
            {
                current++;
            }
        }

        return Math.Max(longest, current);
    }
}
