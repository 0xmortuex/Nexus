using System.Text;

namespace Nexus.Core.Security.StaticAnalysis;

/// <summary>Script languages this analyzer understands well enough to comment on.</summary>
public enum ScriptKind
{
    Unknown,
    PowerShell,
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
            ".ps1" or ".psm1" or ".psd1" => ScriptKind.PowerShell,
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

        AddDefenceTamperingSignals(lower, signals);
        AddShellcodeSignals(lower, signals);
        AddObfuscationSignals(text, lower, signals);
        AddDownloadAndRunSignals(lower, signals);
        AddPersistenceSignals(lower, signals);

        return signals;
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
