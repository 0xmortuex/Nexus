namespace Nexus.Core.Security.Behavior;

/// <summary>What the behavioural engine noticed about one process launch.</summary>
public sealed record BehaviorFinding
{
    public required ScanTarget Target { get; init; }
    public required IReadOnlyList<SecuritySignal> Signals { get; init; }
    public required ProcessStartEvent Trigger { get; init; }

    /// <summary>The strongest weight present, for sorting an alert list.</summary>
    public SignalWeight Severity => Signals.Count == 0
        ? SignalWeight.Informational
        : Signals.Max(s => s.Weight);
}

/// <summary>
/// Watches process launches and reports the ones whose shape is worth a human look.
///
/// Pure and synchronous by design: it takes events in, returns findings out, and
/// touches nothing. The ETW plumbing that feeds it lives in the App layer, which
/// keeps every rule here unit-testable on any OS.
///
/// It remembers a bounded amount of process ancestry so it can answer "what launched
/// this?" even when the parent has already exited — the interesting case, since
/// droppers usually do.
/// </summary>
public sealed class BehaviorEngine
{
    /// <summary>Ancestry beyond this many live processes is dropped oldest-first.
    /// A machine under a fork bomb must not also run Sentinel out of memory.</summary>
    public const int MaxTrackedProcesses = 4096;

    private sealed record TrackedProcess(int Pid, int ParentPid, string ImagePath, DateTimeOffset StartedAt);

    private readonly Dictionary<int, TrackedProcess> _live = new();
    private readonly Queue<int> _insertionOrder = new();
    private readonly object _gate = new();
    private readonly string _selfImageName;

    /// <param name="selfImageName">Nexus's own executable name. Helper processes it
    /// launches are still reported, but marked as its own rather than accused —
    /// Nexus runs schtasks to create its autostart task and PowerShell to query
    /// Defender, and both match rules here. Without this, switching on "start with
    /// Windows" made Nexus raise a security alert about itself.</param>
    public BehaviorEngine(string selfImageName = "Nexus.exe")
    {
        _selfImageName = selfImageName;
    }

    /// <summary>Record a launch and report anything notable about it.</summary>
    public BehaviorFinding? Observe(ProcessStartEvent evt)
    {
        Track(evt);

        var signals = new List<SecuritySignal>();

        AddMasqueradeSignal(evt, signals);
        AddLolBinSignals(evt, signals);
        AddParentChildSignals(evt, signals);
        AddLocationSignal(evt, signals);
        AddCommandLineSignals(evt, signals);
        AddFileNameSignals(evt, signals);

        if (signals.Count == 0)
            return null;

        // Nexus's own helper processes are reported, not hidden — the same choice the
        // startup audit makes about Nexus's own registry keys. A security tool that
        // quietly exempts itself teaches the user to trust a blind spot. But they are
        // marked rather than accused, and carry no score.
        if (IsOwnHelper(evt))
        {
            signals =
            [
                new SecuritySignal(
                    SignalSource.Behavior,
                    SignalWeight.Informational,
                    "beh-nexus-own-helper",
                    $"{evt.ImageName} was started by Nexus itself. It is listed here so Nexus's own " +
                    "footprint is visible rather than hidden."),
            ];
        }

        return new BehaviorFinding
        {
            Target = ScanTarget.ForProcess(evt.Pid, evt.ImagePath),
            Signals = signals,
            Trigger = evt,
        };
    }

    /// <summary>True when Nexus launched this process itself.</summary>
    private bool IsOwnHelper(ProcessStartEvent evt) =>
        evt.ParentImageName.Length > 0
        && string.Equals(evt.ParentImageName, _selfImageName, StringComparison.OrdinalIgnoreCase);

    /// <summary>Drop a process from the ancestry map when it exits.</summary>
    public void Forget(int pid)
    {
        lock (_gate)
        {
            _live.Remove(pid);
        }
    }

    /// <summary>The chain of images from this process up to the root, nearest first.
    /// Useful for explaining a finding ("Word → cmd → powershell").</summary>
    public IReadOnlyList<string> AncestryOf(int pid)
    {
        lock (_gate)
        {
            var chain = new List<string>();
            var seen = new HashSet<int>();
            int current = pid;

            // PID reuse can in principle form a cycle; `seen` makes that terminate.
            while (_live.TryGetValue(current, out var tracked) && seen.Add(current))
            {
                chain.Add(PathHelpers.FileName(tracked.ImagePath));
                current = tracked.ParentPid;
                if (current <= 0)
                    break;
            }

            return chain;
        }
    }

    private void Track(ProcessStartEvent evt)
    {
        lock (_gate)
        {
            _live[evt.Pid] = new TrackedProcess(evt.Pid, evt.ParentPid, evt.ImagePath, evt.At);
            _insertionOrder.Enqueue(evt.Pid);

            while (_insertionOrder.Count > MaxTrackedProcesses)
            {
                int oldest = _insertionOrder.Dequeue();
                // Only evict if it is still the same generation we queued.
                if (_live.TryGetValue(oldest, out var tracked) && tracked.Pid == oldest)
                    _live.Remove(oldest);
            }
        }
    }

    /// <summary>A system binary running from the wrong directory is not that binary.</summary>
    private static void AddMasqueradeSignal(ProcessStartEvent evt, List<SecuritySignal> signals)
    {
        if (!BehaviorCatalog.SystemImageHomes.TryGetValue(evt.ImageName, out var expectedHome))
            return;

        // Nexus cannot always learn a process's image path. Protected processes and
        // anything at a higher integrity level refuse to give it up, and ETW does not
        // carry one at all. "We do not know" must never be reported as "not in
        // System32": that turns a permission failure, or simply a different event
        // source, into Strong evidence of malware.
        //
        // This caught conhost.exe twice. First with an empty path from WMI, then again
        // through ETW, where the bare file name arrived where a path was expected and
        // sailed past a check that only looked for emptiness. A bare name is not a
        // path, and the message printed a blank directory both times because there
        // was never a directory to print.
        if (!PathHelpers.IsRooted(evt.ImagePath))
            return;

        // SysWOW64 is the legitimate 32-bit twin of System32.
        bool atHome = PathHelpers.IsUnder(evt.ImagePath, expectedHome)
                      || (expectedHome.EndsWith("System32", StringComparison.OrdinalIgnoreCase)
                          && PathHelpers.IsUnder(evt.ImagePath, @"C:\Windows\SysWOW64"));

        if (atHome)
            return;

        signals.Add(new SecuritySignal(
            SignalSource.Behavior,
            SignalWeight.Strong,
            "beh-masquerade",
            $"{evt.ImageName} is a Windows system program, but this copy ran from " +
            $"{PathHelpers.DirectoryOf(evt.ImagePath)} instead of {expectedHome}. " +
            "Malware often takes a system program's name to look legitimate."));
    }

    private static void AddLolBinSignals(ProcessStartEvent evt, List<SecuritySignal> signals)
    {
        var commandLine = evt.CommandLine.ToLowerInvariant();

        foreach (var rule in BehaviorCatalog.LolBins)
        {
            if (!string.Equals(rule.Image, evt.ImageName, StringComparison.OrdinalIgnoreCase))
                continue;

            var matched = rule.AbusePatterns
                .Where(pattern => commandLine.Contains(pattern, StringComparison.Ordinal))
                .ToArray();

            bool fires = rule.RequireAll
                ? matched.Length == rule.AbusePatterns.Count
                : matched.Length > 0;

            if (!fires)
                continue;

            signals.Add(new SecuritySignal(
                SignalSource.Behavior,
                rule.Weight,
                "beh-lolbin-" + (rule.Code ?? rule.Image.Replace(".exe", "", StringComparison.OrdinalIgnoreCase)),
                rule.Explanation + $" (matched: {string.Join(", ", matched)})"));
        }
    }

    private static void AddParentChildSignals(ProcessStartEvent evt, List<SecuritySignal> signals)
    {
        if (evt.ParentImageName.Length == 0)
            return;

        if (BehaviorCatalog.DocumentHosts.Contains(evt.ParentImageName)
            && BehaviorCatalog.ShellsAndInterpreters.Contains(evt.ImageName))
        {
            signals.Add(new SecuritySignal(
                SignalSource.Behavior,
                SignalWeight.Strong,
                "beh-document-spawned-shell",
                $"{evt.ParentImageName} started {evt.ImageName}. Documents do not normally " +
                "launch command interpreters; this is how macro-based attacks begin."));
        }
    }

    private static void AddLocationSignal(ProcessStartEvent evt, List<SecuritySignal> signals)
    {
        foreach (var (segment, description) in BehaviorCatalog.UnusualExecutionLocations)
        {
            if (!PathHelpers.ContainsSegment(evt.ImagePath, segment))
                continue;

            signals.Add(new SecuritySignal(
                SignalSource.Behavior,
                SignalWeight.Weak,
                "beh-unusual-location",
                $"{evt.ImageName} ran from {description}. Installers and portable tools do " +
                "this legitimately, so on its own it means little."));
            return; // one location signal is enough
        }
    }

    private static void AddCommandLineSignals(ProcessStartEvent evt, List<SecuritySignal> signals)
    {
        if (evt.CommandLine.Length == 0)
            return;

        if (LooksBase64Encoded(evt.CommandLine, out int blobLength))
        {
            signals.Add(new SecuritySignal(
                SignalSource.Behavior,
                SignalWeight.Moderate,
                "beh-encoded-commandline",
                $"{evt.ImageName} was started with a {blobLength}-character encoded blob on its " +
                "command line, which hides what it was actually told to do."));
        }

        // 2000 was far too low. The Windows limit is 32767 and build tools live near
        // it: compilers with long include lists, linkers, node, java, msbuild. On a
        // real machine this fired on an ordinary 3762-character shell invocation.
        if (evt.CommandLine.Length > 8000)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Behavior,
                SignalWeight.Weak,
                "beh-huge-commandline",
                $"{evt.ImageName} was started with an unusually long command line " +
                $"({evt.CommandLine.Length} characters), which is often obfuscation."));
        }
    }

    private static void AddFileNameSignals(ProcessStartEvent evt, List<SecuritySignal> signals)
    {
        if (HasDeceptiveDoubleExtension(evt.ImageName, out var pretendExtension))
        {
            signals.Add(new SecuritySignal(
                SignalSource.Behavior,
                SignalWeight.Strong,
                "beh-double-extension",
                $"{evt.ImageName} is a program named to look like a {pretendExtension} document. " +
                "This is a deliberate attempt to be double-clicked by mistake."));
        }

        if (evt.ImageName.Any(char.IsControl)
            || evt.ImageName.Contains('\u202E')) // right-to-left override
        {
            signals.Add(new SecuritySignal(
                SignalSource.Behavior,
                SignalWeight.Strong,
                "beh-name-trickery",
                $"The file name of {evt.Pid} contains invisible characters used to disguise " +
                "the real extension."));
        }
    }

    /// <summary>
    /// True when the command line carries a long run of base64. Deliberately
    /// conservative: short base64-looking tokens appear in ordinary paths and GUIDs.
    /// </summary>
    public static bool LooksBase64Encoded(string commandLine, out int blobLength)
    {
        // 40 characters of [A-Za-z0-9] is not rare: a git commit hash is exactly 40,
        // and content-addressed asset names are the same shape. Requiring a longer run
        // *and* a genuine mix of character classes separates encoded payloads from
        // hashes and identifiers, because base64 of UTF-16LE text always carries upper,
        // lower and digits, while hashes are lowercase hex and identifiers have no
        // digits at all.
        const int minimumBlob = 50;

        int longest = 0;
        int run = 0;
        bool upper = false, lower = false, other = false;

        void EndRun()
        {
            if (run >= minimumBlob && upper && lower && other && run > longest)
                longest = run;

            run = 0;
            upper = lower = other = false;
        }

        foreach (char c in commandLine)
        {
            bool isBase64Char = char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=';
            if (isBase64Char)
            {
                run++;
                if (char.IsAsciiLetterUpper(c)) upper = true;
                else if (char.IsAsciiLetterLower(c)) lower = true;
                else other = true;
            }
            else
            {
                EndRun();
            }
        }

        EndRun(); // a blob that runs to the end of the command line still counts

        blobLength = longest;
        return longest > 0;
    }

    /// <summary>Detects "invoice.pdf.exe" — a document extension followed by an
    /// executable one.</summary>
    public static bool HasDeceptiveDoubleExtension(string fileName, out string pretendExtension)
    {
        pretendExtension = "";

        string[] documentExtensions =
            [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".zip", ".rar"];
        string[] executableExtensions =
            [".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".vbs", ".hta", ".lnk"];

        var lower = fileName.ToLowerInvariant();

        foreach (var executable in executableExtensions)
        {
            if (!lower.EndsWith(executable, StringComparison.Ordinal))
                continue;

            var stem = lower[..^executable.Length];
            foreach (var document in documentExtensions)
            {
                if (!stem.EndsWith(document, StringComparison.Ordinal))
                    continue;

                pretendExtension = document;
                return true;
            }
        }

        return false;
    }
}
