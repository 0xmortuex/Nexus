using Nexus.Core.Security.Behavior;

namespace Nexus.Core.Security.Persistence;

/// <summary>Where something arranged to run itself again.</summary>
public enum AutorunKind
{
    RunKey,
    StartupFolder,
    ScheduledTask,
    Service,
    WmiSubscription,

    /// <summary>Image File Execution Options — a "debugger" that launches instead of
    /// the named program.</summary>
    Ifeo,

    /// <summary>Winlogon Shell / Userinit.</summary>
    WinlogonHook,

    /// <summary>AppInit_DLLs — loaded into nearly every process.</summary>
    AppInitDll,

    /// <summary>A COM CLSID pointed at a different server than it should be.</summary>
    ComHijack,
}

/// <summary>One enumerated autorun, as collected by the App layer.</summary>
public sealed record AutorunEntry
{
    public required AutorunKind Kind { get; init; }

    /// <summary>Registry key, folder, or task path it was found in.</summary>
    public required string Location { get; init; }

    public required string Name { get; init; }

    /// <summary>The full command line that will run.</summary>
    public string Command { get; init; } = "";

    /// <summary>The resolved executable, when the command could be parsed.</summary>
    public string? ImagePath { get; init; }

    /// <summary>Authenticode state of <see cref="ImagePath"/>, filled in by the App layer.</summary>
    public bool SignedByTrustedPublisher { get; init; }

    /// <summary>True when Nexus itself created this entry (its own autostart task, or
    /// an IFEO key written by the Processes tab).</summary>
    public bool CreatedByNexus { get; init; }
}

/// <summary>
/// Audits the ways a program can arrange to run again, and explains what it found.
///
/// One deliberate choice: Nexus's own persistence is reported too, marked as its own.
/// A security tool that hides its own footprint teaches the user to trust a blind
/// spot — and Nexus writes IFEO keys and an elevated scheduled task, which are
/// exactly the entries a user should be able to see and recognise.
/// </summary>
public static class AutorunAudit
{
    /// <summary>The only values Winlogon's Shell and Userinit should hold.</summary>
    private static readonly IReadOnlyDictionary<string, string> ExpectedWinlogonValues =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Shell"] = "explorer.exe",
            ["Userinit"] = @"C:\Windows\system32\userinit.exe,",
        };

    public static IReadOnlyList<SecuritySignal> Evaluate(AutorunEntry entry)
    {
        var signals = new List<SecuritySignal>();

        if (entry.CreatedByNexus)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Informational,
                "run-nexus-own",
                $"{entry.Name} was created by Nexus itself. It is listed here so its footprint " +
                "is visible rather than hidden."));
            return signals;
        }

        AddKindSignals(entry, signals);
        AddCommandSignals(entry, signals);
        AddLocationSignals(entry, signals);

        return signals;
    }

    private static void AddKindSignals(AutorunEntry entry, List<SecuritySignal> signals)
    {
        switch (entry.Kind)
        {
            case AutorunKind.Ifeo:
                signals.Add(new SecuritySignal(
                    SignalSource.Persistence,
                    SignalWeight.Strong,
                    "run-ifeo-debugger",
                    $"A debugger is registered for {entry.Name}, so {entry.Command} runs instead " +
                    "of it. This is a legitimate debugging feature and a common hijack."));
                break;

            case AutorunKind.WmiSubscription:
                signals.Add(new SecuritySignal(
                    SignalSource.Persistence,
                    SignalWeight.Strong,
                    "run-wmi-subscription",
                    $"A permanent WMI event subscription ({entry.Name}) runs code on a trigger. " +
                    "Management suites use these; so does fileless malware, because they survive " +
                    "reboots without a file on disk."));
                break;

            case AutorunKind.AppInitDll:
                signals.Add(new SecuritySignal(
                    SignalSource.Persistence,
                    SignalWeight.Strong,
                    "run-appinit-dll",
                    $"AppInit_DLLs is set to {entry.Command}. Every GUI program on the machine " +
                    "loads that library."));
                break;

            case AutorunKind.WinlogonHook:
                bool expected = ExpectedWinlogonValues.TryGetValue(entry.Name, out var value)
                                && entry.Command.Trim().Equals(value, StringComparison.OrdinalIgnoreCase);
                if (!expected)
                {
                    signals.Add(new SecuritySignal(
                        SignalSource.Persistence,
                        SignalWeight.Strong,
                        "run-winlogon-hook",
                        $"Winlogon's {entry.Name} is set to {entry.Command} rather than the Windows " +
                        "default. This runs at every sign-in, before anything else."));
                }
                break;

            case AutorunKind.ComHijack:
                signals.Add(new SecuritySignal(
                    SignalSource.Persistence,
                    SignalWeight.Moderate,
                    "run-com-hijack",
                    $"A per-user COM registration overrides {entry.Name} for this account only, " +
                    "which is a quiet way to get loaded by another program."));
                break;
        }
    }

    private static void AddCommandSignals(AutorunEntry entry, List<SecuritySignal> signals)
    {
        var command = entry.Command.ToLowerInvariant();

        string[] scriptedLaunch =
            ["powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "certutil", "curl"];

        foreach (var interpreter in scriptedLaunch)
        {
            if (!command.Contains(interpreter, StringComparison.Ordinal))
                continue;

            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Moderate,
                "run-scripted-launch",
                $"{entry.Name} starts through {interpreter} rather than running a program directly. " +
                "Ordinary applications rarely need to."));
            break;
        }

        if (BehaviorEngine.LooksBase64Encoded(entry.Command, out int blobLength))
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Strong,
                "run-encoded-command",
                $"{entry.Name} runs a {blobLength}-character encoded command at startup, which " +
                "hides what it actually does."));
        }
    }

    private static void AddLocationSignals(AutorunEntry entry, List<SecuritySignal> signals)
    {
        if (entry.ImagePath is not { Length: > 0 } imagePath)
            return;

        bool inUserWritableLocation = BehaviorCatalog.UnusualExecutionLocations
            .Any(location => PathHelpers.ContainsSegment(imagePath, location.Segment));

        if (inUserWritableLocation && !entry.SignedByTrustedPublisher)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Strong,
                "run-unsigned-from-user-folder",
                $"{entry.Name} starts {PathHelpers.FileName(imagePath)} from a folder any program " +
                "can write to, and it carries no trusted signature."));
        }
        else if (inUserWritableLocation)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Weak,
                "run-from-user-folder",
                $"{entry.Name} starts from a user folder rather than Program Files, though it is " +
                "signed by a publisher this machine trusts."));
        }
        else if (!entry.SignedByTrustedPublisher && entry.Kind == AutorunKind.Service)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Moderate,
                "run-unsigned-service",
                $"The {entry.Name} service runs unsigned code with system privileges."));
        }

        if (BehaviorEngine.HasDeceptiveDoubleExtension(PathHelpers.FileName(imagePath), out var pretend))
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Strong,
                "run-double-extension",
                $"{entry.Name} starts a program named to look like a {pretend} document."));
        }
    }
}
