namespace Nexus.Core.Security.Behavior;

/// <summary>A trusted Windows binary that is routinely abused, plus the argument
/// patterns that distinguish abuse from ordinary use.</summary>
/// <param name="Image">Image name, lowercase.</param>
/// <param name="AbusePatterns">Lowercase substrings; any match is suspicious.</param>
/// <param name="Explanation">Plain language, describing what was seen — not a verdict.</param>
/// <param name="Code">Distinguishes rules that share an image. Several binaries have
/// more than one rule at different severities, and without this they would all report
/// under the same code.</param>
public sealed record LolBinRule(
    string Image,
    IReadOnlyList<string> AbusePatterns,
    string Explanation,
    SignalWeight Weight = SignalWeight.Moderate,
    string? Code = null);

/// <summary>
/// The behavioural rule data: which system binaries get abused and how, which
/// parent/child pairs are odd, and where a system binary is supposed to live.
///
/// This is a catalogue of *observations*, deliberately not of conclusions. Every
/// entry here has a legitimate use too, which is exactly why Sentinel reports rather
/// than blocks — half of these fire on ordinary IT work, and an enforcing tool would
/// be unusable on a developer's machine.
/// </summary>
public static class BehaviorCatalog
{
    /// <summary>Signed Microsoft binaries commonly used to download or run code.</summary>
    public static readonly IReadOnlyList<LolBinRule> LolBins =
    [
        new("certutil.exe", ["-urlcache", "/urlcache", "-decode", "/decode", "-encode", "/encode"],
            "certutil.exe was used to download or decode a file, which is a common way to fetch a payload with a trusted binary",
            SignalWeight.Strong),

        new("mshta.exe", ["http://", "https://", "javascript:", "vbscript:"],
            "mshta.exe ran remote or inline script content",
            SignalWeight.Strong),

        new("regsvr32.exe", ["/i:http", "/i:https", "scrobj.dll", "-i:http"],
            "regsvr32.exe was pointed at a remote scriptlet (the \"Squiblydoo\" pattern)",
            SignalWeight.Strong),

        new("rundll32.exe", ["javascript:", "vbscript:", "url.dll,fileprotocolhandler", ".dll,#1"],
            "rundll32.exe was used to run script or an ordinal export rather than a named function",
            SignalWeight.Moderate),

        new("bitsadmin.exe", ["/transfer", "/addfile", "/setnotifycmdline"],
            "bitsadmin.exe was used to transfer a file in the background",
            SignalWeight.Moderate),

        new("msiexec.exe", ["http://", "https://"],
            "msiexec.exe was told to install a package from a URL",
            SignalWeight.Strong),

        new("wmic.exe", ["process call create", "/node:", "shadowcopy delete"],
            "wmic.exe was used to start a process, query another machine, or delete shadow copies",
            SignalWeight.Moderate),

        // PowerShell is split by severity rather than treated as one rule, because
        // lumping it together made "-NoProfile" as damning as "-EncodedCommand".
        // Every installer, build script and management tool on earth runs
        // "powershell -NoProfile -ExecutionPolicy Bypass -Command ..." — including
        // Nexus itself, to query Defender and enumerate scheduled tasks. A single
        // rule meant Nexus reported its own helper processes as strongly suspicious,
        // and reported the same about every legitimate installer on a developer's
        // machine. That is how an advisory tool teaches people to ignore it.
        new("powershell.exe", ["-enc", "-encodedcommand", "frombase64string", "downloadstring",
                               "downloadfile", "iex(", "invoke-expression"],
            "PowerShell was launched with an encoded command or told to download and run code directly",
            SignalWeight.Strong, Code: "powershell-encoded"),

        new("powershell.exe", ["-w hidden", "-windowstyle hidden"],
            "PowerShell was launched with its window hidden",
            SignalWeight.Moderate, Code: "powershell-hidden"),

        new("powershell.exe", ["-nop", "-noprofile", "bypass"],
            "PowerShell was launched skipping the user profile or the execution policy. " +
            "Installers and management scripts do this constantly, so on its own it means little",
            SignalWeight.Weak, Code: "powershell-policy"),

        new("pwsh.exe", ["-enc", "-encodedcommand", "frombase64string", "downloadstring", "downloadfile"],
            "PowerShell 7 was launched with an encoded command or told to download and run code directly",
            SignalWeight.Strong, Code: "pwsh-encoded"),

        new("pwsh.exe", ["-w hidden", "-windowstyle hidden"],
            "PowerShell 7 was launched with its window hidden",
            SignalWeight.Moderate, Code: "pwsh-hidden"),

        new("pwsh.exe", ["-nop", "-noprofile", "bypass"],
            "PowerShell 7 was launched skipping the user profile or the execution policy",
            SignalWeight.Weak, Code: "pwsh-policy"),

        new("cmd.exe", ["/v:on", "&& start", "|| start"],
            "cmd.exe was launched with an obfuscated command line",
            SignalWeight.Weak),

        new("cscript.exe", [".vbs", ".js", ".wsf", "//e:"],
            "cscript.exe ran a script file",
            SignalWeight.Weak),

        new("wscript.exe", [".vbs", ".js", ".wsf", "//e:"],
            "wscript.exe ran a script file",
            SignalWeight.Weak),

        new("curl.exe", ["-o ", "--output", "http://"],
            "curl.exe downloaded a file to disk",
            SignalWeight.Weak),

        new("schtasks.exe", ["/create", "/ru system", "/sc onlogon", "/sc onstart"],
            "schtasks.exe created a scheduled task, a common persistence step",
            SignalWeight.Moderate),

        new("reg.exe", ["\\currentversion\\run", "\\image file execution options"],
            "reg.exe wrote to a startup or debugger registry key",
            SignalWeight.Moderate),

        new("vssadmin.exe", ["delete shadows", "resize shadowstorage"],
            "vssadmin.exe deleted or shrank shadow copies — this is how ransomware prevents rollback",
            SignalWeight.Decisive),

        new("wbadmin.exe", ["delete catalog", "delete backup", "delete systemstatebackup"],
            "wbadmin.exe deleted backup data — this is how ransomware prevents recovery",
            SignalWeight.Strong),

        new("bcdedit.exe", ["recoveryenabled no", "bootstatuspolicy ignoreallfailures", "safeboot"],
            "bcdedit.exe disabled Windows recovery, which ransomware does before encrypting",
            SignalWeight.Strong),

        new("net.exe", ["user /add", "localgroup administrators"],
            "net.exe created an account or granted administrator rights",
            SignalWeight.Moderate),

        new("netsh.exe", ["firewall set", "advfirewall set", "portproxy"],
            "netsh.exe changed the firewall or set up a port proxy",
            SignalWeight.Moderate),
    ];

    /// <summary>
    /// Parents that have no business spawning a shell or script host. A document
    /// opening a command interpreter is the classic macro-malware shape.
    /// </summary>
    public static readonly IReadOnlySet<string> DocumentHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
        "onenote.exe", "visio.exe", "mspub.exe", "acrord32.exe", "acrobat.exe",
        "wordpad.exe", "eqnedt32.exe",
    };

    /// <summary>Interpreters and shells that are alarming as a document's child.</summary>
    public static readonly IReadOnlySet<string> ShellsAndInterpreters = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
        "curl.exe", "wget.exe", "msbuild.exe", "installutil.exe",
    };

    /// <summary>
    /// System images and the one directory each is supposed to live in.
    ///
    /// This is the check that closes the gap in name-based trust: a "svchost.exe" in
    /// the user's temp folder is not svchost, and matching on the name alone — the
    /// way the optimizer's never-touch list does — would hand it a free pass.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> SystemImageHomes =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["svchost.exe"] = @"C:\Windows\System32",
            ["csrss.exe"] = @"C:\Windows\System32",
            ["lsass.exe"] = @"C:\Windows\System32",
            ["services.exe"] = @"C:\Windows\System32",
            ["winlogon.exe"] = @"C:\Windows\System32",
            ["wininit.exe"] = @"C:\Windows\System32",
            ["smss.exe"] = @"C:\Windows\System32",
            ["spoolsv.exe"] = @"C:\Windows\System32",
            ["taskhostw.exe"] = @"C:\Windows\System32",
            ["dwm.exe"] = @"C:\Windows\System32",
            ["conhost.exe"] = @"C:\Windows\System32",
            ["explorer.exe"] = @"C:\Windows",
        };

    /// <summary>Directories that are normal for installers and portable tools, and
    /// also where dropped payloads land. On its own this is weak evidence.</summary>
    public static readonly IReadOnlyList<(string Segment, string Description)> UnusualExecutionLocations =
    [
        ("$Recycle.Bin", "the recycle bin"),
        ("AppData\\Local\\Temp", "the temporary files folder"),
        ("Windows\\Temp", "the Windows temp folder"),
        ("AppData\\Roaming", "the roaming AppData folder"),
        // Listed after the Temp entries so the more specific description wins.
        // Plenty of legitimate apps install here (Discord, Slack, VS Code), which is
        // why an entry from here is only weak evidence unless it is also unsigned.
        ("AppData\\Local", "the local AppData folder"),
        ("Downloads", "the Downloads folder"),
        ("Public", "the Public user folder"),
    ];
}
