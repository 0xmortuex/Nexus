namespace Nexus.Core.Security.StaticAnalysis;

/// <summary>
/// Static heuristics over a parsed PE file.
///
/// These describe structure, not intent. Packing is not malware — plenty of
/// commercial software is packed, and so is most of what ships with a licence
/// manager — so the weights here stay low and lean on the fusion engine's
/// corroboration rule rather than trying to be conclusive alone.
/// </summary>
public static class PeHeuristics
{
    /// <summary>Above this, a section's contents are compressed, encrypted, or both.</summary>
    public const double PackedEntropyThreshold = 7.2;

    /// <summary>Import combinations that describe a capability rather than a program.</summary>
    private static readonly (string Label, string[] Functions, SignalWeight Weight, string Explanation)[] CapabilityGroups =
    [
        ("process injection",
            ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            SignalWeight.Strong,
            "imports the exact set of functions used to write code into another running program and start it"),

        ("process hollowing",
            ["NtUnmapViewOfSection", "SetThreadContext", "ResumeThread"],
            SignalWeight.Strong,
            "imports the functions used to replace a running program's memory with different code"),

        ("keylogging",
            ["SetWindowsHookEx", "GetAsyncKeyState"],
            SignalWeight.Moderate,
            "imports functions that let it record keystrokes across the whole desktop"),

        ("anti-analysis",
            ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
            SignalWeight.Weak,
            "checks whether it is being debugged, which software does to protect itself and malware does to hide"),

        ("dynamic API resolution",
            ["LoadLibraryA", "GetProcAddress"],
            SignalWeight.Informational,
            "resolves the functions it calls at runtime, so its import table understates what it does"),

        ("credential access",
            ["CredEnumerateW", "CryptUnprotectData"],
            SignalWeight.Moderate,
            "imports functions that read stored Windows credentials"),

        ("service installation",
            ["CreateServiceW", "OpenSCManagerW"],
            SignalWeight.Weak,
            "can install a Windows service, which is how software both installs itself and persists"),
    ];

    public static IReadOnlyList<SecuritySignal> Evaluate(PeImage image)
    {
        var signals = new List<SecuritySignal>();

        AddPackingSignals(image, signals);
        AddSectionSignals(image, signals);
        AddImportSignals(image, signals);
        AddMitigationSignals(image, signals);
        AddOverlaySignal(image, signals);

        return signals;
    }

    private static void AddPackingSignals(PeImage image, List<SecuritySignal> signals)
    {
        var packed = image.Sections
            .Where(s => s.RawSize > 0 && s.Entropy >= PackedEntropyThreshold)
            .ToArray();

        if (packed.Length == 0)
            return;

        // A packed *code* section is the interesting case; a packed resource section
        // is usually just an embedded PNG or an installer payload.
        bool codeIsPacked = packed.Any(s => s.IsExecutable);

        signals.Add(new SecuritySignal(
            SignalSource.StaticRules,
            codeIsPacked ? SignalWeight.Moderate : SignalWeight.Weak,
            codeIsPacked ? "pe-packed-code" : "pe-high-entropy-data",
            codeIsPacked
                ? $"The program's code section ({packed.First(s => s.IsExecutable).Name}) is compressed or " +
                  "encrypted, so its real instructions only appear once it is running. Commercial " +
                  "protectors do this as well as malware."
                : $"{packed.Length} section(s) contain compressed or encrypted data. This is normal for " +
                  "installers and programs with embedded media."));
    }

    private static void AddSectionSignals(PeImage image, List<SecuritySignal> signals)
    {
        foreach (var section in image.Sections)
        {
            if (section.IsExecutable && section.IsWritable)
            {
                signals.Add(new SecuritySignal(
                    SignalSource.StaticRules,
                    SignalWeight.Moderate,
                    "pe-writable-code",
                    $"Section {section.Name} is both writable and executable, which lets the program " +
                    "rewrite its own instructions while running. Modern compilers do not produce this."));
                break;
            }
        }

        // A section whose virtual size dwarfs its file size unpacks itself into memory.
        foreach (var section in image.Sections)
        {
            if (section.RawSize == 0 && section.VirtualSize > 0x1000 && section.IsExecutable)
            {
                signals.Add(new SecuritySignal(
                    SignalSource.StaticRules,
                    SignalWeight.Moderate,
                    "pe-empty-code-section",
                    $"Section {section.Name} takes up space in memory but holds nothing in the file, " +
                    "so its contents are produced at runtime."));
                break;
            }
        }

        // Entry point outside every section is a loader trick.
        bool entryPointMapped = image.EntryPointRva == 0 || image.Sections.Any(s =>
            image.EntryPointRva >= s.VirtualAddress &&
            image.EntryPointRva < s.VirtualAddress + Math.Max(s.VirtualSize, s.RawSize));

        if (!entryPointMapped)
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Strong,
                "pe-entrypoint-outside-sections",
                "The program's starting address does not fall inside any of its own sections. " +
                "This is a deliberate malformation, not something a compiler produces."));
        }

        var suspiciousNames = image.Sections
            .Where(s => IsKnownPackerSection(s.Name))
            .Select(s => s.Name)
            .ToArray();

        if (suspiciousNames.Length > 0)
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Weak,
                "pe-packer-section-name",
                $"Section names ({string.Join(", ", suspiciousNames)}) match a known executable packer."));
        }
    }

    private static bool IsKnownPackerSection(string name) =>
        name is "UPX0" or "UPX1" or "UPX2" or ".aspack" or ".adata" or "ASPack"
             or ".themida" or ".vmp0" or ".vmp1" or ".vmp2" or "MPRESS1" or "MPRESS2"
             or ".petite" or ".nsp0" or ".nsp1" or "Themida" or ".enigma1" or ".enigma2";

    private static void AddImportSignals(PeImage image, List<SecuritySignal> signals)
    {
        // A managed assembly imports one stub function; counting its imports says nothing.
        if (image.IsManaged)
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Informational,
                "pe-managed",
                "This is a .NET program. Its behaviour lives in bytecode rather than in the import table."));
            return;
        }

        var imported = new HashSet<string>(image.ImportedFunctions, StringComparer.OrdinalIgnoreCase);

        foreach (var (label, functions, weight, explanation) in CapabilityGroups)
        {
            if (!functions.All(imported.Contains))
                continue;

            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                weight,
                "pe-capability-" + label.Replace(' ', '-'),
                $"This program {explanation}."));
        }

        // Almost no imports plus a packed section is the classic packed-stub shape.
        if (image.ImportedFunctions.Count is > 0 and < 10
            && image.Sections.Any(s => s.IsExecutable && s.Entropy >= PackedEntropyThreshold))
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Moderate,
                "pe-minimal-imports",
                $"The program declares only {image.ImportedFunctions.Count} imported functions and its " +
                "code is compressed, so almost everything it does is hidden until it runs."));
        }
    }

    private static void AddMitigationSignals(PeImage image, List<SecuritySignal> signals)
    {
        if (image.IsManaged)
            return;

        var missing = new List<string>();
        if (!image.HasDynamicBase)
            missing.Add("address randomisation");
        if (!image.HasNxCompat)
            missing.Add("data-execution prevention");

        if (missing.Count == 2)
        {
            signals.Add(new SecuritySignal(
                SignalSource.StaticRules,
                SignalWeight.Informational,
                "pe-no-mitigations",
                $"Built without {string.Join(" or ", missing)}. That makes the program itself easier to " +
                "exploit; it says nothing about whether it is malicious."));
        }
    }

    private static void AddOverlaySignal(PeImage image, List<SecuritySignal> signals)
    {
        if (image.OverlayBytes <= 0 || image.FileSize <= 0)
            return;

        double fraction = (double)image.OverlayBytes / image.FileSize;
        if (fraction < 0.25)
            return;

        signals.Add(new SecuritySignal(
            SignalSource.StaticRules,
            SignalWeight.Informational,
            "pe-large-overlay",
            $"{fraction:P0} of this file sits after the program itself. Installers and " +
            "self-extracting archives are built exactly this way."));
    }

    // AddTimestampSignal was removed rather than reweighted.
    //
    // It reported a build timestamp in the future as possibly faked. That was true
    // when compilers wrote real dates into that field. Modern toolchains do not:
    // deterministic builds — the default for .NET, Go and Rust — put a content hash
    // there instead, which routinely decodes to dates like 2056 or 2080. On a real
    // machine this fired on nearly every current DLL, and paired with "unsigned" it
    // was enough on its own to push ordinary files past the alert threshold.
    //
    // A rule that fires on the overwhelming majority of legitimate files has no
    // discriminating power left, whatever weight it carries, and a genuinely faked
    // timestamp is now indistinguishable from a hash anyway.
}
