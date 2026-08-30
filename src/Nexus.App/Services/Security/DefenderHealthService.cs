using System.Diagnostics;
using System.Text.Json;
using Nexus.Core.Logging;
using Nexus.Core.Security;

namespace Nexus.App.Services.Security;

/// <summary>What Microsoft Defender is currently doing, or not doing.</summary>
public sealed record DefenderStatus
{
    public bool? RealTimeProtectionEnabled { get; init; }
    public bool? AntivirusEnabled { get; init; }
    public bool? TamperProtectionEnabled { get; init; }
    public bool? SignaturesOutOfDate { get; init; }
    public int? SignatureAgeDays { get; init; }

    public IReadOnlyList<string> ExcludedPaths { get; init; } = [];
    public IReadOnlyList<string> ExcludedExtensions { get; init; } = [];
    public IReadOnlyList<string> ExcludedProcesses { get; init; } = [];

    /// <summary>False when Defender could not be queried at all.</summary>
    public bool Available { get; init; }

    /// <summary>False when the exclusion lists could not be read. Get-MpPreference
    /// returns a placeholder string rather than the real list when the caller is not
    /// elevated, and an empty exclusion list must never be mistaken for a clean one.</summary>
    public bool ExclusionsReadable { get; init; } = true;
}

/// <summary>
/// Reports on Microsoft Defender rather than replacing it.
///
/// Nexus cannot register as the system antivirus — that needs Microsoft Virus
/// Initiative membership — and should not want to. What it can usefully do is watch
/// the defence the machine actually relies on, because two of the most common things
/// an intruder does are switch real-time protection off and add an exclusion for the
/// folder they are working in. Both are quiet, both persist, and neither shows up
/// anywhere a normal user looks.
///
/// Exclusions get particular attention: an exclusion for a whole drive, a user
/// profile, or a temp folder is not a tuning decision, it is a hole. Nexus lists them
/// and explains which ones are suspicious. It does not remove them — that is
/// Defender's own settings page, and silently editing another security product's
/// configuration is exactly the behaviour Sentinel refuses to have.
/// </summary>
public sealed class DefenderHealthService
{
    private readonly ActivityLog _log;

    public DefenderHealthService(ActivityLog log)
    {
        _log = log;
    }

    /// <summary>Folders broad enough that excluding them defeats the point.</summary>
    private static readonly string[] OverlyBroadExclusions =
    [
        @"c:\", @"d:\", @"c:\users", @"c:\windows", @"c:\program files",
        @"c:\programdata", @"%userprofile%", @"%temp%", @"%appdata%",
    ];

    public DefenderStatus Query()
    {
        const string script =
            "$s = Get-MpComputerStatus; $p = Get-MpPreference; " +
            "[pscustomobject]@{ " +
            "RealTime = $s.RealTimeProtectionEnabled; " +
            "Antivirus = $s.AntivirusEnabled; " +
            "Tamper = $s.IsTamperProtected; " +
            "SigAge = $s.AntivirusSignatureAge; " +
            "ExPath = @($p.ExclusionPath); " +
            "ExExt = @($p.ExclusionExtension); " +
            "ExProc = @($p.ExclusionProcess) " +
            "} | ConvertTo-Json -Compress";

        var output = RunPowerShell(script);
        if (output is null || output.Trim().Length == 0)
        {
            _log.Info("Sentinel", "Could not read Microsoft Defender's status on this machine.");
            return new DefenderStatus { Available = false };
        }

        try
        {
            using var json = JsonDocument.Parse(output);
            var root = json.RootElement;

            int? signatureAge = ReadInt(root, "SigAge");

            return new DefenderStatus
            {
                Available = true,
                RealTimeProtectionEnabled = ReadBool(root, "RealTime"),
                AntivirusEnabled = ReadBool(root, "Antivirus"),
                TamperProtectionEnabled = ReadBool(root, "Tamper"),
                SignatureAgeDays = signatureAge,
                SignaturesOutOfDate = signatureAge is > 7,
                ExclusionsReadable = !ContainsAccessPlaceholder(root),
                ExcludedPaths = ReadStrings(root, "ExPath"),
                ExcludedExtensions = ReadStrings(root, "ExExt"),
                ExcludedProcesses = ReadStrings(root, "ExProc"),
            };
        }
        catch (JsonException ex)
        {
            _log.Info("Sentinel", $"Defender status could not be parsed: {ex.Message}");
            return new DefenderStatus { Available = false };
        }
    }

    /// <summary>Turn the status into signals for the findings list.</summary>
    public static IReadOnlyList<SecuritySignal> Evaluate(DefenderStatus status)
    {
        if (!status.Available)
            return [];

        var signals = new List<SecuritySignal>();

        if (status.RealTimeProtectionEnabled == false)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Strong,
                "defender-realtime-off",
                "Microsoft Defender's real-time protection is switched off. Nexus only reports on " +
                "things — Defender is what actually stops them — so this machine currently has no " +
                "active protection."));
        }

        if (status.AntivirusEnabled == false)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Strong,
                "defender-disabled",
                "Microsoft Defender's antivirus engine is disabled."));
        }

        if (status.TamperProtectionEnabled == false)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Weak,
                "defender-tamper-protection-off",
                "Defender's tamper protection is off, so any program running as administrator can " +
                "change its settings without asking."));
        }

        if (status.SignaturesOutOfDate == true)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Moderate,
                "defender-signatures-stale",
                $"Defender's definitions are {status.SignatureAgeDays} days old. It only recognises " +
                "what it has definitions for."));
        }

        if (!status.ExclusionsReadable)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Informational,
                "defender-exclusions-unreadable",
                "Defender's exclusion list could not be read, so Nexus cannot tell whether anything " +
                "has been excluded from scanning. Windows only reveals it to an administrator."));
        }

        foreach (var path in status.ExcludedPaths)
        {
            if (!IsOverlyBroad(path))
                continue;

            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Strong,
                "defender-broad-exclusion",
                $"Defender has been told to ignore {path} entirely. An exclusion that broad turns " +
                "protection off for everything inside it, and adding one is a standard step for " +
                "malware that wants to stay."));
        }

        if (status.ExcludedProcesses.Count > 0)
        {
            signals.Add(new SecuritySignal(
                SignalSource.Persistence,
                SignalWeight.Moderate,
                "defender-process-exclusions",
                $"Defender is ignoring {status.ExcludedProcesses.Count} process(es): " +
                $"{string.Join(", ", status.ExcludedProcesses.Take(5))}. Anything those processes " +
                "touch goes unscanned."));
        }

        return signals;
    }

    private static bool IsOverlyBroad(string path)
    {
        var normalized = path.Trim().TrimEnd('\\', '*').ToLowerInvariant();

        return OverlyBroadExclusions.Any(broad =>
            string.Equals(normalized, broad.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>A one-line summary for the Security tab header.</summary>
    public static string Describe(DefenderStatus status)
    {
        if (!status.Available)
            return "Microsoft Defender's status could not be read on this machine.";

        if (status.RealTimeProtectionEnabled == false)
            return "Microsoft Defender's real-time protection is OFF. Nexus reports; Defender protects. Turn it back on.";

        if (!status.ExclusionsReadable)
        {
            return $"Microsoft Defender is on, definitions {status.SignatureAgeDays ?? 0} day(s) old. " +
                   "Its exclusion list could not be read.";
        }

        int exclusions = status.ExcludedPaths.Count + status.ExcludedProcesses.Count + status.ExcludedExtensions.Count;

        return $"Microsoft Defender is on, definitions {status.SignatureAgeDays ?? 0} day(s) old, " +
               $"{exclusions} exclusion(s) configured.";
    }

    private string? RunPowerShell(string script)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{script}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });

            if (process is null)
                return null;

            var output = process.StandardOutput.ReadToEnd();

            if (!process.WaitForExit(30_000))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                    // Already gone.
                }
                return null;
            }

            return output;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return null;
        }
    }

    private static bool? ReadBool(JsonElement root, string property) =>
        root.TryGetProperty(property, out var value)
            ? value.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                _ => null,
            }
            : null;

    private static int? ReadInt(JsonElement root, string property) =>
        root.TryGetProperty(property, out var value) && value.TryGetInt32(out int number) ? number : null;

    /// <summary>
    /// Detects the "N/A: Must be an administrator to view exclusions" placeholder that
    /// Get-MpPreference substitutes for the real lists when it is not elevated.
    /// Treating that string as an exclusion path would both misreport the count and,
    /// worse, make an unreadable list look like an empty one.
    /// </summary>
    private static bool ContainsAccessPlaceholder(JsonElement root) =>
        new[] { "ExPath", "ExExt", "ExProc" }
            .SelectMany(property => ReadRawStrings(root, property))
            .Any(IsAccessPlaceholder);

    private static bool IsAccessPlaceholder(string value) =>
        value.StartsWith("N/A", StringComparison.OrdinalIgnoreCase)
        && value.Contains("administrator", StringComparison.OrdinalIgnoreCase);

    private static IReadOnlyList<string> ReadStrings(JsonElement root, string property) =>
        ReadRawStrings(root, property).Where(text => !IsAccessPlaceholder(text)).ToArray();

    private static IReadOnlyList<string> ReadRawStrings(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var value))
            return [];

        // ConvertTo-Json collapses a one-element array to a bare value.
        if (value.ValueKind == JsonValueKind.String)
            return [value.GetString() ?? ""];

        if (value.ValueKind != JsonValueKind.Array)
            return [];

        return value.EnumerateArray()
            .Where(item => item.ValueKind == JsonValueKind.String)
            .Select(item => item.GetString() ?? "")
            .Where(text => text.Length > 0)
            .ToArray();
    }
}
