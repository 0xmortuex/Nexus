using System.Diagnostics;
using System.Text.Json;
using Nexus.Core.Logging;

namespace Nexus.App.Services;

public sealed record NicAdvancedProperty(string AdapterName, string Keyword, string DisplayName, string? Value);

/// <summary>
/// NIC advanced-property tuning from the report (Interrupt Moderation, Flow Control,
/// Energy-Efficient Ethernet) via Set-NetAdapterAdvancedProperty. Each keyword is
/// read before it is changed so the original value can be restored; the honest UI
/// note is that disabling interrupt moderation trades CPU for latency and only
/// helps on a fast wired connection.
/// </summary>
public sealed class NicTuningService
{
    /// <summary>Registry/driver keyword → (friendly label, value that means "off").</summary>
    public static IReadOnlyList<(string Keyword, string Label, string OffValue)> LatencyKeywords { get; } =
    [
        ("*InterruptModeration", "Interrupt Moderation", "0"),
        ("*FlowControl", "Flow Control", "0"),
        ("*EEE", "Energy-Efficient Ethernet", "0"),
    ];

    private readonly ActivityLog _log;

    public NicTuningService(ActivityLog log)
    {
        _log = log;
    }

    public IReadOnlyList<string> GetAdapterNames()
    {
        try
        {
            var output = RunPowerShell(
                "Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress", 20_000);
            if (string.IsNullOrWhiteSpace(output))
                return [];
            using var json = JsonDocument.Parse(output);
            return json.RootElement.ValueKind == JsonValueKind.Array
                ? json.RootElement.EnumerateArray().Select(e => e.GetString() ?? "").Where(s => s.Length > 0).ToArray()
                : [json.RootElement.GetString() ?? ""];
        }
        catch (Exception ex)
        {
            _log.Warn("NIC", $"Could not list adapters: {ex.Message}");
            return [];
        }
    }

    public string? ReadKeyword(string adapter, string keyword)
    {
        try
        {
            var output = RunPowerShell(
                $"(Get-NetAdapterAdvancedProperty -Name '{adapter}' -RegistryKeyword '{keyword}' -ErrorAction SilentlyContinue).RegistryValue", 15_000);
            var value = output.Trim();
            return value.Length == 0 ? null : value;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public bool SetKeyword(string adapter, string keyword, string value, out string? error)
    {
        error = null;
        try
        {
            var output = RunPowerShell(
                $"Set-NetAdapterAdvancedProperty -Name '{adapter}' -RegistryKeyword '{keyword}' -RegistryValue '{value}' -NoRestart -ErrorAction Stop; 'OK'", 20_000);
            if (!output.Contains("OK"))
            {
                error = output.Trim().Length > 0 ? output.Trim() : "the adapter does not expose this property";
                _log.Warn("NIC", $"Could not set {keyword} on {adapter}: {error}");
                return false;
            }
            _log.Info("NIC", $"Set {keyword} = {value} on {adapter}.");
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static string RunPowerShell(string script, int timeoutMs)
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
            return "";
        var output = process.StandardOutput.ReadToEnd();
        process.WaitForExit(timeoutMs);
        return output;
    }
}
