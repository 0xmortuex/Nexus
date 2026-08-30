using Nexus.Core.Security;
using Nexus.Core.Security.Persistence;
using Xunit;

namespace Nexus.Core.Tests;

public class AutorunAuditTests
{
    private static AutorunEntry Entry(
        AutorunKind kind,
        string name,
        string command = "",
        string? imagePath = null,
        bool signed = false,
        bool createdByNexus = false) =>
        new()
        {
            Kind = kind,
            Location = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            Name = name,
            Command = command,
            ImagePath = imagePath,
            SignedByTrustedPublisher = signed,
            CreatedByNexus = createdByNexus,
        };

    private static string[] Codes(AutorunEntry entry) =>
        AutorunAudit.Evaluate(entry).Select(s => s.Code).ToArray();

    [Fact]
    public void A_signed_program_in_program_files_is_unremarkable()
    {
        Assert.Empty(Codes(Entry(
            AutorunKind.RunKey, "Steam",
            @"""C:\Program Files (x86)\Steam\steam.exe"" -silent",
            @"C:\Program Files (x86)\Steam\steam.exe",
            signed: true)));
    }

    [Fact]
    public void Nexus_own_entries_are_shown_but_never_scored()
    {
        var signals = AutorunAudit.Evaluate(Entry(
            AutorunKind.ScheduledTask, "NexusAutostart", createdByNexus: true));

        var signal = Assert.Single(signals);
        Assert.Equal("run-nexus-own", signal.Code);
        Assert.Equal(SignalWeight.Informational, signal.Weight);
        Assert.Equal(0, signal.Points);
    }

    [Fact]
    public void An_ifeo_debugger_is_reported()
    {
        Assert.Contains("run-ifeo-debugger", Codes(Entry(
            AutorunKind.Ifeo, "taskmgr.exe", @"C:\Users\x\AppData\Local\Temp\d.exe")));
    }

    [Fact]
    public void A_wmi_event_subscription_is_reported()
    {
        Assert.Contains("run-wmi-subscription", Codes(Entry(
            AutorunKind.WmiSubscription, "BVTFilter", "powershell -enc ...")));
    }

    [Fact]
    public void AppInit_dlls_are_reported()
    {
        Assert.Contains("run-appinit-dll", Codes(Entry(
            AutorunKind.AppInitDll, "AppInit_DLLs", @"C:\Windows\System32\hook.dll")));
    }

    [Fact]
    public void Default_winlogon_values_are_not_flagged()
    {
        Assert.Empty(Codes(Entry(AutorunKind.WinlogonHook, "Shell", "explorer.exe")));
        Assert.Empty(Codes(Entry(AutorunKind.WinlogonHook, "Userinit", @"C:\Windows\system32\userinit.exe,")));
    }

    [Fact]
    public void A_replaced_winlogon_shell_is_reported()
    {
        Assert.Contains("run-winlogon-hook", Codes(Entry(
            AutorunKind.WinlogonHook, "Shell", @"explorer.exe, C:\ProgramData\svc.exe")));
    }

    [Fact]
    public void Startup_entries_that_launch_through_an_interpreter_are_reported()
    {
        Assert.Contains("run-scripted-launch", Codes(Entry(
            AutorunKind.RunKey, "Updater", "powershell -w hidden -File C:\\x\\u.ps1")));
    }

    [Fact]
    public void Encoded_startup_commands_are_reported()
    {
        Assert.Contains("run-encoded-command", Codes(Entry(
            AutorunKind.RunKey, "Sync",
            "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA")));
    }

    [Fact]
    public void Unsigned_startup_from_a_user_writable_folder_is_strong_evidence()
    {
        var signals = AutorunAudit.Evaluate(Entry(
            AutorunKind.RunKey, "Helper",
            @"C:\Users\fadi\AppData\Roaming\helper.exe",
            @"C:\Users\fadi\AppData\Roaming\helper.exe"));

        var signal = Assert.Single(signals, s => s.Code == "run-unsigned-from-user-folder");
        Assert.Equal(SignalWeight.Strong, signal.Weight);
    }

    [Fact]
    public void A_signed_program_in_a_user_folder_is_only_weak_evidence()
    {
        var signals = AutorunAudit.Evaluate(Entry(
            AutorunKind.RunKey, "Discord",
            @"C:\Users\fadi\AppData\Local\Discord\Update.exe",
            @"C:\Users\fadi\AppData\Local\Discord\Update.exe",
            signed: true));

        var signal = Assert.Single(signals, s => s.Code == "run-from-user-folder");
        Assert.Equal(SignalWeight.Weak, signal.Weight);
    }

    [Fact]
    public void An_unsigned_service_is_reported()
    {
        Assert.Contains("run-unsigned-service", Codes(Entry(
            AutorunKind.Service, "UpdateSvc",
            @"C:\Program Files\Vendor\svc.exe",
            @"C:\Program Files\Vendor\svc.exe")));
    }

    [Fact]
    public void A_startup_entry_with_a_deceptive_name_is_reported()
    {
        Assert.Contains("run-double-extension", Codes(Entry(
            AutorunKind.StartupFolder, "Invoice",
            @"C:\Users\fadi\Documents\invoice.pdf.exe",
            @"C:\Users\fadi\Documents\invoice.pdf.exe",
            signed: true)));
    }

    /// <summary>The whole autorun surface feeds one source, so the per-source cap in
    /// the fusion engine keeps a single noisy startup entry from reaching "malicious"
    /// on its own.</summary>
    [Fact]
    public void A_maximally_bad_autorun_entry_still_needs_corroboration()
    {
        var signals = AutorunAudit.Evaluate(Entry(
            AutorunKind.Ifeo, "explorer.exe",
            "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
            @"C:\Users\fadi\AppData\Local\Temp\invoice.pdf.exe"));

        var verdict = VerdictEngine.Evaluate(new VerdictInput
        {
            Target = ScanTarget.ForFile(@"C:\Users\fadi\AppData\Local\Temp\invoice.pdf.exe"),
            Signals = signals,
        }, DateTimeOffset.UnixEpoch);

        Assert.True(signals.Count >= 4, "expected several signals from this entry");
        Assert.Equal(ThreatLevel.LikelyMalicious, verdict.Level);
        Assert.True(verdict.Score <= VerdictEngine.MaxPointsPerSource);
    }
}
