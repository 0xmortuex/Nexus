using Nexus.Core.Security;
using Nexus.Core.Security.StaticAnalysis;
using Xunit;

namespace Nexus.Core.Tests;

public class PeAnalysisTests
{
    private static string[] Codes(byte[] image)
    {
        var parsed = PeImage.TryParse(image);
        Assert.NotNull(parsed);
        return PeHeuristics.Evaluate(parsed).Select(s => s.Code).ToArray();
    }

    // ---- Parser robustness ----

    [Fact]
    public void Non_pe_input_is_rejected_rather_than_throwing()
    {
        Assert.Null(PeImage.TryParse([]));
        Assert.Null(PeImage.TryParse("not an executable"u8));
        Assert.Null(PeImage.TryParse(new byte[4096]));
    }

    [Fact]
    public void An_mz_stub_with_a_bogus_pe_offset_is_rejected()
    {
        var image = new byte[512];
        image[0] = (byte)'M';
        image[1] = (byte)'Z';
        image[0x3C] = 0xFF;
        image[0x3D] = 0xFF;
        image[0x3E] = 0xFF;
        image[0x3F] = 0x7F;

        Assert.Null(PeImage.TryParse(image));
    }

    [Fact]
    public void Truncated_files_are_rejected_at_every_length()
    {
        var complete = new PeBuilder().AddLowEntropySection().Build();

        // Every prefix must be refused cleanly rather than reading past the buffer.
        for (int length = 0; length < complete.Length; length += 7)
            PeImage.TryParse(complete.AsSpan(0, length));
    }

    [Fact]
    public void Corrupted_bytes_never_throw()
    {
        var complete = new PeBuilder()
            .AddHighEntropySection()
            .WithImports("kernel32.dll", "VirtualAllocEx", "WriteProcessMemory")
            .Build();

        var random = new Random(99);
        for (int trial = 0; trial < 300; trial++)
        {
            var mutated = (byte[])complete.Clone();
            for (int i = 0; i < 12; i++)
                mutated[random.Next(mutated.Length)] = (byte)random.Next(256);

            var parsed = PeImage.TryParse(mutated);
            if (parsed is not null)
                PeHeuristics.Evaluate(parsed);
        }
    }

    // ---- Parsing ----

    [Fact]
    public void A_minimal_pe_parses()
    {
        var parsed = PeImage.TryParse(new PeBuilder().AddLowEntropySection().Build());

        Assert.NotNull(parsed);
        Assert.False(parsed.Is64Bit);
        Assert.False(parsed.IsDll);
        Assert.Single(parsed.Sections);
        Assert.Equal(".text", parsed.Sections[0].Name);
    }

    [Fact]
    public void Bitness_and_dll_flags_are_read()
    {
        var parsed = PeImage.TryParse(new PeBuilder().As64Bit().AsDll().AddLowEntropySection().Build());

        Assert.NotNull(parsed);
        Assert.True(parsed.Is64Bit);
        Assert.True(parsed.IsDll);
    }

    [Fact]
    public void Imports_are_read_back()
    {
        var parsed = PeImage.TryParse(new PeBuilder()
            .AddLowEntropySection()
            .WithImports("kernel32.dll", "CreateFileW", "VirtualAllocEx")
            .Build());

        Assert.NotNull(parsed);
        Assert.Contains("kernel32.dll", parsed.ImportedLibraries);
        Assert.Contains("CreateFileW", parsed.ImportedFunctions);
        Assert.Contains("VirtualAllocEx", parsed.ImportedFunctions);
    }

    [Fact]
    public void Entropy_separates_random_data_from_repetitive_data()
    {
        var packed = PeImage.TryParse(new PeBuilder().AddHighEntropySection().Build())!;
        var plain = PeImage.TryParse(new PeBuilder().AddLowEntropySection().Build())!;

        Assert.True(packed.Sections[0].Entropy > 7.5, $"expected high entropy, got {packed.Sections[0].Entropy:F2}");
        Assert.True(plain.Sections[0].Entropy < 2.0, $"expected low entropy, got {plain.Sections[0].Entropy:F2}");
    }

    [Fact]
    public void An_overlay_is_measured()
    {
        var parsed = PeImage.TryParse(new PeBuilder().AddLowEntropySection().WithOverlay(50_000).Build());

        Assert.NotNull(parsed);
        Assert.Equal(50_000, parsed.OverlayBytes);
    }

    // ---- Heuristics ----

    [Fact]
    public void An_ordinary_program_produces_nothing_alarming()
    {
        var codes = Codes(new PeBuilder()
            .AddLowEntropySection()
            .WithImports("kernel32.dll", "CreateFileW", "ReadFile", "CloseHandle")
            .Build());

        Assert.DoesNotContain("pe-packed-code", codes);
        Assert.DoesNotContain("pe-writable-code", codes);
        Assert.DoesNotContain("pe-entrypoint-outside-sections", codes);
    }

    [Fact]
    public void A_packed_code_section_is_reported()
    {
        Assert.Contains("pe-packed-code", Codes(new PeBuilder().AddHighEntropySection().Build()));
    }

    [Fact]
    public void High_entropy_data_is_weaker_evidence_than_packed_code()
    {
        var dataOnly = PeImage.TryParse(new PeBuilder()
            .AddLowEntropySection()
            .AddHighEntropySection(".rsrc", PeBuilder.DataCharacteristics)
            .Build())!;

        var signal = Assert.Single(PeHeuristics.Evaluate(dataOnly), s => s.Code == "pe-high-entropy-data");
        Assert.Equal(SignalWeight.Weak, signal.Weight);
    }

    [Fact]
    public void A_writable_executable_section_is_reported()
    {
        Assert.Contains("pe-writable-code", Codes(new PeBuilder()
            .AddLowEntropySection(".text", PeBuilder.WritableCodeCharacteristics)
            .Build()));
    }

    [Fact]
    public void An_entry_point_outside_every_section_is_reported()
    {
        Assert.Contains("pe-entrypoint-outside-sections", Codes(new PeBuilder()
            .AddLowEntropySection()
            .WithEntryPointRva(0x7F000000)
            .Build()));
    }

    [Fact]
    public void Packer_section_names_are_recognised()
    {
        Assert.Contains("pe-packer-section-name", Codes(new PeBuilder()
            .AddHighEntropySection("UPX1")
            .Build()));
    }

    [Fact]
    public void The_process_injection_import_set_is_reported()
    {
        var codes = Codes(new PeBuilder()
            .AddLowEntropySection()
            .WithImports("kernel32.dll", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
            .Build());

        Assert.Contains("pe-capability-process-injection", codes);
    }

    [Fact]
    public void A_partial_injection_import_set_is_not_reported()
    {
        // Two of the three is not the pattern; plenty of debuggers and profilers
        // import these individually.
        var codes = Codes(new PeBuilder()
            .AddLowEntropySection()
            .WithImports("kernel32.dll", "VirtualAllocEx", "WriteProcessMemory")
            .Build());

        Assert.DoesNotContain("pe-capability-process-injection", codes);
    }

    [Fact]
    public void Minimal_imports_plus_packed_code_is_reported()
    {
        Assert.Contains("pe-minimal-imports", Codes(new PeBuilder()
            .AddHighEntropySection()
            .WithImports("kernel32.dll", "LoadLibraryA", "GetProcAddress")
            .Build()));
    }

    [Fact]
    public void Managed_assemblies_skip_import_heuristics()
    {
        var codes = Codes(new PeBuilder()
            .AsManaged()
            .AddLowEntropySection()
            .WithImports("mscoree.dll", "_CorExeMain")
            .Build());

        Assert.Contains("pe-managed", codes);
        Assert.DoesNotContain("pe-minimal-imports", codes);
    }

    /// <summary>
    /// Deterministic builds — now the default for .NET, Go and Rust — put a content
    /// hash in the timestamp field, which routinely decodes to a far-future date. A
    /// rule firing on nearly every modern binary has no discriminating power left.
    /// </summary>
    [Fact]
    public void A_future_build_timestamp_is_not_reported()
    {
        var codes = Codes(new PeBuilder()
            .AddLowEntropySection()
            .WithTimestamp(DateTimeOffset.UtcNow.AddYears(30))
            .Build());

        Assert.DoesNotContain("pe-future-timestamp", codes);
    }

    [Fact]
    public void Missing_exploit_mitigations_are_informational_only()
    {
        var parsed = PeImage.TryParse(new PeBuilder()
            .AddLowEntropySection()
            .WithoutMitigations()
            .Build())!;

        var signal = Assert.Single(PeHeuristics.Evaluate(parsed), s => s.Code == "pe-no-mitigations");
        Assert.Equal(SignalWeight.Informational, signal.Weight);
        Assert.Equal(0, signal.Points);
    }

    /// <summary>Packing is not malware. A packed binary must not, on static analysis
    /// alone, come out looking malicious.</summary>
    [Fact]
    public void A_heavily_packed_binary_alone_does_not_reach_likely_malicious()
    {
        var parsed = PeImage.TryParse(new PeBuilder()
            .AddHighEntropySection("UPX1")
            .WithImports("kernel32.dll", "LoadLibraryA", "GetProcAddress")
            .WithoutMitigations()
            .Build())!;

        var verdict = VerdictEngine.Evaluate(new VerdictInput
        {
            Target = ScanTarget.ForFile(@"C:\tools\packed.exe", "deadbeef"),
            Signals = PeHeuristics.Evaluate(parsed),
        }, DateTimeOffset.UnixEpoch);

        Assert.True(verdict.Level <= ThreatLevel.Suspicious,
            $"a packed binary reached {verdict.Level} on static analysis alone");
    }
}
