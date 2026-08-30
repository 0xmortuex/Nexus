using Nexus.Core.Models;
using Nexus.Core.Persistence;
using Xunit;

namespace Nexus.Core.Tests;

/// <summary>
/// Loading a settings file written by an older build.
///
/// This is not a hypothetical: every existing install has a settings.json that
/// predates whatever was added last. A missing section has to come back as its
/// defaults, because the alternative is a null that reaches the first line of code
/// which touches it — and in the App layer that means the whole window fails to open
/// while the process stays alive, which is the worst possible way to fail.
/// </summary>
public class SettingsUpgradeTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nexus-settings-upgrade-").FullName;

    private JsonStore<AppSettings> NewStore(string name = "settings.json") => new(
        Path.Combine(_dir, name), NexusJsonContext.Default.AppSettings, static () => new AppSettings());

    private string WriteLegacy(string json, string name = "settings.json")
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllText(path, json);
        return path;
    }

    /// <summary>A real settings.json from before the security module existed.</summary>
    private const string LegacySettings = """
        {
          "ProBalance": {
            "Enabled": true,
            "SystemLoadEnterPct": 85,
            "SystemLoadExitPct": 70
          },
          "ForegroundBoost": false,
          "WizardCompleted": true,
          "AdvancedMode": false
        }
        """;

    [Fact]
    public void A_settings_file_without_the_security_section_still_loads_its_defaults()
    {
        WriteLegacy(LegacySettings);

        var settings = NewStore().Load();

        Assert.NotNull(settings.Security);
        Assert.True(settings.Security.BehaviourMonitoring);
        Assert.True(settings.Security.RansomwareWatch);
    }

    [Fact]
    public void Sections_that_were_present_are_preserved()
    {
        WriteLegacy(LegacySettings);

        var settings = NewStore().Load();

        Assert.True(settings.ProBalance.Enabled);
        Assert.Equal(85, settings.ProBalance.SystemLoadEnterPct);
        Assert.True(settings.WizardCompleted);
    }

    /// <summary>An explicit null is the same problem arriving a different way.</summary>
    [Fact]
    public void An_explicitly_null_section_still_loads_its_defaults()
    {
        WriteLegacy("""{ "Security": null, "WizardCompleted": true }""", "explicit-null.json");

        var settings = NewStore("explicit-null.json").Load();

        Assert.NotNull(settings.Security);
        Assert.True(settings.WizardCompleted);
    }

    /// <summary>Every nested options object, not just the newest one.</summary>
    [Fact]
    public void An_empty_document_produces_a_fully_populated_settings_object()
    {
        WriteLegacy("{}", "empty.json");

        var settings = NewStore("empty.json").Load();

        Assert.NotNull(settings.Security);
        Assert.NotNull(settings.ProBalance);
        Assert.NotNull(settings.Enforcement);
        Assert.NotNull(settings.IdleSaver);
        Assert.NotNull(settings.SmartTrim);
        Assert.NotNull(settings.Power);
        Assert.NotNull(settings.GameMode);
        Assert.NotNull(settings.Memory);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup.
        }
    }
}
