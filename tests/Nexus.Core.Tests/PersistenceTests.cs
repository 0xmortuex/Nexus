using Nexus.Core.Models;
using Nexus.Core.Persistence;
using Nexus.Core.Rules;
using Xunit;

namespace Nexus.Core.Tests;

public class PersistenceTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nexus-tests-").FullName;

    private JsonStore<List<ProcessRule>> NewStore(string name = "rules.json") => new(
        Path.Combine(_dir, name), NexusJsonContext.Default.ListProcessRule, static () => []);

    [Fact]
    public void Rules_round_trip_all_fields()
    {
        var store = NewStore();
        var rule = new ProcessRule
        {
            ExeName = "Game.EXE",
            Priority = ProcessPriority.High,
            AffinityMode = CpuAffinityMode.CustomMask,
            CustomAffinityMask = 0xF0,
            UseCpuSets = false,
            IoPriority = IoPriorityLevel.Low,
            MemoryPriority = MemoryPriorityLevel.BelowNormal,
            EfficiencyMode = false,
            TrimWorkingSetOnStart = true,
            Enabled = false,
        };

        store.Save([rule]);
        var loaded = Assert.Single(NewStore().Load());

        Assert.Equal(rule, loaded);
    }

    [Fact]
    public void Missing_file_returns_defaults()
    {
        Assert.Empty(NewStore("does-not-exist.json").Load());
    }

    [Fact]
    public void Corrupt_file_returns_defaults_and_preserves_evidence()
    {
        var store = NewStore();
        File.WriteAllText(store.Path, "{ not json !!!");

        Assert.Empty(store.Load());
        Assert.False(File.Exists(store.Path));
        Assert.True(File.Exists(store.Path + ".bad"));
    }

    [Fact]
    public void Save_leaves_no_temp_file_behind()
    {
        var store = NewStore();
        store.Save([new ProcessRule { ExeName = "a.exe" }]);

        Assert.True(File.Exists(store.Path));
        Assert.False(File.Exists(store.Path + ".tmp"));
    }

    [Fact]
    public void Unknown_json_properties_are_tolerated()
    {
        var store = NewStore();
        File.WriteAllText(store.Path,
            """[{"ExeName":"x.exe","Priority":"High","SomeFutureField":{"a":1}}]""");

        var loaded = Assert.Single(store.Load());

        Assert.Equal("x.exe", loaded.ExeName);
        Assert.Equal(ProcessPriority.High, loaded.Priority);
    }

    [Fact]
    public void Repository_lookup_is_case_insensitive_and_extension_tolerant()
    {
        var repo = new RulesRepository(NewStore());
        repo.Upsert(new ProcessRule { ExeName = "Game.exe", Priority = ProcessPriority.High });

        Assert.NotNull(repo.Find("GAME.EXE"));
        Assert.NotNull(repo.Find("game"));
        Assert.Null(repo.Find("other.exe"));
    }

    [Fact]
    public void Repository_persists_across_instances()
    {
        new RulesRepository(NewStore()).Upsert(new ProcessRule { ExeName = "a.exe" });

        var reloaded = new RulesRepository(NewStore());

        Assert.NotNull(reloaded.Find("a.exe"));
        Assert.True(reloaded.Remove("A.EXE"));
        Assert.Null(new RulesRepository(NewStore()).Find("a.exe"));
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);
}
