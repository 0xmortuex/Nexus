using Nexus.Core.Persistence;
using Nexus.Core.Tweaks;
using Xunit;

namespace Nexus.Core.Tests;

public class TweakCatalogTests
{
    [Fact]
    public void Every_tweak_is_complete_and_undoable()
    {
        Assert.NotEmpty(TweakCatalog.All);

        foreach (var tweak in TweakCatalog.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(tweak.Id));
            Assert.False(string.IsNullOrWhiteSpace(tweak.Name));
            Assert.False(string.IsNullOrWhiteSpace(tweak.Category));
            Assert.False(string.IsNullOrWhiteSpace(tweak.Description), $"{tweak.Id} needs an honest description");

            // "Never ship decorative toggles": every tweak must DO something...
            Assert.True(tweak.RegistryOps.Count + tweak.Commands.Count > 0,
                $"{tweak.Id} has no registry ops and no commands");

            // ...and every command tweak must know how to undo itself.
            Assert.All(tweak.Commands, c =>
            {
                Assert.False(string.IsNullOrWhiteSpace(c.ApplyArgs));
                Assert.False(string.IsNullOrWhiteSpace(c.UndoArgs));
            });

            // Registry ops must be capturable: rooted key paths and a known kind.
            Assert.All(tweak.RegistryOps, op =>
            {
                Assert.StartsWith("HKEY_", op.KeyPath);
                Assert.Contains(op.Kind, new[] { "dword", "string" });
                if (tweak.PerNetworkAdapter)
                    Assert.Contains("{adapter}", op.KeyPath);
            });
        }
    }

    [Fact]
    public void Tweak_ids_are_unique()
    {
        var ids = TweakCatalog.All.Select(t => t.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
    }

    [Fact]
    public void Affected_keys_deduplicate()
    {
        var mouseAccel = TweakCatalog.Find("mouse-accel-off")!;

        // Three ops on the same key → one key to back up.
        Assert.Single(mouseAccel.AffectedKeys());
    }

    [Fact]
    public void No_description_overpromises()
    {
        foreach (var tweak in TweakCatalog.All)
        {
            Assert.DoesNotContain("boost fps", tweak.Description, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("massive", tweak.Description, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("huge", tweak.Description, StringComparison.OrdinalIgnoreCase);
        }
    }
}

public class CleanerTargetsTests
{
    [Fact]
    public void Paths_inside_roots_are_deletable()
    {
        string root = OperatingSystem.IsWindows() ? @"C:\Users\x\AppData\Local\D3DSCache" : "/tmp/cache";
        var file = Path.Combine(root, "sub", "a.bin");

        Assert.True(CleanerTargets.IsSafeToDelete(file, [root]));
    }

    [Fact]
    public void Traversal_out_of_root_is_blocked()
    {
        string root = OperatingSystem.IsWindows() ? @"C:\Windows\Temp" : "/tmp/wintemp";
        var escape = Path.Combine(root, "..", "System32", "kernel32.dll");

        Assert.False(CleanerTargets.IsSafeToDelete(escape, [root]));
    }

    [Fact]
    public void Sibling_directory_with_same_prefix_is_blocked()
    {
        string root = OperatingSystem.IsWindows() ? @"C:\Temp" : "/tmp/t";
        var sibling = root + "2" + Path.DirectorySeparatorChar + "file.txt";

        Assert.False(CleanerTargets.IsSafeToDelete(sibling, [root]));
    }

    [Fact]
    public void Root_itself_is_not_deletable()
    {
        string root = OperatingSystem.IsWindows() ? @"C:\Windows\Temp" : "/tmp/wintemp";

        Assert.False(CleanerTargets.IsSafeToDelete(root, [root]));
    }

    [Fact]
    public void Target_list_covers_the_advertised_caches()
    {
        var targets = CleanerTargets.Build(@"C:\Users\x\Temp", @"C:\Windows", @"C:\Users\x\AppData\Local");
        var ids = targets.Select(t => t.Id).ToHashSet();

        Assert.Superset(new HashSet<string>
        {
            "user-temp", "windows-temp", "dx-shader-cache",
            "nvidia-shader-cache", "amd-shader-cache", "wu-cache", "thumbnail-cache",
        }, ids);

        // The thumbnail target must be pattern-scoped: the Explorer directory holds
        // other files that must never be touched.
        Assert.Equal("thumbcache_*.db", targets.Single(t => t.Id == "thumbnail-cache").FilePattern);
    }
}

public class TweakStateStoreTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nexus-tweaks-").FullName;

    private TweakStateStore NewStore() => new(new JsonStore<TweaksState>(
        Path.Combine(_dir, "tweaks-state.json"), NexusJsonContext.Default.TweaksState, static () => new TweaksState()));

    [Fact]
    public void Applied_tweaks_persist_with_their_originals()
    {
        var store = NewStore();
        store.RecordApplied(new AppliedTweak("gamedvr-off", DateTimeOffset.Now,
            [new CapturedValue(@"HKEY_CURRENT_USER\System\GameConfigStore", "GameDVR_Enabled", "dword", "1", true)],
            @"C:\backup\dir"));

        var reloaded = NewStore().FindApplied("gamedvr-off");

        Assert.NotNull(reloaded);
        var original = Assert.Single(reloaded.Originals);
        Assert.True(original.Existed);
        Assert.Equal("1", original.Value);

        NewStore().RemoveApplied("gamedvr-off");
        Assert.Null(NewStore().FindApplied("gamedvr-off"));
    }

    [Fact]
    public void Reapplying_replaces_rather_than_duplicates()
    {
        var store = NewStore();
        store.RecordApplied(new AppliedTweak("x", DateTimeOffset.Now, [], null));
        store.RecordApplied(new AppliedTweak("x", DateTimeOffset.Now.AddMinutes(1), [], null));

        Assert.Single(NewStore().Current.Applied);
    }

    [Fact]
    public void First_service_original_wins()
    {
        var store = NewStore();
        var key = @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain";
        store.RecordServiceOriginal(new CapturedValue(key, "Start", "dword", "2", true));
        store.RecordServiceOriginal(new CapturedValue(key, "Start", "dword", "4", true));

        var original = Assert.Single(NewStore().Current.ServiceOriginals);
        Assert.Equal("2", original.Value);
    }

    [Fact]
    public void Disabled_tasks_round_trip_and_dedupe()
    {
        var store = NewStore();
        store.RecordDisabledTask(@"\Microsoft\Windows\Feedback\Siuf\DmClient");
        store.RecordDisabledTask(@"\microsoft\windows\feedback\siuf\dmclient");

        Assert.Single(NewStore().Current.DisabledTasks);

        NewStore().RemoveDisabledTask(@"\Microsoft\Windows\Feedback\Siuf\DmClient");
        Assert.Empty(NewStore().Current.DisabledTasks);
    }

    public void Dispose() => Directory.Delete(_dir, recursive: true);
}
