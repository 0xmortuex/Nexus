using Nexus.Core.Enforcement;
using Nexus.Core.Models;
using Nexus.Core.Power;
using Xunit;

namespace Nexus.Core.Tests;

public class InstanceLimitEngineTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Kills_newest_instances_beyond_limit()
    {
        var limit = new InstanceLimit { ExeName = "app.exe", MaxInstances = 2 };
        var instances = new[]
        {
            new RunningInstance(10, "app.exe", T0),
            new RunningInstance(11, "app.exe", T0.AddSeconds(1)),
            new RunningInstance(12, "app.exe", T0.AddSeconds(2)),
            new RunningInstance(13, "APP.EXE", T0.AddSeconds(3)),
            new RunningInstance(99, "other.exe", T0.AddSeconds(4)),
        };

        var toKill = InstanceLimitEngine.SelectPidsToKill(instances, limit);

        Assert.Equal([13, 12], toKill); // newest first, oldest two survive
    }

    [Fact]
    public void Under_limit_kills_nothing()
    {
        var limit = new InstanceLimit { ExeName = "app.exe", MaxInstances = 3 };
        var instances = new[]
        {
            new RunningInstance(10, "app.exe", T0),
            new RunningInstance(11, "app.exe", T0.AddSeconds(1)),
        };

        Assert.Empty(InstanceLimitEngine.SelectPidsToKill(instances, limit));
    }

    [Fact]
    public void Disabled_or_zero_limit_kills_nothing()
    {
        var instances = new[] { new RunningInstance(10, "app.exe", T0), new RunningInstance(11, "app.exe", T0) };

        Assert.Empty(InstanceLimitEngine.SelectPidsToKill(instances,
            new InstanceLimit { ExeName = "app.exe", MaxInstances = 1, Enabled = false }));
        Assert.Empty(InstanceLimitEngine.SelectPidsToKill(instances,
            new InstanceLimit { ExeName = "app.exe", MaxInstances = 0 }));
    }
}

public class WatchdogEngineTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static SystemSnapshot Snap(DateTimeOffset at, params ProcSample[] procs)
        => new(at, 50, [50], procs, 8L << 30, 16L << 30);

    private static WatchdogRule CpuRule(int forSeconds = 3, int cooldown = 60) => new()
    {
        ExeName = "leaky.exe",
        CpuAbovePct = 50,
        ForSeconds = forSeconds,
        CooldownSeconds = cooldown,
        Action = WatchdogActionKind.Kill,
    };

    [Fact]
    public void Fires_only_after_sustained_breach()
    {
        var engine = new WatchdogEngine();
        var rules = new[] { CpuRule() };

        Assert.Empty(engine.Tick(Snap(T0, new ProcSample(1, "leaky.exe", 80, 0)), rules, T0));
        Assert.Empty(engine.Tick(Snap(T0.AddSeconds(2), new ProcSample(1, "leaky.exe", 80, 0)), rules, T0.AddSeconds(2)));

        var triggers = engine.Tick(Snap(T0.AddSeconds(3), new ProcSample(1, "leaky.exe", 80, 0)), rules, T0.AddSeconds(3));

        var trigger = Assert.Single(triggers);
        Assert.Equal(1, trigger.Pid);
        Assert.Equal(WatchdogActionKind.Kill, trigger.Rule.Action);
    }

    [Fact]
    public void Dropping_below_threshold_resets_the_clock()
    {
        var engine = new WatchdogEngine();
        var rules = new[] { CpuRule() };

        engine.Tick(Snap(T0, new ProcSample(1, "leaky.exe", 80, 0)), rules, T0);
        engine.Tick(Snap(T0.AddSeconds(2), new ProcSample(1, "leaky.exe", 10, 0)), rules, T0.AddSeconds(2));
        var triggers = engine.Tick(Snap(T0.AddSeconds(4), new ProcSample(1, "leaky.exe", 80, 0)), rules, T0.AddSeconds(4));

        Assert.Empty(triggers);
    }

    [Fact]
    public void Cooldown_prevents_immediate_retrigger()
    {
        var engine = new WatchdogEngine();
        var rules = new[] { CpuRule(forSeconds: 0, cooldown: 30) };

        Assert.Single(engine.Tick(Snap(T0, new ProcSample(1, "leaky.exe", 80, 0)), rules, T0));
        Assert.Empty(engine.Tick(Snap(T0.AddSeconds(10), new ProcSample(1, "leaky.exe", 80, 0)), rules, T0.AddSeconds(10)));
        Assert.Single(engine.Tick(Snap(T0.AddSeconds(31), new ProcSample(1, "leaky.exe", 80, 0)), rules, T0.AddSeconds(31)));
    }

    [Fact]
    public void Ram_threshold_is_an_or_condition()
    {
        var engine = new WatchdogEngine();
        var rules = new[]
        {
            new WatchdogRule
            {
                ExeName = "leaky.exe",
                CpuAbovePct = 90,
                WorkingSetAboveBytes = 100 << 20,
                ForSeconds = 0,
                Action = WatchdogActionKind.TrimWorkingSet,
            },
        };

        // CPU is low but RAM is over — must still fire.
        var triggers = engine.Tick(Snap(T0, new ProcSample(1, "leaky.exe", 5, 200 << 20)), rules, T0);

        var trigger = Assert.Single(triggers);
        Assert.Contains("MB", trigger.Reason);
    }
}

public class IdleSaverEngineTests
{
    private static readonly IdleSaverOptions On = new() { Enabled = true, IdleMinutes = 10 };

    [Fact]
    public void Enters_power_saver_after_idle_threshold()
    {
        var engine = new IdleSaverEngine();

        Assert.Null(engine.Tick(TimeSpan.FromMinutes(9), On, suppressed: false));
        Assert.Equal(IdleTransition.EnterPowerSaver, engine.Tick(TimeSpan.FromMinutes(10), On, suppressed: false));
        Assert.Null(engine.Tick(TimeSpan.FromMinutes(11), On, suppressed: false)); // no repeat
    }

    [Fact]
    public void Restores_on_input_and_does_not_repeat()
    {
        var engine = new IdleSaverEngine();
        engine.Tick(TimeSpan.FromMinutes(10), On, false);

        Assert.Equal(IdleTransition.RestorePreviousPlan, engine.Tick(TimeSpan.FromSeconds(1), On, false));
        Assert.Null(engine.Tick(TimeSpan.FromSeconds(2), On, false));
    }

    [Fact]
    public void Suppression_blocks_entry_and_forces_exit()
    {
        var engine = new IdleSaverEngine();

        Assert.Null(engine.Tick(TimeSpan.FromMinutes(30), On, suppressed: true));

        engine.Tick(TimeSpan.FromMinutes(30), On, suppressed: false); // enter
        Assert.Equal(IdleTransition.RestorePreviousPlan, engine.Tick(TimeSpan.FromMinutes(31), On, suppressed: true));
    }

    [Fact]
    public void Disabled_never_enters_and_exits_if_active()
    {
        var engine = new IdleSaverEngine();
        var off = On with { Enabled = false };

        Assert.Null(engine.Tick(TimeSpan.FromHours(2), off, false));

        engine.Tick(TimeSpan.FromMinutes(30), On, false); // enter while enabled
        Assert.Equal(IdleTransition.RestorePreviousPlan, engine.Tick(TimeSpan.FromMinutes(31), off, false));
    }
}

public class SmartTrimEngineTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly SmartTrimOptions On = new()
    {
        Enabled = true,
        WorkingSetThresholdMb = 100,
        IntervalMinutes = 5,
        CooldownMinutes = 15,
    };

    private static SystemSnapshot Snap(DateTimeOffset at, params ProcSample[] procs)
        => new(at, 10, [10], procs, 8L << 30, 16L << 30);

    private static SmartTrimEngine Engine() => new(name => name == "exempt.exe");

    [Fact]
    public void Selects_background_processes_over_threshold_only()
    {
        var engine = Engine();
        var targets = engine.Tick(Snap(T0,
            new ProcSample(101, "big.exe", 0, 200 << 20),
            new ProcSample(102, "small.exe", 0, 50 << 20),
            new ProcSample(103, "fg.exe", 0, 300 << 20),
            new ProcSample(104, "exempt.exe", 0, 300 << 20),
            new ProcSample(4, "system", 0, 500 << 20)), foregroundPid: 103, On, T0);

        Assert.Equal(101, Assert.Single(targets).Pid);
    }

    [Fact]
    public void Respects_interval_and_per_process_cooldown()
    {
        var engine = Engine();
        var proc = new ProcSample(101, "big.exe", 0, 200 << 20);

        Assert.Single(engine.Tick(Snap(T0, proc), null, On, T0));
        // Next pass before the interval: nothing.
        Assert.Empty(engine.Tick(Snap(T0.AddMinutes(1), proc), null, On, T0.AddMinutes(1)));
        // After the interval but within the process cooldown: pass runs, process skipped.
        Assert.Empty(engine.Tick(Snap(T0.AddMinutes(6), proc), null, On, T0.AddMinutes(6)));
        // After the cooldown: trimmed again.
        Assert.Single(engine.Tick(Snap(T0.AddMinutes(16), proc), null, On, T0.AddMinutes(16)));
    }

    [Fact]
    public void Disabled_selects_nothing()
    {
        var engine = Engine();

        Assert.Empty(engine.Tick(Snap(T0, new ProcSample(101, "big.exe", 0, 1L << 30)),
            null, On with { Enabled = false }, T0));
    }
}

public class PowerCfgParserTests
{
    [Fact]
    public void Parses_guid_from_duplicatescheme_output()
    {
        const string output = "Power Scheme GUID: 12345678-abcd-ef01-2345-6789abcdef01  (Nexus Performance)";

        Assert.Equal("12345678-abcd-ef01-2345-6789abcdef01", PowerCfgParser.ParseFirstGuid(output));
    }

    [Fact]
    public void Parses_localized_output_by_guid_only()
    {
        const string output = "GUID du mode de gestion : E9A42B02-D5DF-448D-AA00-03F14749EB61  (Performances ultimes)";

        Assert.Equal(PowerSchemes.UltimatePerformance, PowerCfgParser.ParseFirstGuid(output));
    }

    [Fact]
    public void Parses_scheme_list()
    {
        const string output = """
            Existing Power Schemes (* Active)
            -----------------------------------
            Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced) *
            Power Scheme GUID: a1841308-3541-4fab-bc81-f71556f20b4a  (Power saver)
            """;

        var schemes = PowerCfgParser.ParseSchemeList(output);

        Assert.Equal(2, schemes.Count);
        Assert.Equal(PowerSchemes.Balanced, schemes[0].Guid);
        Assert.Equal(PowerSchemes.PowerSaver, schemes[1].Guid);
    }

    [Fact]
    public void No_guid_returns_null()
    {
        Assert.Null(PowerCfgParser.ParseFirstGuid("Invalid parameter"));
    }
}
