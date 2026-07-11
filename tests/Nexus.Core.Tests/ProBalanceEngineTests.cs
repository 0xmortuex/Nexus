using Nexus.Core.Models;
using Nexus.Core.ProBalance;
using Xunit;

namespace Nexus.Core.Tests;

public class ProBalanceEngineTests
{
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static ProBalanceOptions FastOptions => new()
    {
        SystemLoadEnterPct = 85,
        SystemLoadExitPct = 70,
        SustainMs = 2000,
        ReleaseMs = 3000,
        MinRestraintMs = 5000,
        ProcessCpuThresholdPct = 25,
        ProcessSustainMs = 0,
        MaxRestrainedProcesses = 5,
    };

    private static SystemSnapshot Snap(DateTimeOffset at, double totalCpu, params ProcSample[] procs)
        => new(at, totalCpu, [totalCpu], procs, 8L << 30, 16L << 30);

    private static ProcSample Hog(int pid = 100, string name = "encoder.exe", double cpu = 60)
        => new(pid, name, cpu, 500 << 20);

    /// <summary>Engine with the built-in exemptions replaced by "nothing exempt except 'exempt.exe'".</summary>
    private static ProBalanceEngine Engine(ProBalanceOptions? options = null)
        => new(options ?? FastOptions, name => name == "exempt.exe");

    [Fact]
    public void No_restraint_before_sustain_window_elapses()
    {
        var engine = Engine();

        Assert.Empty(engine.Tick(Snap(T0, 95, Hog()), null, T0));
        Assert.Empty(engine.Tick(Snap(T0.AddSeconds(1), 95, Hog()), null, T0.AddSeconds(1)));
    }

    [Fact]
    public void Sustained_high_load_restrains_the_background_hog()
    {
        var engine = Engine();

        engine.Tick(Snap(T0, 95, Hog()), null, T0);
        var actions = engine.Tick(Snap(T0.AddSeconds(2), 95, Hog()), null, T0.AddSeconds(2));

        var restrain = Assert.IsType<RestrainAction>(Assert.Single(actions));
        Assert.Equal(100, restrain.Pid);
        Assert.Contains(100, engine.RestrainedPids);
    }

    [Fact]
    public void Brief_spike_does_not_restrain()
    {
        var engine = Engine();

        engine.Tick(Snap(T0, 95, Hog()), null, T0);
        // Load dips below the enter threshold before the sustain window is up.
        Assert.Empty(engine.Tick(Snap(T0.AddSeconds(1), 60, Hog()), null, T0.AddSeconds(1)));
        // High again — the sustain clock must restart, so nothing happens yet.
        Assert.Empty(engine.Tick(Snap(T0.AddSeconds(2), 95, Hog()), null, T0.AddSeconds(2)));
        Assert.Empty(engine.Tick(Snap(T0.AddSeconds(3), 95, Hog()), null, T0.AddSeconds(3)));
        // Now the window has elapsed since the second rise.
        Assert.Single(engine.Tick(Snap(T0.AddSeconds(4), 95, Hog()), null, T0.AddSeconds(4)));
    }

    [Fact]
    public void Foreground_process_is_never_restrained()
    {
        var engine = Engine();

        engine.Tick(Snap(T0, 95, Hog()), foregroundPid: 100, T0);
        var actions = engine.Tick(Snap(T0.AddSeconds(3), 95, Hog()), foregroundPid: 100, T0.AddSeconds(3));

        Assert.Empty(actions);
    }

    [Fact]
    public void Exempt_and_user_excluded_processes_are_never_restrained()
    {
        var options = FastOptions with { UserExclusions = ["MyRender"] };
        var engine = Engine(options);
        var procs = new[] { Hog(100, "exempt.exe"), Hog(101, "myrender.exe"), Hog(102, "guilty.exe") };

        engine.Tick(Snap(T0, 95, procs), null, T0);
        var actions = engine.Tick(Snap(T0.AddSeconds(3), 95, procs), null, T0.AddSeconds(3));

        var restrain = Assert.IsType<RestrainAction>(Assert.Single(actions));
        Assert.Equal(102, restrain.Pid);
    }

    [Fact]
    public void Restrained_process_restores_when_it_becomes_foreground()
    {
        var engine = Engine();
        engine.Tick(Snap(T0, 95, Hog()), null, T0);
        engine.Tick(Snap(T0.AddSeconds(2), 95, Hog()), null, T0.AddSeconds(2));

        var actions = engine.Tick(Snap(T0.AddSeconds(3), 95, Hog()), foregroundPid: 100, T0.AddSeconds(3));

        var restore = Assert.IsType<RestoreAction>(Assert.Single(actions));
        Assert.Equal("became the foreground app", restore.Reason);
        Assert.Empty(engine.RestrainedPids);
    }

    [Fact]
    public void Restore_requires_calm_release_window_and_min_restraint_time()
    {
        var engine = Engine();
        engine.Tick(Snap(T0, 95, Hog()), null, T0);
        engine.Tick(Snap(T0.AddSeconds(2), 95, Hog()), null, T0.AddSeconds(2)); // restrained at +2 s

        // Calm immediately after, but neither ReleaseMs (3 s) nor MinRestraintMs (5 s since +2 s) is met.
        Assert.Empty(engine.Tick(Snap(T0.AddSeconds(3), 20, Hog(cpu: 5)), null, T0.AddSeconds(3)));
        Assert.Empty(engine.Tick(Snap(T0.AddSeconds(5), 20, Hog(cpu: 5)), null, T0.AddSeconds(5)));

        // +7 s: calm for 4 s (≥ ReleaseMs) and restrained for 5 s (≥ MinRestraintMs) → restore.
        var actions = engine.Tick(Snap(T0.AddSeconds(7), 20, Hog(cpu: 5)), null, T0.AddSeconds(7));

        var restore = Assert.IsType<RestoreAction>(Assert.Single(actions));
        Assert.False(restore.ProcessExited);
        Assert.Empty(engine.RestrainedPids);
    }

    [Fact]
    public void Exited_process_yields_forget_only_restore()
    {
        var engine = Engine();
        engine.Tick(Snap(T0, 95, Hog()), null, T0);
        engine.Tick(Snap(T0.AddSeconds(2), 95, Hog()), null, T0.AddSeconds(2));

        var actions = engine.Tick(Snap(T0.AddSeconds(3), 95), null, T0.AddSeconds(3));

        var restore = Assert.IsType<RestoreAction>(Assert.Single(actions));
        Assert.True(restore.ProcessExited);
    }

    [Fact]
    public void Per_process_sustain_window_filters_one_sample_spikes()
    {
        var engine = Engine(FastOptions with { ProcessSustainMs = 1500 });

        engine.Tick(Snap(T0, 95, Hog()), null, T0);
        // System pressure is established at +2 s, but the hog has only just re-appeared.
        engine.Tick(Snap(T0.AddSeconds(2), 95, Hog(cpu: 5)), null, T0.AddSeconds(2)); // resets hog clock
        Assert.Empty(engine.Tick(Snap(T0.AddSeconds(3), 95, Hog()), null, T0.AddSeconds(3)));
        Assert.Empty(engine.Tick(Snap(T0.AddSeconds(4), 95, Hog()), null, T0.AddSeconds(4)));

        Assert.Single(engine.Tick(Snap(T0.AddSeconds(5), 95, Hog()), null, T0.AddSeconds(5)));
    }

    [Fact]
    public void Restrained_count_is_capped()
    {
        var engine = Engine(FastOptions with { MaxRestrainedProcesses = 2 });
        var procs = Enumerable.Range(0, 6).Select(i => Hog(200 + i, $"hog{i}.exe")).ToArray();

        engine.Tick(Snap(T0, 95, procs), null, T0);
        var actions = engine.Tick(Snap(T0.AddSeconds(2), 95, procs), null, T0.AddSeconds(2));

        Assert.Equal(2, actions.OfType<RestrainAction>().Count());
        Assert.Equal(2, engine.RestrainedPids.Count);
    }

    [Fact]
    public void Disabling_mid_flight_restores_everything()
    {
        var engine = Engine();
        engine.Tick(Snap(T0, 95, Hog()), null, T0);
        engine.Tick(Snap(T0.AddSeconds(2), 95, Hog()), null, T0.AddSeconds(2));

        engine.Options = FastOptions with { Enabled = false };
        var actions = engine.Tick(Snap(T0.AddSeconds(3), 95, Hog()), null, T0.AddSeconds(3));

        Assert.IsType<RestoreAction>(Assert.Single(actions));
        Assert.Empty(engine.RestrainedPids);
    }

    [Fact]
    public void Oscillating_load_does_not_flap()
    {
        var engine = Engine();
        int transitions = 0;

        // 120 s of load oscillating every second between 90 % and 75 % (inside the
        // dead zone between exit=70 and enter=85 half the time). The sustain windows
        // must keep the engine from ever engaging.
        for (int s = 0; s < 120; s++)
        {
            double load = s % 2 == 0 ? 90 : 75;
            transitions += engine.Tick(Snap(T0.AddSeconds(s), load, Hog()), null, T0.AddSeconds(s)).Count;
        }

        Assert.Equal(0, transitions);
    }

    [Fact]
    public void Slow_oscillation_engages_but_stays_bounded()
    {
        var engine = Engine();
        var actionLog = new List<ProBalanceAction>();

        // 4 minutes alternating 30 s of full load with 30 s idle. With MinRestraintMs
        // and both sustain windows, each full cycle can produce at most one
        // restrain+restore pair for the single hog.
        for (int s = 0; s < 240; s++)
        {
            double load = (s / 30) % 2 == 0 ? 95 : 10;
            double hogCpu = load > 50 ? 60 : 2;
            actionLog.AddRange(engine.Tick(Snap(T0.AddSeconds(s), load, Hog(cpu: hogCpu)), null, T0.AddSeconds(s)));
        }

        int restrains = actionLog.OfType<RestrainAction>().Count();
        int restores = actionLog.OfType<RestoreAction>().Count();
        Assert.InRange(restrains, 1, 4);
        Assert.Equal(restrains, restores + engine.RestrainedPids.Count);
    }
}
