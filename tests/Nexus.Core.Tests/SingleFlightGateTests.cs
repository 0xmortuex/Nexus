using Nexus.Core;
using Xunit;

namespace Nexus.Core.Tests;

public class SingleFlightGateTests
{
    [Fact]
    public void A_free_gate_lets_one_caller_in()
    {
        var gate = new SingleFlightGate();

        Assert.True(gate.TryEnter());
        Assert.True(gate.IsBusy);
    }

    [Fact]
    public void A_held_gate_turns_everyone_else_away()
    {
        var gate = new SingleFlightGate();
        gate.TryEnter();

        Assert.False(gate.TryEnter());
        Assert.False(gate.TryEnter());
    }

    [Fact]
    public void Exiting_reopens_the_gate()
    {
        var gate = new SingleFlightGate();
        gate.TryEnter();
        gate.Exit();

        Assert.False(gate.IsBusy);
        Assert.True(gate.TryEnter());
    }

    [Fact]
    public void Exiting_a_gate_nobody_holds_is_harmless()
    {
        var gate = new SingleFlightGate();
        gate.Exit();

        Assert.True(gate.TryEnter());
    }

    /// <summary>
    /// The whole reason this type exists. A plain null check plus assignment lets two
    /// threads through, which is exactly the bug this replaces.
    /// </summary>
    [Fact]
    public void Only_one_of_many_concurrent_callers_gets_in()
    {
        var gate = new SingleFlightGate();
        int admitted = 0;

        Parallel.For(0, 256, _ =>
        {
            if (gate.TryEnter())
                Interlocked.Increment(ref admitted);
        });

        Assert.Equal(1, admitted);
    }

    [Fact]
    public void Repeated_enter_and_exit_cycles_admit_exactly_one_each_time()
    {
        var gate = new SingleFlightGate();
        int admitted = 0;

        for (int round = 0; round < 50; round++)
        {
            int thisRound = 0;

            Parallel.For(0, 32, _ =>
            {
                if (gate.TryEnter())
                {
                    Interlocked.Increment(ref thisRound);
                    Interlocked.Increment(ref admitted);
                }
            });

            Assert.Equal(1, thisRound);
            gate.Exit();
        }

        Assert.Equal(50, admitted);
    }
}
