namespace Nexus.Core;

/// <summary>
/// Lets exactly one operation be in flight at a time, and says so honestly to
/// everyone else.
///
/// The obvious version of this is a nullable field with a null check in front of it,
/// and the obvious version is wrong: two callers can both pass the check before
/// either assigns. Nexus has that exact shape in more than one place — a timer and a
/// button both able to start the same background job — so the guard lives here, with
/// tests, rather than being re-improvised per service.
///
/// <see cref="TryEnter"/> is the only way in. A caller that gets false must do
/// nothing at all, and the caller that gets true must call <see cref="Exit"/> in a
/// finally block, or the gate stays shut for the rest of the process's life.
/// </summary>
public sealed class SingleFlightGate
{
    private int _busy;

    /// <summary>True while an operation holds the gate.</summary>
    public bool IsBusy => Volatile.Read(ref _busy) != 0;

    /// <summary>
    /// Take the gate if it is free. Returns false — meaning "someone else is already
    /// doing this, do nothing" — otherwise.
    /// </summary>
    public bool TryEnter() => Interlocked.CompareExchange(ref _busy, 1, 0) == 0;

    /// <summary>Release the gate. Safe to call when not held.</summary>
    public void Exit() => Volatile.Write(ref _busy, 0);
}
