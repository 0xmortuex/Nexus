namespace Nexus.App.Services;

public sealed record ProcessEvent(int Pid, string ExeName);

/// <summary>Raises an event the moment a process starts or exits.</summary>
public interface IProcessWatcher : IDisposable
{
    event Action<ProcessEvent>? ProcessStarted;
    event Action<ProcessEvent>? ProcessStopped;

    /// <summary>Human-readable mechanism name for logging ("WMI", "polling").</summary>
    string Mechanism { get; }

    void Start();
}
