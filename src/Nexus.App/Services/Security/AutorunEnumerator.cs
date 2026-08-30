using System.Diagnostics;
using System.IO;
using System.Management;
using System.Text.Json;
using Microsoft.Win32;
using Nexus.App.Interop.Security;
using Nexus.Core.Logging;
using Nexus.Core.Security;
using Nexus.Core.Security.Persistence;

namespace Nexus.App.Services.Security;

/// <summary>
/// Enumerates every way something on this machine has arranged to run again.
///
/// Read-only, always. Nothing here disables, deletes or rewrites an entry — the
/// Startup tab already owns enable/disable, and mixing "audit" with "modify" in one
/// service is how an advisory tool quietly becomes an enforcing one.
///
/// Nexus's own entries are found and marked rather than filtered out, so its
/// footprint appears in its own audit.
/// </summary>
public sealed class AutorunEnumerator
{
    private const string RunKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string RunOnceKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
    private const string RunKeyWow = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    private const string IfeoRoot = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string WinlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string WindowsKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
    private const string ServicesKey = @"SYSTEM\CurrentControlSet\Services";

    private readonly ActivityLog _log;
    private readonly AuthenticodeVerifier _signatures;

    public AutorunEnumerator(ActivityLog log, AuthenticodeVerifier signatures)
    {
        _log = log;
        _signatures = signatures;
    }

    /// <summary>Collect the whole persistence surface. Each collector is independently
    /// guarded so one unreadable hive cannot abort the audit.</summary>
    public IReadOnlyList<AutorunEntry> EnumerateAll(CancellationToken cancellationToken = default)
    {
        var entries = new List<AutorunEntry>();

        Collect(entries, CollectRunKeys, "startup registry keys", cancellationToken);
        Collect(entries, CollectStartupFolders, "startup folders", cancellationToken);
        Collect(entries, CollectServices, "services", cancellationToken);
        Collect(entries, CollectIfeo, "image file execution options", cancellationToken);
        Collect(entries, CollectWinlogon, "Winlogon hooks", cancellationToken);
        Collect(entries, CollectAppInitDlls, "AppInit_DLLs", cancellationToken);
        Collect(entries, CollectWmiSubscriptions, "WMI subscriptions", cancellationToken);
        Collect(entries, CollectScheduledTasks, "scheduled tasks", cancellationToken);

        return entries;
    }

    private void Collect(
        List<AutorunEntry> entries,
        Func<CancellationToken, IEnumerable<AutorunEntry>> collector,
        string what,
        CancellationToken cancellationToken)
    {
        try
        {
            entries.AddRange(collector(cancellationToken));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.Warn("Sentinel", $"Could not read {what}: {ex.Message}");
        }
    }

    // ---- Registry Run keys ----

    private IEnumerable<AutorunEntry> CollectRunKeys(CancellationToken cancellationToken)
    {
        (RegistryKey Root, string Path, string Label)[] locations =
        [
            (Registry.LocalMachine, RunKey, @"HKLM\...\Run"),
            (Registry.LocalMachine, RunOnceKey, @"HKLM\...\RunOnce"),
            (Registry.LocalMachine, RunKeyWow, @"HKLM\...\WOW6432Node\Run"),
            (Registry.CurrentUser, RunKey, @"HKCU\...\Run"),
            (Registry.CurrentUser, RunOnceKey, @"HKCU\...\RunOnce"),
        ];

        foreach (var (root, path, label) in locations)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var key = root.OpenSubKey(path);
            if (key is null)
                continue;

            foreach (var name in key.GetValueNames())
            {
                if (key.GetValue(name) is not string command || command.Length == 0)
                    continue;

                yield return Describe(AutorunKind.RunKey, label, name, command);
            }
        }
    }

    // ---- Startup folders ----

    private IEnumerable<AutorunEntry> CollectStartupFolders(CancellationToken cancellationToken)
    {
        (Environment.SpecialFolder Folder, string Label)[] folders =
        [
            (Environment.SpecialFolder.Startup, "Startup folder (this user)"),
            (Environment.SpecialFolder.CommonStartup, "Startup folder (all users)"),
        ];

        foreach (var (folder, label) in folders)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var directory = Environment.GetFolderPath(folder);
            if (directory.Length == 0 || !Directory.Exists(directory))
                continue;

            foreach (var file in Directory.EnumerateFiles(directory))
            {
                if (Path.GetFileName(file).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase))
                    continue;

                yield return Describe(AutorunKind.StartupFolder, label, Path.GetFileName(file), file);
            }
        }
    }

    // ---- Services ----

    private IEnumerable<AutorunEntry> CollectServices(CancellationToken cancellationToken)
    {
        using var services = Registry.LocalMachine.OpenSubKey(ServicesKey);
        if (services is null)
            yield break;

        foreach (var name in services.GetSubKeyNames())
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var service = services.OpenSubKey(name);
            if (service is null)
                continue;

            // Start: 0 boot, 1 system, 2 automatic, 3 manual, 4 disabled.
            if (service.GetValue("Start") is not int start || start > 2)
                continue;

            if (service.GetValue("ImagePath") is not string imagePath || imagePath.Length == 0)
                continue;

            // Driver services live in the kernel and are out of scope for a
            // user-mode advisory scanner; reporting them would be noise it cannot
            // act on or explain well.
            if (service.GetValue("Type") is int type && (type & 0x3) != 0 && (type & 0x30) == 0)
                continue;

            yield return Describe(AutorunKind.Service, @"HKLM\...\Services", name,
                Environment.ExpandEnvironmentVariables(imagePath));
        }
    }

    // ---- Image File Execution Options ----

    private IEnumerable<AutorunEntry> CollectIfeo(CancellationToken cancellationToken)
    {
        using var root = Registry.LocalMachine.OpenSubKey(IfeoRoot);
        if (root is null)
            yield break;

        foreach (var name in root.GetSubKeyNames())
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var entry = root.OpenSubKey(name);
            if (entry is null)
                continue;

            // A Debugger value replaces the program entirely — the hijack case.
            if (entry.GetValue("Debugger") is string debugger && debugger.Length > 0)
            {
                yield return Describe(AutorunKind.Ifeo, IfeoRoot, name, debugger);
            }

            // PerfOptions is what Nexus itself writes: a launch-time priority, not a
            // replacement program. Reported so the user can see Nexus's own footprint.
            using var perfOptions = entry.OpenSubKey("PerfOptions");
            if (perfOptions?.GetValue("CpuPriorityClass") is not null)
            {
                yield return new AutorunEntry
                {
                    Kind = AutorunKind.Ifeo,
                    Location = IfeoRoot,
                    Name = name,
                    Command = "launch-time priority (PerfOptions)",
                    CreatedByNexus = true,
                };
            }
        }
    }

    // ---- Winlogon ----

    private IEnumerable<AutorunEntry> CollectWinlogon(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        using var key = Registry.LocalMachine.OpenSubKey(WinlogonKey);
        if (key is null)
            yield break;

        foreach (var valueName in new[] { "Shell", "Userinit" })
        {
            if (key.GetValue(valueName) is not string value || value.Length == 0)
                continue;

            yield return Describe(AutorunKind.WinlogonHook, WinlogonKey, valueName, value);
        }
    }

    // ---- AppInit_DLLs ----

    private IEnumerable<AutorunEntry> CollectAppInitDlls(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        using var key = Registry.LocalMachine.OpenSubKey(WindowsKey);
        if (key?.GetValue("AppInit_DLLs") is not string value || value.Trim().Length == 0)
            yield break;

        // Only meaningful when loading is actually enabled.
        if (key.GetValue("LoadAppInit_DLLs") is int load && load == 0)
            yield break;

        yield return Describe(AutorunKind.AppInitDll, WindowsKey, "AppInit_DLLs", value);
    }

    // ---- WMI permanent event subscriptions ----

    private IEnumerable<AutorunEntry> CollectWmiSubscriptions(CancellationToken cancellationToken)
    {
        var results = new List<AutorunEntry>();

        var scope = new ManagementScope(@"\\.\root\subscription");
        scope.Connect();

        foreach (var consumerClass in new[] { "CommandLineEventConsumer", "ActiveScriptEventConsumer" })
        {
            cancellationToken.ThrowIfCancellationRequested();

            using var searcher = new ManagementObjectSearcher(
                scope, new ObjectQuery($"SELECT * FROM {consumerClass}"));
            using var collection = searcher.Get();

            foreach (var item in collection)
            {
                using var consumer = (ManagementObject)item;

                var name = consumer["Name"] as string ?? "(unnamed)";
                var command = consumer["CommandLineTemplate"] as string
                              ?? consumer["ScriptText"] as string
                              ?? consumer["ExecutablePath"] as string
                              ?? "";

                results.Add(Describe(AutorunKind.WmiSubscription, @"root\subscription", name, command));
            }
        }

        return results;
    }

    // ---- Scheduled tasks ----

    /// <summary>Enumerated through PowerShell rather than schtasks, because schtasks'
    /// CSV output is localized and unparseable on a non-English Windows.</summary>
    private IEnumerable<AutorunEntry> CollectScheduledTasks(CancellationToken cancellationToken)
    {
        const string script =
            "Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object { " +
            "$a = $_.Actions | Select-Object -First 1; " +
            "[pscustomobject]@{ Name = $_.TaskName; Path = $_.TaskPath; " +
            "Execute = $a.Execute; Arguments = $a.Arguments } } | ConvertTo-Json -Compress";

        var output = RunPowerShell(script, cancellationToken);
        if (output is null || output.Trim().Length == 0)
            return [];

        var results = new List<AutorunEntry>();

        using var json = JsonDocument.Parse(output);
        var items = json.RootElement.ValueKind == JsonValueKind.Array
            ? json.RootElement.EnumerateArray().ToArray()
            : [json.RootElement];

        foreach (var item in items)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var name = Text(item, "Name");
            var taskPath = Text(item, "Path");
            var execute = Text(item, "Execute");
            if (name is null || execute is null || execute.Length == 0)
                continue;

            var arguments = Text(item, "Arguments") ?? "";
            var command = arguments.Length > 0 ? $"{execute} {arguments}" : execute;

            results.Add(Describe(
                AutorunKind.ScheduledTask,
                "Task Scheduler",
                (taskPath ?? "\\") + name,
                command,
                createdByNexus: name.Contains("Nexus", StringComparison.OrdinalIgnoreCase)));
        }

        return results;

        static string? Text(JsonElement element, string property) =>
            element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
    }

    private string? RunPowerShell(string script, CancellationToken cancellationToken)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"{script}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        });

        if (process is null)
            return null;

        var output = process.StandardOutput.ReadToEnd();

        if (!process.WaitForExit(60_000))
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
                // Already gone.
            }
            return null;
        }

        cancellationToken.ThrowIfCancellationRequested();
        return output;
    }

    // ---- Shared ----

    private AutorunEntry Describe(
        AutorunKind kind, string location, string name, string command, bool createdByNexus = false)
    {
        var imagePath = ExtractImagePath(command);
        bool signed = false;

        if (imagePath is not null)
        {
            var info = _signatures.Verify(imagePath);
            signed = info.State == SignatureState.Valid;
        }

        return new AutorunEntry
        {
            Kind = kind,
            Location = location,
            Name = name,
            Command = command,
            ImagePath = imagePath,
            SignedByTrustedPublisher = signed,
            CreatedByNexus = createdByNexus || IsNexusOwn(imagePath),
        };
    }

    private static bool IsNexusOwn(string? imagePath) =>
        imagePath is not null
        && Path.GetFileName(imagePath).Equals("Nexus.exe", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Pull the executable out of a command line, resolving unquoted paths the way
    /// the loader does. The parsing itself lives in
    /// <see cref="ScanTargeting.ExtractImagePath"/> in Core, where it is tested
    /// against the unquoted service path hijack it exists to expose.
    /// </summary>
    public static string? ExtractImagePath(string command) =>
        ScanTargeting.ExtractImagePath(
            Environment.ExpandEnvironmentVariables(command), File.Exists);
}
