using System.IO;
using Microsoft.Win32;
using Nexus.Core.Logging;

namespace Nexus.App.Services.Security;

/// <summary>
/// The "Scan with Nexus" entry in the right-click menu.
///
/// Everything here is written under HKEY_CURRENT_USER, never HKEY_LOCAL_MACHINE.
/// That means it needs no administrator rights, it affects only the person who asked
/// for it, and removing it cannot break the machine for anyone else. A context-menu
/// entry is not worth a system-wide change.
///
/// It is off until the user turns it on, and turning it off removes every key this
/// class created. A tool that leaves things behind after being told to stop is a
/// tool people stop trusting.
/// </summary>
public sealed class ShellIntegrationService
{
    /// <summary>Our key name under each file class. Distinctive so removal cannot
    /// touch anything that is not ours.</summary>
    private const string KeyName = "Nexus.ScanWithNexus";

    private const string MenuText = "Scan with Nexus";

    /// <summary>
    /// Where the entry appears: every file, every folder, and every drive. Those are
    /// the three the user would expect to be able to right-click.
    /// </summary>
    private static readonly string[] Classes = ["*", "Directory", "Drive"];

    private readonly ActivityLog _log;
    private readonly string _executablePath;

    public ShellIntegrationService(ActivityLog log, string executablePath)
    {
        _log = log;
        _executablePath = executablePath;
    }

    private static string PathFor(string className) => $@"Software\Classes\{className}\shell\{KeyName}";

    /// <summary>True when the entry is present for every class it should cover.</summary>
    public bool IsRegistered
    {
        get
        {
            try
            {
                foreach (var className in Classes)
                {
                    using var key = Registry.CurrentUser.OpenSubKey(PathFor(className));
                    if (key is null)
                        return false;
                }

                return true;
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
            {
                return false;
            }
        }
    }

    /// <summary>Add the menu entry. Returns a sentence for the UI; never throws.</summary>
    public string Register()
    {
        if (!File.Exists(_executablePath))
        {
            return "Could not find the Nexus program file, so the menu entry was not added.";
        }

        try
        {
            foreach (var className in Classes)
            {
                using var key = Registry.CurrentUser.CreateSubKey(PathFor(className));
                key.SetValue(null, MenuText);
                key.SetValue("Icon", _executablePath);

                using var command = key.CreateSubKey("command");

                // %1 must stay quoted: without the quotes a path containing a space
                // arrives as several arguments and the scan silently targets the
                // wrong thing, or nothing.
                command.SetValue(null, $"\"{_executablePath}\" --scan \"%1\"");
            }

            _log.Info("Sentinel", "Added \"Scan with Nexus\" to the right-click menu for this user.");
            return "\"Scan with Nexus\" is now in your right-click menu for files, folders and drives.";
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            _log.Warn("Sentinel", $"Could not add the right-click entry: {ex.Message}");
            return $"Could not add the menu entry: {ex.Message}";
        }
    }

    /// <summary>Remove every key this class created, and nothing else.</summary>
    public string Unregister()
    {
        int removed = 0;

        foreach (var className in Classes)
        {
            try
            {
                using var shell = Registry.CurrentUser.OpenSubKey(
                    $@"Software\Classes\{className}\shell", writable: true);

                if (shell?.OpenSubKey(KeyName) is null)
                    continue;

                shell.DeleteSubKeyTree(KeyName);
                removed++;
            }
            catch (Exception ex) when (ex is System.Security.SecurityException
                                          or UnauthorizedAccessException or IOException or ArgumentException)
            {
                _log.Warn("Sentinel", $"Could not remove the right-click entry for {className}: {ex.Message}");
            }
        }

        if (removed > 0)
            _log.Info("Sentinel", "Removed \"Scan with Nexus\" from the right-click menu.");

        return removed > 0
            ? "\"Scan with Nexus\" has been taken out of your right-click menu."
            : "The right-click entry was not there.";
    }
}
