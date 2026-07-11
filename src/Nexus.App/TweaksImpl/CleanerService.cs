using System.IO;
using Nexus.Core.Logging;
using Nexus.Core.Tweaks;

namespace Nexus.App.TweaksImpl;

public sealed record CleanPreviewEntry(CleanTarget Target, long SizeBytes, int FileCount);

/// <summary>
/// Two-phase cache cleaner: ScanAsync sizes each target for a preview, the UI
/// confirms, DeleteAsync removes only what was scanned. Every path is re-validated
/// against the target roots before deletion; files in use are simply skipped.
/// </summary>
public sealed class CleanerService
{
    private readonly ActivityLog _log;
    private readonly IReadOnlyList<CleanTarget> _targets;

    public CleanerService(ActivityLog log)
        : this(log, CleanerTargets.Build(
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)))
    {
    }

    public CleanerService(ActivityLog log, IReadOnlyList<CleanTarget> targets)
    {
        _log = log;
        _targets = targets;
    }

    public IReadOnlyList<CleanTarget> Targets => _targets;

    public Task<IReadOnlyList<CleanPreviewEntry>> ScanAsync() => Task.Run<IReadOnlyList<CleanPreviewEntry>>(() =>
    {
        var preview = new List<CleanPreviewEntry>();
        foreach (var target in _targets)
        {
            long size = 0;
            int count = 0;
            foreach (var file in EnumerateFiles(target))
            {
                try
                {
                    size += new FileInfo(file).Length;
                    count++;
                }
                catch (Exception)
                {
                    // Race with deletion/permissions — skip.
                }
            }
            preview.Add(new CleanPreviewEntry(target, size, count));
        }
        return preview;
    });

    public Task<long> DeleteAsync(IReadOnlyCollection<string> targetIds) => Task.Run(() =>
    {
        long freed = 0;
        foreach (var target in _targets.Where(t => targetIds.Contains(t.Id)))
        {
            long targetFreed = 0;
            int skipped = 0;
            foreach (var file in EnumerateFiles(target))
            {
                // Safety: never delete anything that isn't truly under a target root.
                if (!CleanerTargets.IsSafeToDelete(file, target.Directories))
                    continue;

                try
                {
                    var info = new FileInfo(file);
                    var length = info.Length;
                    info.Attributes = FileAttributes.Normal;
                    info.Delete();
                    targetFreed += length;
                }
                catch (Exception)
                {
                    skipped++; // in use / access denied — normal for temp dirs
                }
            }

            // Remove now-empty subdirectories, best effort.
            foreach (var dir in target.Directories.Where(Directory.Exists))
            {
                foreach (var sub in Directory.EnumerateDirectories(dir, "*", SearchOption.AllDirectories)
                             .OrderByDescending(d => d.Length))
                {
                    try
                    {
                        if (!Directory.EnumerateFileSystemEntries(sub).Any())
                            Directory.Delete(sub);
                    }
                    catch (Exception)
                    {
                    }
                }
            }

            freed += targetFreed;
            _log.Info("Cleaner",
                $"{target.Name}: freed {targetFreed / (1024 * 1024)} MB{(skipped > 0 ? $", {skipped} in-use files skipped" : "")}.");
        }
        return freed;
    });

    private static IEnumerable<string> EnumerateFiles(CleanTarget target)
    {
        foreach (var dir in target.Directories)
        {
            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, target.FilePattern ?? "*", new EnumerationOptions
                {
                    RecurseSubdirectories = target.FilePattern is null,
                    IgnoreInaccessible = true,
                    AttributesToSkip = FileAttributes.ReparsePoint, // don't follow junctions out
                });
            }
            catch (Exception)
            {
                continue;
            }

            foreach (var file in files)
                yield return file;
        }
    }
}
