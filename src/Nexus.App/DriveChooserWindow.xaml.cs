using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using Nexus.App.Services.Security;

namespace Nexus.App;

/// <summary>One drive in the chooser, with its tick state.</summary>
public sealed class DriveChoice : INotifyPropertyChanged
{
    private bool _selected;

    public required SentinelService.ScannableDrive Drive { get; init; }

    public bool Selected
    {
        get => _selected;
        set
        {
            if (_selected == value)
                return;

            _selected = value;
            OnPropertyChanged();
            SelectionChanged?.Invoke();
        }
    }

    public string Display => Drive.Display;
    public string Kind => Drive.Kind;
    public string Size => Drive.Size;

    /// <summary>Raised so the window can keep its summary line current.</summary>
    public Action? SelectionChanged { get; set; }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>
/// Asks which drives to scan.
///
/// A full scan used to mean every fixed drive, decided for the user. On a machine
/// with a second disk full of games or backups that is a very different job from
/// scanning Windows, and it is not a choice the tool should be making silently.
///
/// Removable drives are offered here even though the scheduled scan skips them:
/// this list is one somebody picks from deliberately, and "check the stick I just
/// plugged in" is a reasonable thing to want.
/// </summary>
public partial class DriveChooserWindow : Window
{
    private readonly ObservableCollection<DriveChoice> _choices = [];

    public DriveChooserWindow(IReadOnlyList<SentinelService.ScannableDrive> drives, string? preselect)
    {
        InitializeComponent();

        foreach (var drive in drives)
        {
            var choice = new DriveChoice
            {
                Drive = drive,
                // The Windows drive is ticked by default: it is what people mean by
                // "scan my PC", and it is where anything that matters ends up.
                Selected = preselect is not null
                           && drive.Root.StartsWith(preselect, StringComparison.OrdinalIgnoreCase),
            };

            choice.SelectionChanged = UpdateSummary;
            _choices.Add(choice);
        }

        DriveList.ItemsSource = _choices;
        UpdateSummary();
    }

    /// <summary>The roots the user ticked. Empty when they cancelled.</summary>
    public IReadOnlyList<string> SelectedRoots { get; private set; } = [];

    private void UpdateSummary()
    {
        int count = _choices.Count(c => c.Selected);

        Summary.Text = count switch
        {
            0 => "Nothing selected.",
            1 => "1 drive selected.",
            _ => $"{count} drives selected.",
        };
    }

    private void OnStart(object sender, RoutedEventArgs e)
    {
        SelectedRoots = _choices.Where(c => c.Selected).Select(c => c.Drive.Root).ToArray();

        if (SelectedRoots.Count == 0)
        {
            MessageBox.Show(this, "Tick at least one drive first.", "Nexus",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        DialogResult = true;
    }

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;
}
