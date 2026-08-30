using System.ComponentModel;
using System.Windows;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using Nexus.App.ViewModels;

namespace Nexus.App;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;
    private readonly DispatcherTimer _timer;
    private int _tick;

    /// <summary>Set false only when the user chooses Exit from the tray.</summary>
    public bool MinimizeToTrayOnClose { get; set; } = true;

    /// <summary>Bring the Security tab forward — used when a right-click scan
    /// arrives, so the answer appears where the user is looking.</summary>
    public void ShowSecurityTab() => Tabs.SelectedItem = SecurityTab;

    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = viewModel;

        _timer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromSeconds(1),
        };
        _timer.Tick += (_, _) => Refresh();
        _timer.Start();

        // Leaving Advanced mode may hide the current tab; fall back to Dashboard so
        // the pane never goes blank.
        _viewModel.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(MainViewModel.IsAdvanced) && !_viewModel.IsAdvanced)
                Tabs.SelectedIndex = 0;
        };

        _viewModel.Tweaks.RefreshStartup();

        // Boot reveal: the whole shell fades and rises in as it powers on.
        Loaded += (_, _) =>
        {
            var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
            Root.BeginAnimation(OpacityProperty,
                new DoubleAnimation(0, 1, new Duration(TimeSpan.FromMilliseconds(420))) { EasingFunction = ease });
            RootShift.BeginAnimation(System.Windows.Media.TranslateTransform.YProperty,
                new DoubleAnimation(16, 0, new Duration(TimeSpan.FromMilliseconds(520))) { EasingFunction = ease });
        };

        // Gentle cross-fade whenever the active tab changes.
        Tabs.SelectionChanged += (s, e) =>
        {
            if (!ReferenceEquals(e.OriginalSource, Tabs))
                return; // ignore selection bubbling up from inner ListViews/ComboBoxes
            if (Tabs.SelectedContent is UIElement content)
                content.BeginAnimation(OpacityProperty,
                    new DoubleAnimation(0.3, 1, new Duration(TimeSpan.FromMilliseconds(220))));
        };
    }

    private void Refresh()
    {
        if (!IsVisible)
            return;

        _tick++;
        _viewModel.Dashboard.Refresh();
        if (_tick % 2 == 0)
            _viewModel.Processes.Refresh();
        if (_tick % 10 == 0)
            _viewModel.Dashboard.RefreshRating(); // rating changes rarely; recompute occasionally
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (MinimizeToTrayOnClose)
        {
            // Keep the optimizer engines running; the window is just a viewport.
            e.Cancel = true;
            Hide();
            return;
        }
        base.OnClosing(e);
    }
}
