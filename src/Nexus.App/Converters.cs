using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace Nexus.App;

/// <summary>
/// Renders a bool as "On" / "OFF" for the security status list.
///
/// Uppercase on the negative deliberately: the whole point of that panel is that a
/// component which failed to start should be hard to skim past, and lower-case "off"
/// reads as a setting rather than a problem.
/// </summary>
public sealed class BoolToOnOffConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object? parameter, CultureInfo culture)
        => value is true ? "On" : "OFF";

    public object ConvertBack(object value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>Visible when the bound bool is false (used for Next vs Finish).</summary>
public sealed class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object? parameter, CultureInfo culture)
        => value is true ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object? parameter, CultureInfo culture)
        => value is Visibility.Collapsed;
}

/// <summary>Visible when the bound integer count is zero (empty-state messages).</summary>
public sealed class ZeroToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object? parameter, CultureInfo culture)
        => value is int n && n == 0 ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object? parameter, CultureInfo culture)
        => Binding.DoNothing;
}

/// <summary>Given a filled-bar count and a bar index (ConverterParameter, 1-based),
/// returns the accent brush if that bar is filled, otherwise a faint track brush.</summary>
public sealed class BarsToBrushConverter : IValueConverter
{
    private static readonly Brush On = new SolidColorBrush(Color.FromRgb(0x4F, 0x8C, 0xFF));
    private static readonly Brush Off = new SolidColorBrush(Color.FromArgb(0x40, 0xFF, 0xFF, 0xFF));

    static BarsToBrushConverter()
    {
        On.Freeze();
        Off.Freeze();
    }

    public object Convert(object value, Type targetType, object? parameter, CultureInfo culture)
    {
        int bars = value is int b ? b : 0;
        int index = parameter is string s && int.TryParse(s, out var i) ? i : 1;
        return bars >= index ? On : Off;
    }

    public object ConvertBack(object value, Type targetType, object? parameter, CultureInfo culture)
        => Binding.DoNothing;
}
