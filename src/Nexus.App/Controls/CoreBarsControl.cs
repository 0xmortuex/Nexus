using System.Windows;
using System.Windows.Media;
using Brush = System.Windows.Media.Brush;
using Brushes = System.Windows.Media.Brushes;
using Color = System.Windows.Media.Color;

namespace Nexus.App.Controls;

/// <summary>One vertical bar per logical CPU, 0–100 %. P-cores and E-cores are
/// tinted differently when a hybrid mask is provided.</summary>
public sealed class CoreBarsControl : FrameworkElement
{
    public static readonly DependencyProperty ValuesProperty = DependencyProperty.Register(
        nameof(Values), typeof(IReadOnlyList<double>), typeof(CoreBarsControl),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ECoreMaskProperty = DependencyProperty.Register(
        nameof(ECoreMask), typeof(ulong), typeof(CoreBarsControl),
        new FrameworkPropertyMetadata(0UL, FrameworkPropertyMetadataOptions.AffectsRender));

    public IReadOnlyList<double>? Values
    {
        get => (IReadOnlyList<double>?)GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
    }

    /// <summary>Bit i set → logical CPU i is an E-core (different tint).</summary>
    public ulong ECoreMask
    {
        get => (ulong)GetValue(ECoreMaskProperty);
        set => SetValue(ECoreMaskProperty, value);
    }

    private static readonly Brush PBrush = Freeze(new SolidColorBrush(Color.FromRgb(0x4F, 0x8C, 0xFF)));
    private static readonly Brush EBrush = Freeze(new SolidColorBrush(Color.FromRgb(0x39, 0xC9, 0x82)));
    private static readonly Brush TrackBrush = Freeze(new SolidColorBrush(Color.FromArgb(40, 0, 0, 0)));

    private static Brush Freeze(Brush brush)
    {
        brush.Freeze();
        return brush;
    }

    protected override void OnRender(DrawingContext context)
    {
        var values = Values;
        if (values is null || values.Count == 0 || ActualWidth < 4 || ActualHeight < 4)
            return;

        double gap = 2;
        double barWidth = Math.Max(2, (ActualWidth - gap * (values.Count - 1)) / values.Count);

        for (int i = 0; i < values.Count; i++)
        {
            double x = i * (barWidth + gap);
            if (x + barWidth > ActualWidth + 0.5)
                break;

            context.DrawRectangle(TrackBrush, null, new Rect(x, 0, barWidth, ActualHeight));

            double height = Math.Clamp(values[i], 0, 100) / 100 * ActualHeight;
            var brush = i < 64 && (ECoreMask & (1UL << i)) != 0 ? EBrush : PBrush;
            context.DrawRectangle(brush, null, new Rect(x, ActualHeight - height, barWidth, height));
        }
    }
}
