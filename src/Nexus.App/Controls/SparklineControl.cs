using System.Windows;
using System.Windows.Media;
using Brush = System.Windows.Media.Brush;
using Brushes = System.Windows.Media.Brushes;
using Color = System.Windows.Media.Color;

namespace Nexus.App.Controls;

/// <summary>
/// Minimal line chart for a rolling series of 0–100 samples. Custom OnRender
/// drawing — no charting dependency, renders a 60-point series in microseconds.
/// </summary>
public sealed class SparklineControl : FrameworkElement
{
    public static readonly DependencyProperty ValuesProperty = DependencyProperty.Register(
        nameof(Values), typeof(IReadOnlyList<double>), typeof(SparklineControl),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty StrokeProperty = DependencyProperty.Register(
        nameof(Stroke), typeof(Brush), typeof(SparklineControl),
        new FrameworkPropertyMetadata(Brushes.DodgerBlue, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty MaximumProperty = DependencyProperty.Register(
        nameof(Maximum), typeof(double), typeof(SparklineControl),
        new FrameworkPropertyMetadata(100.0, FrameworkPropertyMetadataOptions.AffectsRender));

    public IReadOnlyList<double>? Values
    {
        get => (IReadOnlyList<double>?)GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
    }

    public Brush Stroke
    {
        get => (Brush)GetValue(StrokeProperty);
        set => SetValue(StrokeProperty, value);
    }

    public double Maximum
    {
        get => (double)GetValue(MaximumProperty);
        set => SetValue(MaximumProperty, value);
    }

    protected override void OnRender(DrawingContext context)
    {
        var bounds = new Rect(0, 0, ActualWidth, ActualHeight);
        context.DrawRectangle(new SolidColorBrush(Color.FromArgb(40, 0, 0, 0)), null, bounds);

        var values = Values;
        if (values is null || values.Count < 2 || ActualWidth < 4 || ActualHeight < 4)
            return;

        double max = Maximum <= 0 ? 100 : Maximum;
        double stepX = ActualWidth / (values.Count - 1);

        Point At(int i)
        {
            double clamped = Math.Clamp(values[i], 0, max);
            return new Point(i * stepX, ActualHeight - clamped / max * (ActualHeight - 2) - 1);
        }

        var fill = new StreamGeometry();
        using (var geo = fill.Open())
        {
            geo.BeginFigure(new Point(0, ActualHeight), isFilled: true, isClosed: true);
            for (int i = 0; i < values.Count; i++)
                geo.LineTo(At(i), false, false);
            geo.LineTo(new Point(ActualWidth, ActualHeight), false, false);
        }
        fill.Freeze();

        var fillBrush = Stroke.Clone();
        fillBrush.Opacity = 0.18;
        fillBrush.Freeze();
        context.DrawGeometry(fillBrush, null, fill);

        var line = new StreamGeometry();
        using (var geo = line.Open())
        {
            geo.BeginFigure(At(0), isFilled: false, isClosed: false);
            for (int i = 1; i < values.Count; i++)
                geo.LineTo(At(i), true, true);
        }
        line.Freeze();

        var pen = new Pen(Stroke, 1.6);
        pen.Freeze();
        context.DrawGeometry(null, pen, line);

        // Glowing leading dot at the newest sample — the "alive" endpoint.
        var last = At(values.Count - 1);
        if (Stroke is SolidColorBrush sb)
        {
            var c = sb.Color;
            var glowFar = new SolidColorBrush(Color.FromArgb(40, c.R, c.G, c.B));
            var glowNear = new SolidColorBrush(Color.FromArgb(90, c.R, c.G, c.B));
            glowFar.Freeze();
            glowNear.Freeze();
            context.DrawEllipse(glowFar, null, last, 7 * _pulse, 7 * _pulse);
            context.DrawEllipse(glowNear, null, last, 4, 4);
        }
        context.DrawEllipse(Stroke, null, last, 2.4, 2.4);
    }

    // Gentle breathing pulse for the endpoint glow, driven by the render clock.
    private double _pulse = 1.0;

    public SparklineControl()
    {
        var pulse = new System.Windows.Media.Animation.DoubleAnimation(0.8, 1.25,
            new Duration(TimeSpan.FromMilliseconds(1400)))
        {
            AutoReverse = true,
            RepeatBehavior = System.Windows.Media.Animation.RepeatBehavior.Forever,
        };
        var clock = pulse.CreateClock();
        ApplyAnimationClock(PulseProperty, clock);
    }

    private static readonly DependencyProperty PulseProperty = DependencyProperty.Register(
        nameof(_pulse), typeof(double), typeof(SparklineControl),
        new FrameworkPropertyMetadata(1.0, FrameworkPropertyMetadataOptions.AffectsRender,
            (d, e) => ((SparklineControl)d)._pulse = (double)e.NewValue));
}
