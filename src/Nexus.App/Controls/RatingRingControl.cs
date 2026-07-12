using System.Globalization;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Animation;
using Brush = System.Windows.Media.Brush;
using Color = System.Windows.Media.Color;

namespace Nexus.App.Controls;

/// <summary>
/// The dashboard hero: a circular gauge whose accent arc sweeps to the system
/// rating while the score counts up and the grade sits in the middle. Setting
/// <see cref="Score"/> animates <see cref="Progress"/> with an ease-out, so the
/// number and the arc rise together (0→82 on first load, and smoothly on refresh).
/// </summary>
public sealed class RatingRingControl : FrameworkElement
{
    public static readonly DependencyProperty ScoreProperty = DependencyProperty.Register(
        nameof(Score), typeof(double), typeof(RatingRingControl),
        new FrameworkPropertyMetadata(0.0, OnScoreChanged));

    /// <summary>The animated value actually drawn (0–100). Driven by the animation.</summary>
    private static readonly DependencyProperty ProgressProperty = DependencyProperty.Register(
        nameof(Progress), typeof(double), typeof(RatingRingControl),
        new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty GradeProperty = DependencyProperty.Register(
        nameof(Grade), typeof(string), typeof(RatingRingControl),
        new FrameworkPropertyMetadata("—", FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty AccentProperty = DependencyProperty.Register(
        nameof(Accent), typeof(Brush), typeof(RatingRingControl),
        new FrameworkPropertyMetadata(new SolidColorBrush(Color.FromRgb(0x4F, 0x8C, 0xFF)),
            FrameworkPropertyMetadataOptions.AffectsRender));

    public double Score
    {
        get => (double)GetValue(ScoreProperty);
        set => SetValue(ScoreProperty, value);
    }

    private double Progress => (double)GetValue(ProgressProperty);

    public string Grade
    {
        get => (string)GetValue(GradeProperty);
        set => SetValue(GradeProperty, value);
    }

    public Brush Accent
    {
        get => (Brush)GetValue(AccentProperty);
        set => SetValue(AccentProperty, value);
    }

    private static void OnScoreChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        var control = (RatingRingControl)d;
        var from = control.Progress;
        var to = Math.Clamp((double)e.NewValue, 0, 100);
        var anim = new DoubleAnimation(from, to, new Duration(TimeSpan.FromMilliseconds(950)))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut },
        };
        control.BeginAnimation(ProgressProperty, anim);
    }

    protected override void OnRender(DrawingContext context)
    {
        double size = Math.Min(ActualWidth, ActualHeight);
        if (size < 8)
            return;

        var center = new Point(ActualWidth / 2, ActualHeight / 2);
        double thickness = Math.Max(4, size * 0.09);
        double radius = size / 2 - thickness / 2 - 1;
        var accentColor = Accent is SolidColorBrush b ? b.Color : Color.FromRgb(0x4F, 0x8C, 0xFF);

        // Track ring.
        var track = new Pen(new SolidColorBrush(Color.FromArgb(38, 255, 255, 255)), thickness);
        track.Freeze();
        context.DrawEllipse(null, track, center, radius, radius);

        // Progress arc from 12 o'clock, clockwise.
        double fraction = Math.Clamp(Progress / 100.0, 0, 1);
        if (fraction > 0.0001)
        {
            double sweep = fraction * 360.0;
            var start = PointOnCircle(center, radius, -90);
            var end = PointOnCircle(center, radius, -90 + sweep);
            var arc = new StreamGeometry();
            using (var geo = arc.Open())
            {
                geo.BeginFigure(start, isFilled: false, isClosed: false);
                geo.ArcTo(end, new Size(radius, radius), 0, sweep > 180,
                    SweepDirection.Clockwise, isStroked: true, isSmoothJoin: true);
            }
            arc.Freeze();

            // Soft glow underlay + crisp arc.
            var glowPen = new Pen(new SolidColorBrush(Color.FromArgb(70, accentColor.R, accentColor.G, accentColor.B)),
                thickness + 6) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
            glowPen.Freeze();
            context.DrawGeometry(null, glowPen, arc);

            var arcPen = new Pen(Accent, thickness) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
            arcPen.Freeze();
            context.DrawGeometry(null, arcPen, arc);
        }

        // Centre: grade (big) + live score count.
        var gradeText = new FormattedText(Grade, CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
            new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.Bold, FontStretches.Normal),
            size * 0.34, Accent, VisualTreeHelper.GetDpi(this).PixelsPerDip);
        context.DrawText(gradeText, new Point(center.X - gradeText.Width / 2, center.Y - gradeText.Height * 0.72));

        var scoreText = new FormattedText($"{Progress:0} / 100", CultureInfo.InvariantCulture, FlowDirection.LeftToRight,
            new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal),
            size * 0.11, new SolidColorBrush(Color.FromRgb(0x9A, 0xA3, 0xB2)), VisualTreeHelper.GetDpi(this).PixelsPerDip);
        context.DrawText(scoreText, new Point(center.X - scoreText.Width / 2, center.Y + gradeText.Height * 0.10));
    }

    private static Point PointOnCircle(Point center, double radius, double angleDegrees)
    {
        double r = angleDegrees * Math.PI / 180.0;
        return new Point(center.X + radius * Math.Cos(r), center.Y + radius * Math.Sin(r));
    }
}
