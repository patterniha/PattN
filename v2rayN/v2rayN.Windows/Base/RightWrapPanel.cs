using System.Windows.Controls;

namespace v2rayN.Base;

/// <summary>
/// PattN: lays its children out from left to right in their order, starting a new line where the next one does not
/// fit, as a horizontal WrapPanel does, but puts every line at the right edge, <see cref="LineSpacing" /> apart, as the
/// Avalonia twin's WrapPanel does with ItemsAlignment="End" and LineSpacing; WPF's WrapPanel starts every line at the
/// left and has no spacing. For the buttons of <see cref="Views.ChoiceDialog" />, which a long translation wraps.
/// </summary>
public class RightWrapPanel : Panel
{
    public static readonly DependencyProperty LineSpacingProperty = DependencyProperty.Register(
        nameof(LineSpacing),
        typeof(double),
        typeof(RightWrapPanel),
        new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsMeasure));

    /// <summary>The space between two lines.</summary>
    public double LineSpacing
    {
        get => (double)GetValue(LineSpacingProperty);
        set => SetValue(LineSpacingProperty, value);
    }

    protected override Size MeasureOverride(Size availableSize)
    {
        var lines = Lines(availableSize.Width, child =>
        {
            child.Measure(new Size(availableSize.Width, double.PositiveInfinity));
            return child.DesiredSize;
        });
        return new Size(
            lines.Count == 0 ? 0 : lines.Max(line => line.Width),
            lines.Sum(line => line.Height) + (LineSpacing * Math.Max(0, lines.Count - 1)));
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        var top = 0.0;
        foreach (var line in Lines(finalSize.Width, child => child.DesiredSize))
        {
            var left = finalSize.Width - line.Width;
            foreach (var child in line.Children)
            {
                child.Arrange(new Rect(left, top, child.DesiredSize.Width, line.Height));
                left += child.DesiredSize.Width;
            }
            top += line.Height + LineSpacing;
        }
        return finalSize;
    }

    /// <summary>
    /// The children in lines no wider than <paramref name="width" />, each child sized by <paramref name="size" />; a
    /// child wider than that has a line of its own.
    /// </summary>
    private List<Line> Lines(double width, Func<UIElement, Size> size)
    {
        var lines = new List<Line>();
        Line? line = null;
        foreach (UIElement child in InternalChildren)
        {
            var childSize = size(child);
            if (line is null || (line.Children.Count > 0 && line.Width + childSize.Width > width))
            {
                line = new Line();
                lines.Add(line);
            }
            line.Children.Add(child);
            line.Width += childSize.Width;
            line.Height = Math.Max(line.Height, childSize.Height);
        }
        return lines;
    }

    private sealed class Line
    {
        public List<UIElement> Children { get; } = [];
        public double Width { get; set; }
        public double Height { get; set; }
    }
}
