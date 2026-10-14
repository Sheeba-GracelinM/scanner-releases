// Custom-painted controls for the RiskNox dark theme: one-to-one ports of the Windows build's
// ../RiskNoxScanner/Widgets.cs (same shapes, sizes, colours and behaviour) on Avalonia.
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;

namespace RiskNox;

/// <summary>Painted control with hover/press tracking and a Click event.</summary>
public class DBControl : Control
{
    protected bool Hover, Down;
    public event EventHandler? Click;

    public DBControl() { ClipToBounds = false; }

    protected Rect R => new(0.5, 0.5, Math.Max(0, Bounds.Width - 1), Math.Max(0, Bounds.Height - 1));

    protected override void OnPointerEntered(PointerEventArgs e) { Hover = true; InvalidateVisual(); base.OnPointerEntered(e); }
    protected override void OnPointerExited(PointerEventArgs e) { Hover = Down = false; InvalidateVisual(); base.OnPointerExited(e); }

    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);
        if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed) { Down = true; InvalidateVisual(); }
    }

    protected override void OnPointerReleased(PointerReleasedEventArgs e)
    {
        base.OnPointerReleased(e);
        bool was = Down;
        Down = false;
        InvalidateVisual();
        if (was && IsEffectivelyEnabled && new Rect(Bounds.Size).Contains(e.GetPosition(this))) OnClick(e);
    }

    protected virtual void OnClick(PointerReleasedEventArgs e) => RaiseClick();
    public void RaiseClick() => Click?.Invoke(this, EventArgs.Empty);

    protected override void OnPropertyChanged(AvaloniaPropertyChangedEventArgs change)
    {
        base.OnPropertyChanged(change);
        if (change.Property == IsEnabledProperty || change.Property == IsEffectivelyEnabledProperty) InvalidateVisual();
    }
}

/// <summary>Rounded panel with an optional icon + uppercase title header (web ".pnl" + ".ph").</summary>
public sealed class Card : Border
{
    public StackPanel Body { get; } = new() { Orientation = Orientation.Vertical };
    readonly Grid _header = new() { Height = 46, ColumnDefinitions = new ColumnDefinitions("Auto,*,Auto") };

    public Card(string title = "", Geometry? glyph = null, bool fill = false)
    {
        Background = Ui.B(Ui.Card);
        BorderBrush = Ui.B(Ui.Border);
        BorderThickness = new Thickness(1);
        CornerRadius = new CornerRadius(12);
        ClipToBounds = true;
        var dock = new DockPanel { LastChildFill = true };
        if (title.Length > 0)
        {
            var head = new DockPanel();
            if (glyph != null)
            {
                var ic = new Border
                {
                    Width = 28, Height = 28, CornerRadius = new CornerRadius(6), Background = Ui.B(Ui.Alpha(Ui.Orange, 0.12)),
                    Margin = new Thickness(16, 0, 10, 0), VerticalAlignment = VerticalAlignment.Center,
                    Child = new PathIcon { Data = glyph, Width = 15, Height = 15, Foreground = Ui.B(Ui.Orange) },
                };
                Grid.SetColumn(ic, 0);
                _header.Children.Add(ic);
            }
            var t = new TextBlock
            {
                Text = title.ToUpperInvariant(), FontFamily = Ui.Sans, FontSize = Ui.Label.Size, FontWeight = FontWeight.SemiBold,
                Foreground = Ui.B(Ui.Muted), VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis,
                Margin = new Thickness(glyph == null ? 16 : 0, 0, 16, 0), LetterSpacing = 0.4,
            };
            Grid.SetColumn(t, 1);
            _header.Children.Add(t);
            DockPanel.SetDock(_header, Dock.Top);
            dock.Children.Add(_header);
            var line = new Border { Height = 1, Background = Ui.B(Ui.Border) };
            DockPanel.SetDock(line, Dock.Top);
            dock.Children.Add(line);
        }
        Body.Margin = new Thickness(16, 12, 16, 14);
        if (fill) dock.Children.Add(BodyHost = new Panel { Margin = Body.Margin });
        else dock.Children.Add(Body);
        Child = dock;
    }

    /// <summary>Fill-mode content host (when constructed with fill: true).</summary>
    public Panel? BodyHost { get; }

    /// <summary>Place a control (e.g. buttons) right-aligned in the header row.</summary>
    public void SetHeaderRight(Control c)
    {
        c.VerticalAlignment = VerticalAlignment.Center;
        c.Margin = new Thickness(0, 0, 12, 0);
        Grid.SetColumn(c, 2);
        _header.Children.Add(c);
    }

    public void Add(params Control[] items) { foreach (var c in items) Body.Children.Add(c); }
}

public enum ButtonKind { Primary, Secondary, Danger, Ghost, Chip }

/// <summary>Flat rounded button in the RiskNox styles (gradient primary, outline danger, dashed ghost, filter chip).</summary>
public sealed class FlatButton : DBControl
{
    ButtonKind _kind;
    string _text;
    Geometry? _glyph;
    public ButtonKind Kind { get => _kind; set { _kind = value; InvalidateVisual(); } }
    public string Text { get => _text; set { _text = value; InvalidateMeasure(); InvalidateVisual(); } }
    public Geometry? Glyph { get => _glyph; set { _glyph = value; InvalidateMeasure(); InvalidateVisual(); } }
    public UiFont Font { get; set; }
    public bool Active { get; set; }
    public Color? Accent { get; set; }
    public object? Data { get; set; }

    public FlatButton(string text, ButtonKind kind = ButtonKind.Secondary, Geometry? glyph = null)
    {
        _text = text; _kind = kind; _glyph = glyph;
        Height = 34;
        Font = kind == ButtonKind.Primary ? Ui.Bold : Ui.Base;
        Cursor = new Cursor(StandardCursorType.Hand);
        Focusable = true;
    }

    protected override Size MeasureOverride(Size availableSize) =>
        new(Ui.Measure(_text, Font).Width + (_glyph != null ? 50 : 30), Height);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (e.Key is Key.Enter or Key.Space && IsEffectivelyEnabled) { RaiseClick(); e.Handled = true; }
    }

    public override void Render(DrawingContext g)
    {
        var r = R;
        bool en = IsEffectivelyEnabled;
        double rad = Kind == ButtonKind.Chip ? Bounds.Height / 2 : Kind == ButtonKind.Primary ? 9 : 7;
        Color fg = Ui.Text, accent = Accent ?? Ui.Orange;
        switch (Kind)
        {
            case ButtonKind.Primary:
                Ui.FillRound(g, en ? Ui.OrangeGradient() : Ui.B(Ui.Dim), r, rad);
                if (Hover && en && !Down) Ui.FillRound(g, Ui.B(Color.FromArgb(28, 255, 255, 255)), r, rad);
                fg = en ? Colors.White : Ui.Muted;
                break;
            case ButtonKind.Danger:
                Ui.FillRound(g, Ui.B(Ui.Alpha(Ui.Crit, Hover ? 0.22 : 0.10)), r, rad);
                Ui.DrawRound(g, Ui.P(en ? Ui.Crit : Ui.Dim), r, rad);
                fg = en ? Ui.Crit : Ui.Muted;
                break;
            case ButtonKind.Ghost:
                if (Hover && en) Ui.FillRound(g, Ui.B(Ui.Alpha(Ui.Orange, 0.10)), r, rad);
                Ui.DrawRound(g, Ui.P(Hover && en ? Ui.Orange : Ui.Border, 1, Ui.Dash), r, rad);
                fg = Hover && en ? Ui.Orange : Ui.Muted;
                break;
            case ButtonKind.Chip:
                Ui.FillRound(g, Ui.B(Active ? Ui.Alpha(accent, 0.16) : Hover ? Ui.El : Ui.In), r, rad);
                Ui.DrawRound(g, Ui.P(Active ? Ui.Alpha(accent, 0.6) : Ui.Border), r, rad);
                fg = Active ? accent : Hover ? Ui.Text : Ui.Muted;
                break;
            default:
                Ui.FillRound(g, Ui.B(Hover && en ? Ui.Dim : Ui.El), r, rad);
                Ui.DrawRound(g, Ui.P(Hover && en ? Ui.BorderHover : Ui.Border), r, rad);
                fg = en ? Ui.Text : Ui.Muted;
                break;
        }
        if (IsFocused && Kind != ButtonKind.Chip) Ui.DrawRound(g, Ui.P(Ui.Alpha(Ui.Orange, 0.5)), r.Deflate(1.5), rad - 1);
        if (_glyph != null)
        {
            var ts = Ui.Measure(_text, Font);
            double gw = 16, gap = 8, total = gw + gap + ts.Width, x = (Bounds.Width - total) / 2;
            Icons.Draw(g, _glyph, fg, new Rect(x, 0, gw, Bounds.Height), 15);
            Ui.Draw(g, _text, Font, fg, new Rect(x + gw + gap, 0, ts.Width + 2, Bounds.Height));
        }
        else Ui.Draw(g, _text, Font, fg, new Rect(4, 0, Bounds.Width - 8, Bounds.Height), Ui.H.Center);
    }
}

/// <summary>Dark menu shown under a control (replaces the WinForms ContextMenuStrip + DarkMenuRenderer).</summary>
public static class DarkMenu
{
    public static void Show(Control anchor, IEnumerable<(string Label, bool Checked, Action OnClick)> items, double? width = null)
    {
        var stack = new StackPanel();
        var fly = new Flyout
        {
            Placement = PlacementMode.BottomEdgeAlignedLeft, ShowMode = FlyoutShowMode.Standard,
            FlyoutPresenterClasses = { "dark" },
            Content = new Border
            {
                Background = Ui.B(Ui.El), BorderBrush = Ui.B(Ui.BorderHover), BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6), Padding = new Thickness(0, 3), Child = stack,
            },
        };
        foreach (var (label, check, act) in items)
        {
            var row = new MenuRow(label, check) { MinWidth = Math.Max(180, (width ?? 0) - 2) };
            row.Click += (_, _) => { fly.Hide(); act(); };
            stack.Children.Add(row);
        }
        fly.ShowAt(anchor);
    }

    sealed class MenuRow(string text, bool check) : DBControl
    {
        protected override Size MeasureOverride(Size a) => new(Ui.Measure(text, Ui.Base).Width + 44, 30);

        public override void Render(DrawingContext g)
        {
            var r = new Rect(2, 0, Bounds.Width - 4, Bounds.Height);
            if (Hover) { Ui.FillRound(g, Ui.B(Ui.Over(Ui.Orange, 0.25, Ui.El)), r, 3); Ui.DrawRound(g, Ui.P(Ui.Orange), r, 3); }
            if (check) Ui.Draw(g, "✓", Ui.Base, Ui.Orange, new Rect(8, 0, 16, Bounds.Height));
            Ui.Draw(g, text, Ui.Base, Hover ? Colors.White : Ui.Text, new Rect(26, 0, Bounds.Width - 32, Bounds.Height));
        }
    }
}

/// <summary>Dark drop-down selector (same as the Windows DarkSelect).</summary>
public sealed class DarkSelect : DBControl
{
    public List<(string Value, string Label)> Options { get; } = new();
    int _index;
    public event EventHandler? SelectionChanged;

    public DarkSelect() { Height = 34; Cursor = new Cursor(StandardCursorType.Hand); Focusable = true; }

    public string Value
    {
        get => _index >= 0 && _index < Options.Count ? Options[_index].Value : "";
        set
        {
            int i = Options.FindIndex(o => o.Value == value);
            if (i >= 0 && i != _index) { _index = i; InvalidateVisual(); SelectionChanged?.Invoke(this, EventArgs.Empty); }
        }
    }

    protected override void OnClick(PointerReleasedEventArgs e)
    {
        base.OnClick(e);
        Open();
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (!IsEffectivelyEnabled) return;
        if (e.Key is Key.Enter or Key.Space) { Open(); e.Handled = true; }
        else if (e.Key == Key.Down && _index < Options.Count - 1) { Value = Options[_index + 1].Value; e.Handled = true; }
        else if (e.Key == Key.Up && _index > 0) { Value = Options[_index - 1].Value; e.Handled = true; }
    }

    void Open()
    {
        if (!IsEffectivelyEnabled) return;
        DarkMenu.Show(this, Options.Select((o, i) => (o.Label, i == _index, (Action)(() => Value = o.Value))), Bounds.Width);
    }

    public override void Render(DrawingContext g)
    {
        var r = R;
        bool en = IsEffectivelyEnabled;
        Ui.FillRound(g, Ui.B(Ui.In), r, 8);
        Ui.DrawRound(g, Ui.P((Hover || IsFocused) && en ? Ui.Orange : Ui.Border), r, 8);
        string label = _index >= 0 && _index < Options.Count ? Options[_index].Label : "";
        Ui.Draw(g, label, Ui.Base, en ? Ui.Text : Ui.Muted, new Rect(12, 0, Bounds.Width - 40, Bounds.Height));
        Icons.Draw(g, Icons.Chevron, Ui.Muted, new Rect(Bounds.Width - 30, 0, 20, Bounds.Height), 16);
    }
}

/// <summary>Rounded host around a borderless TextBox (search field).</summary>
public sealed class SearchBox : Border
{
    public TextBox Box { get; } = new()
    {
        BorderThickness = new Thickness(0), Background = Brushes.Transparent, Foreground = Ui.B(Ui.Text),
        FontFamily = Ui.Sans, FontSize = Ui.Base.Size, VerticalAlignment = VerticalAlignment.Center,
        Padding = new Thickness(0), MinHeight = 0, CaretBrush = Ui.B(Ui.Text),
        SelectionBrush = Ui.B(Ui.Alpha(Ui.Orange, 0.4)),
    };

    public SearchBox(string placeholder)
    {
        Height = 34;
        Background = Ui.B(Ui.In);
        BorderBrush = Ui.B(Ui.Border);
        BorderThickness = new Thickness(1);
        CornerRadius = new CornerRadius(8);
        Box.Watermark = placeholder;
        Box.Classes.Add("search");
        var dock = new DockPanel();
        var icon = new PathIcon { Data = Icons.Search, Width = 15, Height = 15, Foreground = Ui.B(Ui.Muted), Margin = new Thickness(11, 0, 8, 0) };
        DockPanel.SetDock(icon, Dock.Left);
        dock.Children.Add(icon);
        dock.Children.Add(Box);
        Child = dock;
        Box.GotFocus += (_, _) => BorderBrush = Ui.B(Ui.Orange);
        Box.LostFocus += (_, _) => BorderBrush = Ui.B(Ui.Border);
        PointerPressed += (_, _) => Box.Focus();
    }
}

/// <summary>List of scan paths with a remove (×) button per row (web ".paths-list").</summary>
public sealed class PathList : DBControl
{
    public List<string> Paths { get; } = new();
    public event EventHandler? Changed;
    int _hoverRemove = -1, _hoverRow = -1;
    const double RowH = 34, Gap = 5;
    static readonly StringComparer Cmp = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    public void Set(IEnumerable<string> paths) { Paths.Clear(); Paths.AddRange(paths.Distinct(Cmp)); Reflow(); }
    public void Add(string p) { if (!Paths.Contains(p, Cmp)) { Paths.Add(p); Reflow(); } }

    void Reflow() { Changed?.Invoke(this, EventArgs.Empty); InvalidateMeasure(); InvalidateVisual(); }

    protected override Size MeasureOverride(Size a) => new(0, Math.Max(RowH, Paths.Count * (RowH + Gap) - Gap));

    Rect RemoveRect(int i) => new(Bounds.Width - 30, i * (RowH + Gap) + (RowH - 22) / 2, 22, 22);

    protected override void OnPointerMoved(PointerEventArgs e)
    {
        base.OnPointerMoved(e);
        var pt = e.GetPosition(this);
        int row = (int)(pt.Y / (RowH + Gap));
        int hr = row < Paths.Count && RemoveRect(row).Contains(pt) ? row : -1;
        if (hr != _hoverRemove || row != _hoverRow) { _hoverRemove = hr; _hoverRow = row; InvalidateVisual(); }
        Cursor = hr >= 0 && IsEffectivelyEnabled ? new Cursor(StandardCursorType.Hand) : Cursor.Default;
    }

    protected override void OnPointerExited(PointerEventArgs e) { _hoverRemove = _hoverRow = -1; base.OnPointerExited(e); }

    protected override void OnClick(PointerReleasedEventArgs e)
    {
        if (!IsEffectivelyEnabled || _hoverRemove < 0 || _hoverRemove >= Paths.Count) return;
        Paths.RemoveAt(_hoverRemove);
        _hoverRemove = -1;
        Reflow();
    }

    public override void Render(DrawingContext g)
    {
        if (Paths.Count == 0)
        {
            Ui.Draw(g, "No folders selected — add one below.", Ui.Small, Ui.Muted, new Rect(Bounds.Size));
            return;
        }
        bool en = IsEffectivelyEnabled;
        for (int i = 0; i < Paths.Count; i++)
        {
            var r = new Rect(0.5, i * (RowH + Gap) + 0.5, Bounds.Width - 1, RowH - 1);
            Ui.FillRound(g, Ui.B(Ui.In), r, 7);
            Ui.DrawRound(g, Ui.P(i == _hoverRow ? Ui.BorderHover : Ui.Border), r, 7);
            Icons.Draw(g, Icons.Folder, Ui.Orange, new Rect(9, r.Y, 18, RowH), 15);
            Ui.Draw(g, Paths[i], Ui.Mono, en ? Ui.Text : Ui.Muted, new Rect(32, r.Y, Bounds.Width - 68, RowH), leading: true);
            if (en)
            {
                var rr = RemoveRect(i);
                if (i == _hoverRemove) Ui.FillRound(g, Ui.B(Ui.Alpha(Ui.Crit, 0.15)), rr, 4);
                Icons.Draw(g, Icons.Close, i == _hoverRemove ? Ui.Crit : Ui.Muted, rr, 12);
            }
        }
    }
}

/// <summary>Dashed drop target; click opens a file picker (web ".upzone").</summary>
public sealed class DropZone : DBControl
{
    bool _over;
    public string Line1 { get; set; } = "Drop files or folders here";
    public string Line2 { get; set; } = "";

    public DropZone() { Cursor = new Cursor(StandardCursorType.Hand); DragDrop.SetAllowDrop(this, true); }

    public void SetDragOver(bool v) { _over = v; InvalidateVisual(); }

    public override void Render(DrawingContext g)
    {
        bool hot = (Hover || _over) && IsEffectivelyEnabled;
        var r = new Rect(1, 1, Bounds.Width - 3, Bounds.Height - 3);
        Ui.FillRound(g, Ui.B(hot ? Ui.Over(Ui.Orange, 0.10, Ui.In) : Ui.In), r, 12);
        Ui.DrawRound(g, Ui.P(hot ? Ui.Orange : Ui.Border, 2, Ui.Dash), r, 12);
        double y = Bounds.Height / 2 - 38;
        Icons.Draw(g, Icons.Upload, hot ? Ui.Orange : Ui.Muted, new Rect(0, y, Bounds.Width, 32), 30);
        Ui.Draw(g, Line1, Ui.Bold, Ui.Text, new Rect(0, y + 36, Bounds.Width, 20), Ui.H.Center);
        Ui.Draw(g, Line2, Ui.Small, Ui.Muted, new Rect(12, y + 58, Bounds.Width - 24, 30), Ui.H.Center, Ui.V.Top, wrap: true);
    }
}

/// <summary>Stat tile (web ".scard"): tinted background, big number, small label.</summary>
public sealed class Tile : DBControl
{
    string _value = "0";
    public string Value { get => _value; set { if (_value != value) { _value = value; InvalidateVisual(); } } }
    public string Caption { get; }
    public Color Accent { get; }
    public bool Tinted { get; }
    public Geometry? Glyph { get; }

    public Tile(string caption, Color accent, bool tinted, Geometry? glyph = null)
    {
        Caption = caption; Accent = accent; Tinted = tinted; Glyph = glyph;
        Height = 104;
    }

    public override void Render(DrawingContext g)
    {
        var r = R;
        Ui.FillRound(g, Ui.B(Tinted ? Ui.Over(Accent, 0.07, Ui.Card) : Ui.El), r, 12);
        Ui.DrawRound(g, Ui.P(Tinted ? Ui.Over(Accent, 0.22, Ui.Card) : Ui.Border), r, 12);
        double x = 14;
        if (Glyph != null) Icons.Draw(g, Glyph, Tinted ? Accent : Ui.Muted, new Rect(x, 10, 20, 20), 16);
        else g.DrawEllipse(Ui.B(Accent), null, new Rect(x, 15, 10, 10));
        Ui.Draw(g, Value, Ui.Big, Tinted ? Accent : Ui.Text, new Rect(x - 1, 28, Bounds.Width - x - 4, 40));
        Ui.Draw(g, Caption, Ui.Small, Ui.Muted, new Rect(x, Bounds.Height - 28, Bounds.Width - x - 4, 20));
    }
}

/// <summary>Rounded orange progress bar.</summary>
public sealed class ProgressStrip : Control
{
    double _value;
    public double Value { get => _value; set { _value = Math.Clamp(value, 0, 1); InvalidateVisual(); } }
    public ProgressStrip() { Height = 8; }

    public override void Render(DrawingContext g)
    {
        double h = Bounds.Height;
        var r = new Rect(0, 0, Bounds.Width, h);
        Ui.FillRound(g, Ui.B(Ui.El), r, h / 2);
        if (_value <= 0) return;
        Ui.FillRound(g, Ui.OrangeGradient(0), new Rect(0, 0, Math.Max(h, Bounds.Width * _value), h), h / 2);
    }
}

/// <summary>Donut chart + legend with per-confidence counts (web "PII Type Breakdown").</summary>
public sealed class Breakdown : Control
{
    public List<(string Type, int High, int Medium, int Low)> Items { get; private set; } = new();

    public void SetItems(IEnumerable<(string, int, int, int)> items)
    {
        Items = items.OrderByDescending(i => i.Item2 + i.Item3 + i.Item4).ToList();
        InvalidateMeasure();
        InvalidateVisual();
    }

    protected override Size MeasureOverride(Size a) => new(0, Math.Max(220, 64 + Items.Count * 30));

    static Geometry Arc(Rect ring, double startDeg, double sweepDeg)
    {
        double cx = ring.Center.X, cy = ring.Center.Y, rad = ring.Width / 2;
        Point P(double deg) => new(cx + rad * Math.Cos(deg * Math.PI / 180), cy + rad * Math.Sin(deg * Math.PI / 180));
        var geo = new StreamGeometry();
        using var c = geo.Open();
        c.BeginFigure(P(startDeg), false);
        c.ArcTo(P(startDeg + sweepDeg), new Size(rad, rad), 0, sweepDeg > 180, SweepDirection.Clockwise);
        c.EndFigure(false);
        return geo;
    }

    public override void Render(DrawingContext g)
    {
        int total = Items.Sum(i => i.High + i.Medium + i.Low);
        double d = 170, cx = 8, cy = 10;
        var ring = new Rect(cx + 11, cy + 11, d - 22, d - 22);
        g.DrawEllipse(null, Ui.P(Ui.El, 22), ring.Center, ring.Width / 2, ring.Height / 2);
        double start = -90;
        if (total > 0)
            foreach (var it in Items)
            {
                double sweep = 360.0 * (it.High + it.Medium + it.Low) / total;
                double s = Math.Min(359.9, Math.Max(0.5, sweep - 1.2));
                g.DrawGeometry(null, Ui.P(Ui.TypeColor(it.Type), 22), Arc(ring, start, s));
                start += sweep;
            }
        Ui.Draw(g, total.ToString("N0"), Ui.Title, Ui.Text, new Rect(cx, cy + d / 2 - 18, d, 24), Ui.H.Center);
        Ui.Draw(g, "total PII", Ui.Small, Ui.Muted, new Rect(cx, cy + d / 2 + 4, d, 18), Ui.H.Center);

        // legend table
        double x = cx + d + 30, w = Bounds.Width - x - 4;
        if (w < 200) return;
        double colH = x + w * 0.42, colM = colH + w * 0.14, colL = colM + w * 0.14, colT = colL + w * 0.14;
        double y = 6;
        void Head(string s, double at, Color c) => Ui.Draw(g, s, Ui.SmallBold, c, new Rect(at, y, 80, 20));
        Head("TYPE", x, Ui.Muted); Head("HIGH", colH, Ui.Crit); Head("MEDIUM", colM, Ui.Med); Head("LOW", colL, Ui.Muted); Head("TOTAL", colT, Ui.Muted);
        y += 26;
        int max = Items.Count > 0 ? Items.Max(i => i.High + i.Medium + i.Low) : 1;
        foreach (var it in Items)
        {
            int t = it.High + it.Medium + it.Low;
            var c = Ui.TypeColor(it.Type);
            g.DrawEllipse(Ui.B(c), null, new Rect(x, y + 9, 9, 9));
            Ui.Draw(g, it.Type.Replace('_', ' '), Ui.Base, Ui.Text, new Rect(x + 16, y, colH - x - 20, 26));
            double bw = (colH - x - 24) * t / Math.Max(1, max);
            g.FillRectangle(Ui.B(Ui.Alpha(c, 0.35)), new Rect(x + 16, y + 24, bw, 2));
            Ui.Draw(g, it.High.ToString("N0"), Ui.Base, Ui.Text, new Rect(colH, y, 80, 26));
            Ui.Draw(g, it.Medium.ToString("N0"), Ui.Base, Ui.Text, new Rect(colM, y, 80, 26));
            Ui.Draw(g, it.Low.ToString("N0"), Ui.Base, Ui.Muted, new Rect(colL, y, 80, 26));
            Ui.Draw(g, t.ToString("N0"), Ui.Bold, Ui.Text, new Rect(colT, y, 90, 26));
            y += 30;
        }
        if (Items.Count == 0) Ui.Draw(g, "No PII detected yet.", Ui.Base, Ui.Muted, new Rect(x, y, w, 26));
    }
}

/// <summary>Location classification: counts + stacked bar (web "Location Classification").</summary>
public sealed class LocationView : Control
{
    public Dictionary<string, int> Counts { get; set; } = new();
    static readonly (string Key, string Label, string Hint)[] Keys =
    [
        ("violation", "Policy violation", "PII in a location this role must not use (Downloads, Desktop, personal cloud, USB…)"),
        ("review", "Needs review", "PII outside approved and disallowed locations"),
        ("expected_location", "Expected location", "PII in an approved share for this role"),
    ];

    public LocationView() { Height = 150; }

    public override void Render(DrawingContext g)
    {
        int total = Keys.Sum(k => Counts.GetValueOrDefault(k.Key));
        var bar = new Rect(0, 4, Bounds.Width, 12);
        Ui.FillRound(g, Ui.B(Ui.El), bar, 6);
        if (total > 0)
        {
            using (g.PushClip(new RoundedRect(bar, 6)))
            {
                double x = 0;
                foreach (var k in Keys)
                {
                    double w = Bounds.Width * Counts.GetValueOrDefault(k.Key) / total;
                    g.FillRectangle(Ui.B(Ui.LocationColors[k.Key]), new Rect(x, bar.Y, w, bar.Height));
                    x += w;
                }
            }
        }
        double cw = Bounds.Width / Keys.Length, y = 30;
        for (int i = 0; i < Keys.Length; i++)
        {
            var (key, label, hint) = Keys[i];
            double x = i * cw;
            int n = Counts.GetValueOrDefault(key);
            var c = Ui.LocationColors[key];
            g.DrawEllipse(Ui.B(c), null, new Rect(x, y + 6, 9, 9));
            Ui.Draw(g, label, Ui.Label, Ui.Muted, new Rect(x + 16, y, cw - 20, 20));
            Ui.Draw(g, n.ToString("N0"), Ui.Big, c, new Rect(x + 14, y + 18, cw - 20, 40));
            Ui.Draw(g, hint, Ui.Small, Ui.Muted, new Rect(x + 16, y + 60, cw - 28, 48), Ui.H.Left, Ui.V.Top, wrap: true);
        }
    }
}

/// <summary>Wrapping row of "type ×count" chips (live PII so far).</summary>
public sealed class ChipsView : Control
{
    List<(string Type, int Count)> _items = new();
    public List<(string Type, int Count)> Items { get => _items; set { _items = value; InvalidateMeasure(); InvalidateVisual(); } }
    const double H = 26, G = 6;

    IEnumerable<(Rect R, string Text, Color C)> Layout(double width)
    {
        double x = 0, y = 0;
        foreach (var (t, n) in _items)
        {
            string s = $"{t.Replace('_', ' ')}  {n:N0}";
            double w = Ui.Measure(s, Ui.Small).Width + 18;
            if (x + w > width && x > 0) { x = 0; y += H + G; }
            yield return (new Rect(x, y, w, H), s, Ui.TypeColor(t));
            x += w + G;
        }
    }

    protected override Size MeasureOverride(Size a)
    {
        if (_items.Count == 0) return new Size(0, 34);
        double w = double.IsInfinity(a.Width) ? 600 : a.Width;
        return new Size(0, Math.Max(34, Layout(w).Max(l => l.R.Bottom) + 2));
    }

    public override void Render(DrawingContext g)
    {
        if (_items.Count == 0) { Ui.Draw(g, "Nothing yet.", Ui.Small, Ui.Muted, new Rect(0, 0, Bounds.Width, H)); return; }
        foreach (var (r, s, c) in Layout(Bounds.Width))
        {
            Ui.FillRound(g, Ui.B(Ui.Over(c, 0.14, Ui.Card)), r, H / 2);
            Ui.DrawRound(g, Ui.P(Ui.Over(c, 0.35, Ui.Card)), r, H / 2);
            Ui.Draw(g, s, Ui.Small, c, r, Ui.H.Center);
        }
    }
}

/// <summary>Sidebar navigation entry (accent pill on the selected item).</summary>
public sealed class NavItem : DBControl
{
    public string Text { get; }
    public Geometry Glyph { get; }
    bool _sel;
    string _badge = "";
    public bool Selected { get => _sel; set { _sel = value; InvalidateVisual(); } }
    public string Badge { get => _badge; set { if (_badge != value) { _badge = value; InvalidateVisual(); } } }

    public NavItem(string text, Geometry glyph) { Text = text; Glyph = glyph; Height = 40; Cursor = new Cursor(StandardCursorType.Hand); }

    public override void Render(DrawingContext g)
    {
        double W = Bounds.Width, Hh = Bounds.Height;
        g.FillRectangle(Ui.B(Ui.Bg), new Rect(Bounds.Size));
        var r = new Rect(8, 2, W - 16, Hh - 4);
        if (_sel || Hover) Ui.FillRound(g, Ui.B(_sel ? Ui.El : Ui.Over(Ui.El, 0.6, Ui.Bg)), r, 6);
        if (_sel) Ui.FillRound(g, Ui.B(Ui.Orange), new Rect(8, Hh / 2 - 8, 3, 16), 2);
        Icons.Draw(g, Glyph, _sel ? Ui.Orange : Ui.Muted, new Rect(22, 0, 20, Hh), 17);
        Ui.Draw(g, Text, _sel ? Ui.Bold : Ui.Base, _sel ? Ui.Text : Ui.NavText, new Rect(54, 0, W - 100, Hh));
        if (_badge.Length > 0)
        {
            double w = Ui.Measure(_badge, Ui.SmallBold).Width + 12;
            var br = new Rect(W - 16 - w, Hh / 2 - 10, w, 20);
            Ui.FillRound(g, Ui.B(Ui.Alpha(Ui.Orange, 0.16)), br, 10);
            Ui.Draw(g, _badge, Ui.SmallBold, Ui.Orange, br, Ui.H.Center);
        }
    }
}

/// <summary>Brand mark: the Risknox three-bar shape on an 18x24 grid.</summary>
public sealed class Logo : Control
{
    public Logo() { Width = 34; Height = 34; }

    public static void Paint(DrawingContext g, Size size)
    {
        double k = Math.Min(size.Width / 18, size.Height / 24) * 0.9;
        double ox = (size.Width - 18 * k) / 2, oy = (size.Height - 24 * k) / 2;
        Point P(double x, double y) => new(ox + x * k, oy + y * k);
        Geometry Poly(params Point[] pts)
        {
            var geo = new StreamGeometry();
            using var c = geo.Open();
            c.BeginFigure(pts[0], true);
            foreach (var p in pts.Skip(1)) c.LineTo(p);
            c.EndFigure(true);
            return geo;
        }
        g.DrawGeometry(Ui.B(Ui.OrangeDeep), null, Poly(P(0, 6), P(6, 2), P(6, 26), P(0, 22)));
        g.DrawGeometry(Ui.B(Ui.Orange), null, Poly(P(6, 2), P(18, 8), P(18, 14), P(6, 8)));
        g.DrawGeometry(Ui.B(Ui.Orange), null, Poly(P(6, 14), P(18, 20), P(18, 26), P(6, 20)));
    }

    public override void Render(DrawingContext g) => Paint(g, Bounds.Size);
}

/// <summary>State dot + label (idle / scanning / done / error) for the status bar.</summary>
public sealed class StatusDot : Control
{
    string _state = "idle";
    bool _blink;
    readonly DispatcherTimer _t = new() { Interval = TimeSpan.FromMilliseconds(600) };
    public string State { get => _state; set { _state = value; InvalidateVisual(); } }

    public StatusDot()
    {
        Height = 24; Width = 110;
        _t.Tick += (_, _) => { _blink = !_blink; if (_state == "scanning") InvalidateVisual(); };
        _t.Start();
    }

    public override void Render(DrawingContext g)
    {
        Color c = _state switch { "scanning" => Ui.Orange, "done" => Ui.Low, "error" => Ui.Crit, "stopped" => Ui.Med, _ => Ui.Muted };
        byte a = (byte)(_state == "scanning" && _blink ? 110 : 255);
        g.DrawEllipse(Ui.B(Color.FromArgb(a, c.R, c.G, c.B)), null, new Rect(2, Bounds.Height / 2 - 4, 8, 8));
        Ui.Draw(g, _state.ToUpperInvariant(), Ui.SmallBold, Ui.Text, new Rect(16, 0, Bounds.Width - 16, Bounds.Height));
    }
}

/// <summary>Painted read-only table (header + rows). Height follows the row count.</summary>
public sealed class SimpleTable : Control
{
    public sealed record Column(string Title, double Width, bool Right = false); // Width <= 0: fill
    public List<Column> Columns { get; } = new();
    public List<(string[] Cells, bool Strong)> Rows { get; } = new();
    public string EmptyText { get; set; } = "";
    const double HeaderH = 30, RowH = 28;

    public void SetRows(IEnumerable<(string[] Cells, bool Strong)> rows)
    {
        Rows.Clear();
        Rows.AddRange(rows);
        InvalidateMeasure();
        InvalidateVisual();
    }

    protected override Size MeasureOverride(Size a) => new(0, HeaderH + Math.Max(1, Rows.Count) * RowH + 4);

    double[] Widths()
    {
        double fixedW = Columns.Where(c => c.Width > 0).Sum(c => c.Width);
        int fills = Math.Max(1, Columns.Count(c => c.Width <= 0));
        double fill = Math.Max(60, (Bounds.Width - 20 - fixedW) / fills);
        return Columns.Select(c => c.Width > 0 ? c.Width : fill).ToArray();
    }

    public override void Render(DrawingContext g)
    {
        var w = Widths();
        var line = Ui.P(Ui.Border);
        double x = 0;
        for (int i = 0; i < Columns.Count; i++)
        {
            var c = Columns[i];
            Ui.Draw(g, c.Title.ToUpperInvariant(), Ui.SmallBold, Ui.Muted, new Rect(x + 6, 0, w[i] - 12, HeaderH), c.Right ? Ui.H.Right : Ui.H.Left);
            x += w[i];
        }
        g.DrawLine(line, new Point(0, HeaderH - 0.5), new Point(Bounds.Width, HeaderH - 0.5));
        if (Rows.Count == 0 && EmptyText.Length > 0)
            Ui.Draw(g, EmptyText, Ui.Base, Ui.Muted, new Rect(6, HeaderH, Bounds.Width - 12, RowH));
        double y = HeaderH;
        foreach (var (cells, strong) in Rows)
        {
            x = 0;
            for (int i = 0; i < Columns.Count && i < cells.Length; i++)
            {
                var color = strong || i == 0 ? Ui.Text : Ui.Muted;
                Ui.Draw(g, cells[i], strong ? Ui.Bold : Ui.Base, color, new Rect(x + 6, y, w[i] - 12, RowH),
                    Columns[i].Right ? Ui.H.Right : Ui.H.Left, leading: i == Columns.Count - 1);
                x += w[i];
            }
            y += RowH;
            g.DrawLine(line, new Point(0, y - 0.5), new Point(Bounds.Width, y - 0.5));
        }
    }
}
