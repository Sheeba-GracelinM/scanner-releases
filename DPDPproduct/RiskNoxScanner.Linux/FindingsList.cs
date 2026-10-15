// Findings table: the Windows build's owner-drawn virtual ListView (Risk | File | PII types |
// Score | Location, 48 px rows, sortable headers) as a painted, virtualised Avalonia control.
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;

namespace RiskNox;

public sealed class FindingRow
{
    public required string Path { get; init; }
    public long Size { get; init; }
    public DateTime Modified { get; init; }
    public string? Sha { get; set; }
    public required Dictionary<string, TypeCount> Types { get; init; }
    public double Score { get; init; }
    public required string Tier { get; init; }
    public required string Location { get; init; }
    public int Total => Types.Values.Sum(v => v.Count);
}

public sealed class FindingsList : Grid
{
    readonly Canvas _canvas;
    readonly ScrollBar _scroll = new() { Orientation = Orientation.Vertical, AllowAutoHide = false, Width = 12 };

    public IReadOnlyList<FindingRow> Items { get; private set; } = [];
    public int SelectedIndex { get; private set; } = -1;
    public int SortCol { get; set; }
    public bool SortDesc { get; set; } = true;

    public event EventHandler? SelectionChanged;
    public event EventHandler<int>? ColumnClick;
    public event EventHandler? ItemActivated;

    public FindingsList()
    {
        ColumnDefinitions = new ColumnDefinitions("*,Auto");
        _canvas = new Canvas(this);
        Children.Add(_canvas);
        SetColumn(_scroll, 1);
        _scroll.Margin = new Thickness(0, Canvas.HeaderH, 0, 0);
        Children.Add(_scroll);
        _scroll.Scroll += (_, _) => _canvas.InvalidateVisual();
        _scroll.PropertyChanged += (_, e) => { if (e.Property == RangeBase.ValueProperty) _canvas.InvalidateVisual(); };
        _canvas.SizeChanged += (_, _) => UpdateScroll();
    }

    public void SetItems(IReadOnlyList<FindingRow> items)
    {
        Items = items;
        if (SelectedIndex >= items.Count) SelectedIndex = -1;
        UpdateScroll();
        _canvas.InvalidateVisual();
    }

    public FindingRow? Selected => SelectedIndex >= 0 && SelectedIndex < Items.Count ? Items[SelectedIndex] : null;

    public void Select(int i, bool raise = true)
    {
        i = Items.Count == 0 ? -1 : Math.Clamp(i, -1, Items.Count - 1);
        if (i == SelectedIndex) return;
        SelectedIndex = i;
        EnsureVisible(i);
        _canvas.InvalidateVisual();
        if (raise) SelectionChanged?.Invoke(this, EventArgs.Empty);
    }

    void EnsureVisible(int i)
    {
        if (i < 0) return;
        double top = i * Canvas.RowH, view = _canvas.Bounds.Height - Canvas.HeaderH;
        if (top < _scroll.Value) _scroll.Value = top;
        else if (top + Canvas.RowH > _scroll.Value + view) _scroll.Value = Math.Min(_scroll.Maximum, top + Canvas.RowH - view);
    }

    void UpdateScroll()
    {
        double view = Math.Max(0, _canvas.Bounds.Height - Canvas.HeaderH);
        double max = Math.Max(0, Items.Count * Canvas.RowH - view);
        _scroll.Maximum = max;
        _scroll.ViewportSize = view;
        _scroll.SmallChange = Canvas.RowH;
        _scroll.LargeChange = Math.Max(Canvas.RowH, view);
        if (_scroll.Value > max) _scroll.Value = max;
        _scroll.IsVisible = max > 0;
    }

    sealed class Canvas : Control
    {
        public const double HeaderH = 28, RowH = 48;
        static readonly string[] Cols = ["Risk", "File", "PII types", "Score", "Location"];
        readonly FindingsList _o;

        public Canvas(FindingsList owner) { _o = owner; Focusable = true; ClipToBounds = true; }

        double[] Widths()
        {
            // File and PII-type columns share the space left by the fixed columns (no horizontal scrolling).
            double fixedW = 96 + 60 + 132;
            double free = Math.Max(200, Bounds.Width - fixedW - 2);
            double file = Math.Floor(free * 45 / 100);
            return [96, file, free - file, 60, 132];
        }

        protected override void OnPointerWheelChanged(PointerWheelEventArgs e)
        {
            base.OnPointerWheelChanged(e);
            var s = _o._scroll;
            s.Value = Math.Clamp(s.Value - e.Delta.Y * RowH * 1.5, 0, s.Maximum);
            e.Handled = true;
        }

        protected override void OnPointerPressed(PointerPressedEventArgs e)
        {
            base.OnPointerPressed(e);
            Focus();
            var pt = e.GetPosition(this);
            if (pt.Y < HeaderH)
            {
                var w = Widths();
                double x = 0;
                for (int i = 0; i < w.Length; i++) { if (pt.X < x + w[i]) { _o.ColumnClick?.Invoke(_o, i); return; } x += w[i]; }
                return;
            }
            int idx = (int)((pt.Y - HeaderH + _o._scroll.Value) / RowH);
            if (idx < 0 || idx >= _o.Items.Count) return;
            _o.Select(idx);
            if (e.ClickCount == 2) _o.ItemActivated?.Invoke(_o, EventArgs.Empty);
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);
            int page = Math.Max(1, (int)((Bounds.Height - HeaderH) / RowH) - 1), i = _o.SelectedIndex;
            switch (e.Key)
            {
                case Key.Down: _o.Select(i + 1); break;
                case Key.Up: _o.Select(Math.Max(0, i - 1)); break;
                case Key.PageDown: _o.Select(i + page); break;
                case Key.PageUp: _o.Select(Math.Max(0, i - page)); break;
                case Key.Home: _o.Select(0); break;
                case Key.End: _o.Select(_o.Items.Count - 1); break;
                case Key.Enter: _o.ItemActivated?.Invoke(_o, EventArgs.Empty); break;
                default: return;
            }
            e.Handled = true;
        }

        public override void Render(DrawingContext g)
        {
            var w = Widths();
            g.FillRectangle(Ui.B(Ui.Card), new Rect(Bounds.Size));
            // header
            double x = 0;
            for (int c = 0; c < Cols.Length; c++)
            {
                string text = Cols[c].ToUpperInvariant();
                if (c == _o.SortCol) text += _o.SortDesc ? "  ↓" : "  ↑";
                Ui.Draw(g, text, Ui.SmallBold, Ui.Muted, new Rect(x + 10, 0, w[c] - 12, HeaderH));
                x += w[c];
            }
            g.DrawLine(Ui.P(Ui.Border), new Point(0, HeaderH - 0.5), new Point(Bounds.Width, HeaderH - 0.5));

            using var clip = g.PushClip(new Rect(0, HeaderH, Bounds.Width, Math.Max(0, Bounds.Height - HeaderH)));
            double off = _o._scroll.Value;
            int first = Math.Max(0, (int)(off / RowH)), last = Math.Min(_o.Items.Count - 1, (int)((off + Bounds.Height) / RowH));
            for (int i = first; i <= last; i++)
            {
                var r = _o.Items[i];
                double y = HeaderH + i * RowH - off;
                bool sel = i == _o.SelectedIndex;
                var row = new Rect(0, y, Bounds.Width, RowH);
                g.FillRectangle(Ui.B(sel ? Ui.Over(Ui.Orange, 0.12, Ui.Card) : Ui.Card), row);
                g.DrawLine(Ui.P(Ui.Border), new Point(0, row.Bottom - 0.5), new Point(Bounds.Width, row.Bottom - 0.5));
                if (sel) g.FillRectangle(Ui.B(Ui.Orange), new Rect(0, y + 12, 3, RowH - 24));
                x = 0;
                for (int c = 0; c < w.Length; c++)
                {
                    var inner = new Rect(x + 10, y, w[c] - 14, RowH);
                    using (g.PushClip(new Rect(x, y, w[c], RowH))) Cell(g, r, c, inner);
                    x += w[c];
                }
            }
        }

        static void Cell(DrawingContext g, FindingRow r, int col, Rect inner)
        {
            double cy = inner.Y + inner.Height / 2;
            switch (col)
            {
                case 0: Pill(g, r.Tier.ToUpperInvariant(), Ui.TierColors.GetValueOrDefault(r.Tier, Ui.Muted), inner.X, cy); break;
                case 1:
                    Ui.Draw(g, System.IO.Path.GetFileName(r.Path), Ui.Bold, Ui.Text, new Rect(inner.X, inner.Y + 5, inner.Width, 20));
                    Ui.Draw(g, System.IO.Path.GetDirectoryName(r.Path) ?? "", Ui.Small, Ui.Muted, new Rect(inner.X, inner.Y + 25, inner.Width, 18), leading: true);
                    break;
                case 2:
                {
                    double x = inner.X;
                    var ordered = r.Types.OrderByDescending(kv => kv.Value.Count).ToList();
                    for (int i = 0; i < ordered.Count; i++)
                    {
                        var (t, c) = (ordered[i].Key, ordered[i].Value);
                        string s = $"{t.Replace('_', ' ')} {c.Count:N0}";
                        double pw = Ui.Measure(s, Ui.Small).Width + 12;
                        if (x + pw > inner.Right - 28 && i < ordered.Count - 1)
                        {
                            Ui.Draw(g, $"+{ordered.Count - i}", Ui.SmallBold, Ui.Muted, new Rect(x, inner.Y, 30, inner.Height));
                            break;
                        }
                        Pill(g, s, Ui.TypeColor(t), x, cy, Ui.Small);
                        x += pw + 4;
                    }
                    break;
                }
                case 3: Ui.Draw(g, r.Score.ToString("0.#"), Ui.Bold, Ui.TierColors.GetValueOrDefault(r.Tier, Ui.Text), inner); break;
                case 4:
                    if (r.Location != "n/a")
                        Pill(g, MainWindow.LocationLabel(r.Location), Ui.LocationColors.GetValueOrDefault(r.Location, Ui.Muted), inner.X, cy);
                    break;
            }
        }

        static void Pill(DrawingContext g, string s, Color c, double x, double cy, UiFont? font = null)
        {
            font ??= Ui.SmallBold;
            var sz = Ui.Measure(s, font);
            var r = new Rect(x, cy - 10, sz.Width + 12, 20);
            Ui.FillRound(g, Ui.B(Ui.Over(c, 0.14, Ui.Card)), r, 10);
            Ui.DrawRound(g, Ui.P(Ui.Over(c, 0.30, Ui.Card)), r, 10);
            Ui.Draw(g, s, font, c, r, Ui.H.Center);
        }
    }
}
