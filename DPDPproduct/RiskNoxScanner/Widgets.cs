// Custom-painted controls for the RiskNox dark theme (WinForms has no dark theme of its own).
using System.Drawing.Drawing2D;

namespace RiskNox;

public class DBControl : Control
{
    public DBControl()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint |
                 ControlStyles.ResizeRedraw | ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Theme.Card;
        ForeColor = Theme.Text;
        Font = Theme.Base;
    }

    protected int S(int v) => LogicalToDeviceUnits(v);
}

/// <summary>Rounded panel with an optional icon + uppercase title header (web ".pnl" + ".ph").</summary>
public sealed class Card : Panel
{
    public string Title { get; set; } = "";
    public string Glyph { get; set; } = "";
    public Control? HeaderRight { get; private set; }
    int HeaderH => string.IsNullOrEmpty(Title) ? 0 : LogicalToDeviceUnits(46);

    public Card(string title = "", string glyph = "")
    {
        Title = title; Glyph = glyph;
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        BackColor = Theme.Card;
        ForeColor = Theme.Text;
        Margin = new Padding(0, 0, 0, 14);
        UpdatePadding();
    }

    void UpdatePadding() => Padding = new Padding(LogicalToDeviceUnits(16), HeaderH + LogicalToDeviceUnits(12), LogicalToDeviceUnits(16), LogicalToDeviceUnits(14));

    protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); UpdatePadding(); }

    /// <summary>Place a control (e.g. buttons) right-aligned in the header row.</summary>
    public void SetHeaderRight(Control c)
    {
        HeaderRight = c;
        c.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        Controls.Add(c);
        LayoutHeader();
    }

    void LayoutHeader()
    {
        if (HeaderRight == null) return;
        HeaderRight.Location = new Point(Width - HeaderRight.Width - LogicalToDeviceUnits(12), (HeaderH - HeaderRight.Height) / 2);
    }

    protected override void OnResize(EventArgs e) { base.OnResize(e); LayoutHeader(); }

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(Parent?.BackColor ?? Theme.Bg);
        Theme.Hq(g);
        var r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
        using (var b = new SolidBrush(Theme.Card)) Theme.FillRound(g, b, r, LogicalToDeviceUnits(12));
        using (var p = new Pen(Theme.Border)) Theme.DrawRound(g, p, r, LogicalToDeviceUnits(12));
        if (HeaderH > 0)
        {
            int s = LogicalToDeviceUnits(28), x = LogicalToDeviceUnits(16), y = (HeaderH - s) / 2;
            if (Glyph.Length > 0)
            {
                using (var b = new SolidBrush(Theme.Alpha(Theme.Orange, 0.12))) Theme.FillRound(g, b, new RectangleF(x, y, s, s), LogicalToDeviceUnits(6));
                Theme.Draw(g, Glyph, Theme.Icons, Theme.Orange, new Rectangle(x, y, s, s), TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
                x += s + LogicalToDeviceUnits(10);
            }
            int reserve = HeaderRight != null ? HeaderRight.Width + LogicalToDeviceUnits(24) : LogicalToDeviceUnits(16);
            Theme.Draw(g, Title.ToUpperInvariant(), Theme.Label, Theme.Muted, new Rectangle(x, 0, Width - x - reserve, HeaderH));
            using var line = new Pen(Theme.Border);
            g.SmoothingMode = SmoothingMode.None;
            g.DrawLine(line, 1, HeaderH, Width - 2, HeaderH);
        }
    }
}

public enum ButtonKind { Primary, Secondary, Danger, Ghost, Chip }

/// <summary>Flat rounded button in the RiskNox styles (gradient primary, outline danger, dashed ghost, filter chip).</summary>
public sealed class FlatButton : DBControl
{
    public ButtonKind Kind { get; set; }
    public string Glyph { get; set; } = "";
    public bool Active { get; set; }
    public Color? Accent { get; set; }
    bool _hover, _down;

    public FlatButton(string text, ButtonKind kind = ButtonKind.Secondary, string glyph = "")
    {
        Text = text; Kind = kind; Glyph = glyph;
        Cursor = Cursors.Hand;
        Height = 34;
        Font = kind == ButtonKind.Primary ? Theme.Bold : Theme.Base;
        BackColor = Color.Transparent;
        Width = TextRenderer.MeasureText(text, Font).Width + (glyph.Length > 0 ? 50 : 30);
    }

    protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { _hover = false; _down = false; Invalidate(); base.OnMouseLeave(e); }
    protected override void OnMouseDown(MouseEventArgs e) { _down = true; Invalidate(); base.OnMouseDown(e); }
    protected override void OnMouseUp(MouseEventArgs e) { _down = false; Invalidate(); base.OnMouseUp(e); }
    protected override void OnEnabledChanged(EventArgs e) { Cursor = Enabled ? Cursors.Hand : Cursors.Default; Invalidate(); base.OnEnabledChanged(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Theme.Hq(g);
        var r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
        float rad = Kind == ButtonKind.Chip ? Height / 2f : S(Kind == ButtonKind.Primary ? 9 : 7);
        Color fg = Theme.Text;
        Color accent = Accent ?? Theme.Orange;
        switch (Kind)
        {
            case ButtonKind.Primary:
                using (var b = new LinearGradientBrush(r, Enabled ? Theme.Orange : Theme.Dim, Enabled ? Theme.OrangeDeep : Theme.Dim, 35f))
                    Theme.FillRound(g, b, r, rad);
                if (_hover && Enabled && !_down)
                    using (var hb = new SolidBrush(Color.FromArgb(28, 255, 255, 255))) Theme.FillRound(g, hb, r, rad);
                fg = Enabled ? Color.White : Theme.Muted;
                break;
            case ButtonKind.Danger:
                using (var b = new SolidBrush(Theme.Alpha(Theme.Crit, _hover ? 0.22 : 0.10))) Theme.FillRound(g, b, r, rad);
                using (var p = new Pen(Enabled ? Theme.Crit : Theme.Dim)) Theme.DrawRound(g, p, r, rad);
                fg = Enabled ? Theme.Crit : Theme.Muted;
                break;
            case ButtonKind.Ghost:
                if (_hover && Enabled) using (var b = new SolidBrush(Theme.Alpha(Theme.Orange, 0.10))) Theme.FillRound(g, b, r, rad);
                using (var p = new Pen(_hover && Enabled ? Theme.Orange : Theme.Border) { DashStyle = DashStyle.Dash }) Theme.DrawRound(g, p, r, rad);
                fg = _hover && Enabled ? Theme.Orange : Theme.Muted;
                break;
            case ButtonKind.Chip:
                using (var b = new SolidBrush(Active ? Theme.Alpha(accent, 0.16) : _hover ? Theme.El : Theme.In)) Theme.FillRound(g, b, r, rad);
                using (var p = new Pen(Active ? Theme.Alpha(accent, 0.6) : Theme.Border)) Theme.DrawRound(g, p, r, rad);
                fg = Active ? accent : _hover ? Theme.Text : Theme.Muted;
                break;
            default:
                using (var b = new SolidBrush(_hover && Enabled ? Theme.Dim : Theme.El)) Theme.FillRound(g, b, r, rad);
                using (var p = new Pen(_hover && Enabled ? Theme.BorderHover : Theme.Border)) Theme.DrawRound(g, p, r, rad);
                fg = Enabled ? Theme.Text : Theme.Muted;
                break;
        }
        var flags = TextFormatFlags.VerticalCenter | TextFormatFlags.HorizontalCenter;
        if (Glyph.Length > 0)
        {
            var ts = TextRenderer.MeasureText(Text, Font);
            int gw = S(16), gap = S(8), total = gw + gap + ts.Width, x = (Width - total) / 2;
            Theme.Draw(g, Glyph, Theme.Icons, fg, new Rectangle(x, 0, gw, Height), flags);
            Theme.Draw(g, Text, Font, fg, new Rectangle(x + gw + gap, 0, ts.Width + 2, Height), TextFormatFlags.VerticalCenter | TextFormatFlags.Left);
        }
        else Theme.Draw(g, Text, Font, fg, ClientRectangle, flags);
    }
}

/// <summary>Dark drop-down selector (replaces ComboBox/NumericUpDown, which cannot be themed).</summary>
public sealed class DarkSelect : DBControl
{
    public List<(string Value, string Label)> Options { get; } = new();
    int _index;
    bool _hover;
    public event EventHandler? SelectionChanged;

    public DarkSelect() { Height = 34; Cursor = Cursors.Hand; BackColor = Color.Transparent; }

    public string Value
    {
        get => _index >= 0 && _index < Options.Count ? Options[_index].Value : "";
        set
        {
            int i = Options.FindIndex(o => o.Value == value);
            if (i >= 0 && i != _index) { _index = i; Invalidate(); SelectionChanged?.Invoke(this, EventArgs.Empty); }
        }
    }

    protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { _hover = false; Invalidate(); base.OnMouseLeave(e); }
    protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }

    protected override void OnClick(EventArgs e)
    {
        base.OnClick(e);
        if (!Enabled) return;
        var menu = new ContextMenuStrip { Renderer = new DarkMenuRenderer(), ShowImageMargin = false, Font = Theme.Base, BackColor = Theme.El };
        for (int i = 0; i < Options.Count; i++)
        {
            int idx = i;
            var item = new ToolStripMenuItem(Options[i].Label) { ForeColor = Theme.Text, AutoSize = false, Width = Width, Height = S(30), Checked = i == _index };
            item.Click += (_, _) => { if (_index != idx) { _index = idx; Invalidate(); SelectionChanged?.Invoke(this, EventArgs.Empty); } };
            menu.Items.Add(item);
        }
        menu.Closed += (_, _) => BeginInvoke(menu.Dispose);
        menu.Show(this, new Point(0, Height + 2));
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Theme.Hq(g);
        var r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
        using (var b = new SolidBrush(Theme.In)) Theme.FillRound(g, b, r, S(8));
        using (var p = new Pen(_hover && Enabled ? Theme.Orange : Theme.Border)) Theme.DrawRound(g, p, r, S(8));
        string label = _index >= 0 && _index < Options.Count ? Options[_index].Label : "";
        Theme.Draw(g, label, Font, Enabled ? Theme.Text : Theme.Muted, new Rectangle(S(12), 0, Width - S(40), Height));
        Theme.Draw(g, "", new Font(Theme.Icons.FontFamily, 7.5f), Theme.Muted, new Rectangle(Width - S(30), 0, S(20), Height), TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
    }
}

/// <summary>Rounded host around a borderless TextBox (search field).</summary>
public sealed class SearchBox : DBControl
{
    public TextBox Box { get; } = new() { BorderStyle = BorderStyle.None, BackColor = Theme.In, ForeColor = Theme.Text, Font = Theme.Base };
    bool _focus;

    public SearchBox(string placeholder)
    {
        Height = 34;
        BackColor = Color.Transparent;
        Box.PlaceholderText = placeholder;
        Controls.Add(Box);
        Box.GotFocus += (_, _) => { _focus = true; Invalidate(); };
        Box.LostFocus += (_, _) => { _focus = false; Invalidate(); };
        Click += (_, _) => Box.Focus();
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        Box.Location = new Point(S(34), (Height - Box.Height) / 2);
        Box.Width = Width - S(44);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Theme.Hq(g);
        var r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
        using (var b = new SolidBrush(Theme.In)) Theme.FillRound(g, b, r, S(8));
        using (var p = new Pen(_focus ? Theme.Orange : Theme.Border)) Theme.DrawRound(g, p, r, S(8));
        Theme.Draw(g, Theme.GSearch, Theme.Icons, Theme.Muted, new Rectangle(S(8), 0, S(22), Height), TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
    }
}

/// <summary>List of scan paths with a remove (×) button per row (web ".paths-list").</summary>
public sealed class PathList : DBControl
{
    public List<string> Paths { get; } = new();
    public event EventHandler? Changed;
    int _hoverRemove = -1, _hoverRow = -1;
    int RowH => S(34);
    int Gap => S(5);

    public PathList() { BackColor = Color.Transparent; }

    public void Set(IEnumerable<string> paths) { Paths.Clear(); Paths.AddRange(paths); Changed?.Invoke(this, EventArgs.Empty); Reflow(); }
    public void Add(string p) { if (!Paths.Contains(p, StringComparer.OrdinalIgnoreCase)) { Paths.Add(p); Changed?.Invoke(this, EventArgs.Empty); Reflow(); } }

    void Reflow() { Height = Math.Max(S(34), Paths.Count * (RowH + Gap) - Gap); Invalidate(); Parent?.PerformLayout(); }

    Rectangle RemoveRect(int i) => new(Width - S(30), i * (RowH + Gap) + (RowH - S(22)) / 2, S(22), S(22));

    protected override void OnMouseMove(MouseEventArgs e)
    {
        int row = e.Y / (RowH + Gap);
        int hr = row < Paths.Count && RemoveRect(row).Contains(e.Location) ? row : -1;
        if (hr != _hoverRemove || row != _hoverRow) { _hoverRemove = hr; _hoverRow = row; Invalidate(); }
        Cursor = hr >= 0 ? Cursors.Hand : Cursors.Default;
        base.OnMouseMove(e);
    }

    protected override void OnMouseLeave(EventArgs e) { _hoverRemove = _hoverRow = -1; Invalidate(); base.OnMouseLeave(e); }

    protected override void OnMouseClick(MouseEventArgs e)
    {
        base.OnMouseClick(e);
        if (!Enabled || _hoverRemove < 0 || _hoverRemove >= Paths.Count) return;
        Paths.RemoveAt(_hoverRemove);
        _hoverRemove = -1;
        Changed?.Invoke(this, EventArgs.Empty);
        Reflow();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Theme.Hq(g);
        if (Paths.Count == 0)
        {
            Theme.Draw(g, "No folders selected — add one below.", Theme.Small, Theme.Muted, ClientRectangle);
            return;
        }
        for (int i = 0; i < Paths.Count; i++)
        {
            var r = new RectangleF(0.5f, i * (RowH + Gap) + 0.5f, Width - 1.5f, RowH - 1);
            using (var b = new SolidBrush(Theme.In)) Theme.FillRound(g, b, r, S(7));
            using (var p = new Pen(i == _hoverRow ? Theme.BorderHover : Theme.Border)) Theme.DrawRound(g, p, r, S(7));
            Theme.Draw(g, Theme.GFolder, Theme.Icons, Theme.Orange, new Rectangle(S(9), (int)r.Y, S(18), RowH), TextFormatFlags.VerticalCenter | TextFormatFlags.HorizontalCenter);
            Theme.Draw(g, Paths[i], Theme.Mono, Enabled ? Theme.Text : Theme.Muted, new Rectangle(S(32), (int)r.Y, Width - S(68), RowH),
                TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.PathEllipsis);
            if (Enabled)
            {
                var rr = RemoveRect(i);
                if (i == _hoverRemove) using (var hb = new SolidBrush(Theme.Alpha(Theme.Crit, 0.15))) Theme.FillRound(g, hb, rr, S(4));
                Theme.Draw(g, Theme.GClose, new Font(Theme.Icons.FontFamily, 7.5f), i == _hoverRemove ? Theme.Crit : Theme.Muted, rr, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
            }
        }
    }
}

/// <summary>Dashed drop target; click opens a file picker (web ".upzone").</summary>
public sealed class DropZone : DBControl
{
    bool _hover, _over;
    public string Line1 { get; set; } = "Drop files or folders here";
    public string Line2 { get; set; } = "";

    public DropZone() { AllowDrop = true; Cursor = Cursors.Hand; BackColor = Color.Transparent; }

    public void SetDragOver(bool v) { _over = v; Invalidate(); }
    protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { _hover = false; Invalidate(); base.OnMouseLeave(e); }
    protected override void OnDragLeave(EventArgs e) { SetDragOver(false); base.OnDragLeave(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Theme.Hq(g);
        bool hot = (_hover || _over) && Enabled;
        var r = new RectangleF(1, 1, Width - 3, Height - 3);
        using (var b = new SolidBrush(hot ? Theme.Over(Theme.Orange, 0.10, Theme.In) : Theme.In)) Theme.FillRound(g, b, r, S(12));
        using (var p = new Pen(hot ? Theme.Orange : Theme.Border, S(2)) { DashStyle = DashStyle.Dash }) Theme.DrawRound(g, p, r, S(12));
        int y = Height / 2 - S(38);
        Theme.Draw(g, "", new Font(Theme.Icons.FontFamily, 18f), hot ? Theme.Orange : Theme.Muted, new Rectangle(0, y, Width, S(32)), TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        Theme.Draw(g, Line1, Theme.Bold, Theme.Text, new Rectangle(0, y + S(36), Width, S(20)), TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        Theme.Draw(g, Line2, Theme.Small, Theme.Muted, new Rectangle(S(12), y + S(58), Width - S(24), S(30)), TextFormatFlags.HorizontalCenter | TextFormatFlags.Top | TextFormatFlags.WordBreak);
    }
}

/// <summary>Stat tile (web ".scard"): tinted background, big number, small label.</summary>
public sealed class Tile : DBControl
{
    public string Value { get => _value; set { if (_value != value) { _value = value; Invalidate(); } } }
    string _value = "0";
    public string Caption { get; set; }
    public Color Accent { get; set; }
    public bool Tinted { get; set; }
    public string Glyph { get; set; }

    public Tile(string caption, Color accent, bool tinted, string glyph = "")
    {
        Caption = caption; Accent = accent; Tinted = tinted; Glyph = glyph;
        Height = 104;
        BackColor = Color.Transparent;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Theme.Hq(g);
        var r = new RectangleF(0.5f, 0.5f, Width - 1.5f, Height - 1.5f);
        using (var b = new SolidBrush(Tinted ? Theme.Over(Accent, 0.07, Theme.Card) : Theme.El)) Theme.FillRound(g, b, r, S(12));
        using (var p = new Pen(Tinted ? Theme.Over(Accent, 0.22, Theme.Card) : Theme.Border)) Theme.DrawRound(g, p, r, S(12));
        int x = S(14);
        if (Glyph.Length > 0)
            Theme.Draw(g, Glyph, Theme.Icons, Tinted ? Accent : Theme.Muted, new Rectangle(x, S(10), S(20), S(20)));
        else
            using (var dot = new SolidBrush(Accent)) g.FillEllipse(dot, x, S(15), S(10), S(10));
        Theme.Draw(g, Value, Theme.Big, Tinted ? Accent : Theme.Text, new Rectangle(x - S(3), S(28), Width - x, S(40)));
        Theme.Draw(g, Caption, Theme.Small, Theme.Muted, new Rectangle(x, Height - S(28), Width - x, S(20)));
    }
}

/// <summary>Rounded orange progress bar.</summary>
public sealed class ProgressStrip : DBControl
{
    double _value;
    public double Value { get => _value; set { _value = Math.Clamp(value, 0, 1); Invalidate(); } }
    public ProgressStrip() { Height = 8; BackColor = Color.Transparent; }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Theme.Hq(g);
        var r = new RectangleF(0, 0, Width - 1, Height - 1);
        using (var b = new SolidBrush(Theme.El)) Theme.FillRound(g, b, r, Height / 2f);
        if (_value <= 0) return;
        var f = new RectangleF(0, 0, Math.Max(Height, (float)((Width - 1) * _value)), Height - 1);
        using var gb = new LinearGradientBrush(new RectangleF(0, 0, Width, Height), Theme.Orange, Theme.OrangeDeep, 0f);
        Theme.FillRound(g, gb, f, Height / 2f);
    }
}

/// <summary>Donut chart + legend with per-confidence counts (web "PII Type Breakdown").</summary>
public sealed class Breakdown : DBControl
{
    public List<(string Type, int High, int Medium, int Low)> Items { get; private set; } = new();
    public void SetItems(IEnumerable<(string, int, int, int)> items)
    {
        Items = items.OrderByDescending(i => i.Item2 + i.Item3 + i.Item4).ToList();
        Height = Math.Max(S(220), S(64) + Items.Count * S(30));
        Invalidate();
    }

    public Breakdown() { BackColor = Color.Transparent; Height = 220; }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Theme.Hq(g);
        int total = Items.Sum(i => i.High + i.Medium + i.Low);
        int d = S(170), cx = S(8), cy = S(10);
        var ring = new RectangleF(cx, cy, d, d);
        float start = -90;
        using (var bg = new Pen(Theme.El, S(22))) g.DrawEllipse(bg, RectangleF.Inflate(ring, -S(11), -S(11)));
        if (total > 0)
            foreach (var it in Items)
            {
                float sweep = 360f * (it.High + it.Medium + it.Low) / total;
                using var p = new Pen(Theme.TypeColor(it.Type), S(22));
                g.DrawArc(p, RectangleF.Inflate(ring, -S(11), -S(11)), start, Math.Max(0.5f, sweep - 1.2f));
                start += sweep;
            }
        Theme.Draw(g, total.ToString("N0"), Theme.Title, Theme.Text, new Rectangle(cx, cy + d / 2 - S(18), d, S(24)), TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        Theme.Draw(g, "total PII", Theme.Small, Theme.Muted, new Rectangle(cx, cy + d / 2 + S(4), d, S(18)), TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);

        // legend table
        int x = cx + d + S(30), w = Width - x - S(4);
        if (w < S(200)) return;
        int colH = x + (int)(w * 0.42), colM = colH + (int)(w * 0.14), colL = colM + (int)(w * 0.14), colT = colL + (int)(w * 0.14);
        int y = S(6);
        void Head(string s, int at, Color c) => Theme.Draw(g, s, Theme.SmallBold, c, new Rectangle(at, y, S(80), S(20)));
        Head("TYPE", x, Theme.Muted); Head("HIGH", colH, Theme.Crit); Head("MEDIUM", colM, Theme.Med); Head("LOW", colL, Theme.Muted); Head("TOTAL", colT, Theme.Muted);
        y += S(26);
        int max = Items.Count > 0 ? Items.Max(i => i.High + i.Medium + i.Low) : 1;
        foreach (var it in Items)
        {
            int t = it.High + it.Medium + it.Low;
            var c = Theme.TypeColor(it.Type);
            using (var b = new SolidBrush(c)) g.FillEllipse(b, x, y + S(9), S(9), S(9));
            Theme.Draw(g, it.Type.Replace('_', ' '), Theme.Base, Theme.Text, new Rectangle(x + S(16), y, colH - x - S(20), S(26)));
            // proportion bar under the name
            float bw = (colH - x - S(24)) * (float)t / Math.Max(1, max);
            using (var bb = new SolidBrush(Theme.Alpha(c, 0.35))) g.FillRectangle(bb, x + S(16), y + S(24), bw, S(2));
            Theme.Draw(g, it.High.ToString("N0"), Theme.Base, Theme.Text, new Rectangle(colH, y, S(80), S(26)));
            Theme.Draw(g, it.Medium.ToString("N0"), Theme.Base, Theme.Text, new Rectangle(colM, y, S(80), S(26)));
            Theme.Draw(g, it.Low.ToString("N0"), Theme.Base, Theme.Muted, new Rectangle(colL, y, S(80), S(26)));
            Theme.Draw(g, t.ToString("N0"), Theme.Bold, Theme.Text, new Rectangle(colT, y, S(90), S(26)));
            y += S(30);
        }
        if (Items.Count == 0) Theme.Draw(g, "No PII detected yet.", Theme.Base, Theme.Muted, new Rectangle(x, y, w, S(26)));
    }
}

/// <summary>Location classification: counts + stacked bar (web "Location Classification").</summary>
public sealed class LocationView : DBControl
{
    public Dictionary<string, int> Counts { get; set; } = new();
    static readonly (string Key, string Label, string Hint)[] Keys =
    [
        ("violation", "Policy violation", "PII in a location this role must not use (Downloads, Desktop, personal cloud, USB…)"),
        ("review", "Needs review", "PII outside approved and disallowed locations"),
        ("expected_location", "Expected location", "PII in an approved share for this role"),
    ];

    public LocationView() { BackColor = Color.Transparent; Height = 150; }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Theme.Hq(g);
        int total = Keys.Sum(k => Counts.GetValueOrDefault(k.Key));
        var bar = new RectangleF(0, S(4), Width - 1, S(12));
        using (var bb = new SolidBrush(Theme.El)) Theme.FillRound(g, bb, bar, S(6));
        if (total > 0)
        {
            var clip = Theme.Round(bar, S(6));
            g.SetClip(clip);
            float x = 0;
            foreach (var k in Keys)
            {
                float w = (Width - 1) * Counts.GetValueOrDefault(k.Key) / (float)total;
                using var b = new SolidBrush(Theme.LocationColors[k.Key]);
                g.FillRectangle(b, x, bar.Y, w, bar.Height);
                x += w;
            }
            g.ResetClip();
            clip.Dispose();
        }
        int cw = Width / Keys.Length, y = S(30);
        for (int i = 0; i < Keys.Length; i++)
        {
            var (key, label, hint) = Keys[i];
            int x = i * cw, n = Counts.GetValueOrDefault(key);
            var c = Theme.LocationColors[key];
            using (var b = new SolidBrush(c)) g.FillEllipse(b, x, y + S(6), S(9), S(9));
            Theme.Draw(g, label, Theme.Label, Theme.Muted, new Rectangle(x + S(16), y, cw - S(20), S(20)));
            Theme.Draw(g, n.ToString("N0"), Theme.Big, c, new Rectangle(x + S(13), y + S(18), cw - S(20), S(40)));
            Theme.Draw(g, hint, Theme.Small, Theme.Muted, new Rectangle(x + S(16), y + S(60), cw - S(28), S(48)), TextFormatFlags.Left | TextFormatFlags.Top | TextFormatFlags.WordBreak);
        }
    }
}

/// <summary>Wrapping row of "type ×count" chips (live PII so far).</summary>
public sealed class ChipsView : DBControl
{
    public List<(string Type, int Count)> Items { get; set; } = new();
    public ChipsView() { BackColor = Color.Transparent; Height = 34; }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Theme.Hq(g);
        if (Items.Count == 0) { Theme.Draw(g, "Nothing yet.", Theme.Small, Theme.Muted, ClientRectangle); return; }
        int x = 0, y = 0, h = S(26);
        foreach (var (t, n) in Items)
        {
            string s = $"{t.Replace('_', ' ')}  {n:N0}";
            int w = TextRenderer.MeasureText(s, Theme.Small).Width + S(18);
            if (x + w > Width && x > 0) { x = 0; y += h + S(6); }
            var c = Theme.TypeColor(t);
            var r = new RectangleF(x, y, w, h);
            using (var b = new SolidBrush(Theme.Over(c, 0.14, Theme.Card))) Theme.FillRound(g, b, r, h / 2f);
            using (var p = new Pen(Theme.Over(c, 0.35, Theme.Card))) Theme.DrawRound(g, p, r, h / 2f);
            Theme.Draw(g, s, Theme.Small, c, Rectangle.Round(r), TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
            x += w + S(6);
        }
        int need = y + h + 2;
        if (Height != need) BeginInvoke(() => { Height = need; Parent?.PerformLayout(); });
    }
}

/// <summary>Sidebar navigation entry (Windows 11 style: accent pill on the selected item).</summary>
public sealed class NavItem : DBControl
{
    public string Glyph { get; }
    public bool Selected { get => _sel; set { _sel = value; Invalidate(); } }
    public string Badge { get => _badge; set { if (_badge != value) { _badge = value; Invalidate(); } } }
    bool _sel, _hover;
    string _badge = "";

    public NavItem(string text, string glyph) { Text = text; Glyph = glyph; Height = 40; Cursor = Cursors.Hand; BackColor = Theme.Bg; }

    protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { _hover = false; Invalidate(); base.OnMouseLeave(e); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(Theme.Bg);
        Theme.Hq(g);
        var r = new RectangleF(S(8), S(2), Width - S(16), Height - S(4));
        if (_sel || _hover)
            using (var b = new SolidBrush(_sel ? Theme.El : Theme.Over(Theme.El, 0.6, Theme.Bg))) Theme.FillRound(g, b, r, S(6));
        if (_sel)
            using (var a = new SolidBrush(Theme.Orange)) Theme.FillRound(g, a, new RectangleF(S(8), Height / 2f - S(8), S(3), S(16)), S(2));
        Theme.Draw(g, Glyph, Theme.Icons, _sel ? Theme.Orange : Theme.Muted, new Rectangle(S(22), 0, S(20), Height), TextFormatFlags.VerticalCenter | TextFormatFlags.HorizontalCenter);
        Theme.Draw(g, Text, _sel ? Theme.Bold : Theme.Base, _sel ? Theme.Text : Theme.Hex("#BBBBBB"), new Rectangle(S(54), 0, Width - S(100), Height));
        if (_badge.Length > 0)
        {
            int w = TextRenderer.MeasureText(_badge, Theme.SmallBold).Width + S(12);
            var br = new RectangleF(Width - S(16) - w, Height / 2f - S(10), w, S(20));
            using (var b = new SolidBrush(Theme.Alpha(Theme.Orange, 0.16))) Theme.FillRound(g, b, br, S(10));
            Theme.Draw(g, _badge, Theme.SmallBold, Theme.Orange, Rectangle.Round(br), TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }
    }
}

/// <summary>Brand mark: orange gradient rounded square with "R" (web ".logo").</summary>
public sealed class Logo : DBControl
{
    public Logo() { BackColor = Theme.Bg; Size = new Size(34, 34); }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(Theme.Bg);
        Theme.Hq(g);
        // Risknox mark (same three-bar shape as the Monitor app), drawn on an 18x24 grid.
        float k = Math.Min(Width / 18f, Height / 24f) * 0.9f;
        float ox = (Width - 18 * k) / 2, oy = (Height - 24 * k) / 2;
        PointF P(float x, float y) => new(ox + x * k, oy + y * k);
        using var deep = new SolidBrush(Theme.OrangeDeep);
        using var org = new SolidBrush(Theme.Orange);
        g.FillPolygon(deep, [P(0, 6), P(6, 2), P(6, 22 + 4), P(0, 22)]);
        g.FillPolygon(org, [P(6, 2), P(18, 8), P(18, 14), P(6, 8)]);
        g.FillPolygon(org, [P(6, 14), P(18, 20), P(18, 26), P(6, 20)]);
    }
}

/// <summary>State dot + label (idle / scanning / done / error) for the status bar.</summary>
public sealed class StatusDot : DBControl
{
    public string State { get => _state; set { _state = value; Invalidate(); } }
    string _state = "idle";
    bool _blink;
    readonly System.Windows.Forms.Timer _t = new() { Interval = 600 };

    public StatusDot()
    {
        BackColor = Theme.Card; Height = 24; Width = 120;
        _t.Tick += (_, _) => { _blink = !_blink; Invalidate(); };
        _t.Start();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(BackColor);
        Theme.Hq(g);
        Color c = _state switch { "scanning" => Theme.Orange, "done" => Theme.Low, "error" => Theme.Crit, "stopped" => Theme.Med, _ => Theme.Muted };
        int a = _state == "scanning" && _blink ? 110 : 255;
        using (var b = new SolidBrush(Color.FromArgb(a, c))) g.FillEllipse(b, S(2), Height / 2 - S(4), S(8), S(8));
        Theme.Draw(g, _state.ToUpperInvariant(), Theme.SmallBold, Theme.Text, new Rectangle(S(16), 0, Width - S(16), Height));
    }

    protected override void Dispose(bool disposing) { if (disposing) _t.Dispose(); base.Dispose(disposing); }
}

/// <summary>Painted read-only table (header + rows). Height follows the row count, so put it in
/// a scrolling panel for long lists. Avoids ListView's light theme artefacts.</summary>
public sealed class SimpleTable : DBControl
{
    public sealed record Column(string Title, int Width, bool Right = false); // Width <= 0: fill
    public List<Column> Columns { get; } = new();
    public List<(string[] Cells, bool Strong)> Rows { get; } = new();
    public string EmptyText { get; set; } = "";
    int HeaderH => S(30);
    int RowH => S(28);

    public SimpleTable() { BackColor = Theme.Card; }

    public void SetRows(IEnumerable<(string[] Cells, bool Strong)> rows)
    {
        Rows.Clear();
        Rows.AddRange(rows);
        Height = HeaderH + Math.Max(1, Rows.Count) * RowH + S(4);
        Invalidate();
    }

    int[] Widths()
    {
        int fixedW = Columns.Where(c => c.Width > 0).Sum(c => S(c.Width));
        int fills = Math.Max(1, Columns.Count(c => c.Width <= 0));
        int fill = Math.Max(S(60), (Width - S(20) - fixedW) / fills); // keep clear of the card edge
        return Columns.Select(c => c.Width > 0 ? S(c.Width) : fill).ToArray();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(BackColor);
        var w = Widths();
        using var line = new Pen(Theme.Border);
        int x = 0;
        for (int i = 0; i < Columns.Count; i++)
        {
            var c = Columns[i];
            var flags = TextFormatFlags.VerticalCenter | (c.Right ? TextFormatFlags.Right : TextFormatFlags.Left);
            Theme.Draw(g, c.Title.ToUpperInvariant(), Theme.SmallBold, Theme.Muted, new Rectangle(x + S(6), 0, w[i] - S(12), HeaderH), flags | TextFormatFlags.NoPadding);
            x += w[i];
        }
        g.DrawLine(line, 0, HeaderH - 1, Width, HeaderH - 1);
        if (Rows.Count == 0 && EmptyText.Length > 0)
            Theme.Draw(g, EmptyText, Theme.Base, Theme.Muted, new Rectangle(S(6), HeaderH, Width - S(12), RowH));
        int y = HeaderH;
        foreach (var (cells, strong) in Rows)
        {
            x = 0;
            for (int i = 0; i < Columns.Count && i < cells.Length; i++)
            {
                var flags = TextFormatFlags.VerticalCenter | (Columns[i].Right ? TextFormatFlags.Right : TextFormatFlags.Left);
                var color = strong || i == 0 ? Theme.Text : Theme.Muted;
                Theme.Draw(g, cells[i], strong ? Theme.Bold : Theme.Base, color, new Rectangle(x + S(6), y, w[i] - S(12), RowH),
                    flags | TextFormatFlags.NoPadding | (i == Columns.Count - 1 ? TextFormatFlags.PathEllipsis : 0));
                x += w[i];
            }
            y += RowH;
            g.DrawLine(line, 0, y - 1, Width, y - 1);
        }
    }
}
