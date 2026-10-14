// RiskNox visual theme for the native UI: same palette as the original web UI
// (--bg #090909, --bg-card #111, --orange #FF6B1A, tier colours, ...).
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace RiskNox;

public static class Theme
{
    public static readonly Color Bg = Hex("#090909");
    public static readonly Color Card = Hex("#111111");
    public static readonly Color El = Hex("#181818");
    public static readonly Color In = Hex("#0d0d0d");
    public static readonly Color Border = Hex("#222222");
    public static readonly Color BorderHover = Hex("#333333");
    public static readonly Color Orange = Hex("#FF6B1A");
    public static readonly Color OrangeDeep = Hex("#FF3D00");
    public static readonly Color Text = Hex("#EEEEEE");
    public static readonly Color Muted = Hex("#666666");
    public static readonly Color Dim = Hex("#2c2c2c");
    public static readonly Color Crit = Hex("#FF3B3B");
    public static readonly Color High = Hex("#FF8C00");
    public static readonly Color Med = Hex("#F5C842");
    public static readonly Color Low = Hex("#4ECA6A");

    public static readonly Dictionary<string, Color> TierColors = new()
    {
        ["critical"] = Crit, ["high"] = High, ["medium"] = Med, ["low"] = Low, ["none"] = Muted,
    };

    public static readonly Dictionary<string, Color> LocationColors = new()
    {
        ["violation"] = Crit, ["review"] = Med, ["expected_location"] = Low, ["n/a"] = Muted,
    };

    static readonly Dictionary<string, Color> TypeColors = new()
    {
        ["aadhaar"] = Hex("#FF6B1A"), ["pan"] = Hex("#FF3B3B"), ["card"] = Hex("#FF8C00"),
        ["bank_account"] = Hex("#F5C842"), ["ifsc"] = Hex("#C9A227"), ["passport"] = Hex("#4ECA6A"),
        ["voter_id"] = Hex("#36B5A5"), ["upi"] = Hex("#4EA3FF"), ["phone"] = Hex("#8B7CFF"),
        ["email"] = Hex("#C77DFF"), ["dob"] = Hex("#FF7EB6"),
    };

    public static Color TypeColor(string t) => TypeColors.GetValueOrDefault(t, Muted);

    public static readonly Font Base = new("Segoe UI", 9f);
    public static readonly Font Small = new("Segoe UI", 7.75f);
    public static readonly Font SmallBold = new("Segoe UI Semibold", 7.75f);
    public static readonly Font Label = new("Segoe UI Semibold", 8.25f);
    public static readonly Font Bold = new("Segoe UI Semibold", 9.5f);
    public static readonly Font Brand = new("Segoe UI", 11.5f, FontStyle.Bold);
    public static readonly Font Title = new("Segoe UI", 12f, FontStyle.Bold);
    public static readonly Font Big = new("Segoe UI", 20f, FontStyle.Bold);
    public static readonly Font Huge = new("Segoe UI", 24f, FontStyle.Bold);
    public static readonly Font Mono = new(FontExists("Cascadia Mono") ? "Cascadia Mono" : "Consolas", 8.25f);
    public static readonly Font Icons = new(FontExists("Segoe Fluent Icons") ? "Segoe Fluent Icons" : "Segoe MDL2 Assets", 10f);
    public static readonly Font IconsBig = new(Icons.FontFamily, 26f);

    // Segoe Fluent / MDL2 glyphs
    public const string GSettings = "", GFolder = "", GSearch = "", GTarget = "",
        GChart = "", GPlay = "", GStop = "", GAdd = "", GClose = "",
        GPage = "", GPin = "", GList = "", GDownload = "", GWarn = "", GOpen = "",
        GClear = "";

    public static Color Hex(string s) => ColorTranslator.FromHtml(s);
    public static Color Alpha(Color c, double a) => Color.FromArgb((int)(a * 255), c);

    /// <summary>Colour <paramref name="c"/> at opacity <paramref name="a"/> over <paramref name="bg"/> (opaque result).</summary>
    public static Color Over(Color c, double a, Color bg) => Color.FromArgb(
        (int)(c.R * a + bg.R * (1 - a)), (int)(c.G * a + bg.G * (1 - a)), (int)(c.B * a + bg.B * (1 - a)));

    static bool FontExists(string name)
    {
        using var f = new Font(name, 9f);
        return string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase);
    }

    public static GraphicsPath Round(RectangleF r, float radius)
    {
        var p = new GraphicsPath();
        float d = Math.Min(radius * 2, Math.Min(r.Width, r.Height));
        if (d <= 0) { p.AddRectangle(r); return p; }
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }

    public static void FillRound(Graphics g, Brush b, RectangleF r, float radius)
    {
        using var p = Round(r, radius);
        g.FillPath(b, p);
    }

    public static void DrawRound(Graphics g, Pen pen, RectangleF r, float radius)
    {
        using var p = Round(r, radius);
        g.DrawPath(pen, p);
    }

    public static void Hq(Graphics g)
    {
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
    }

    public static void Draw(Graphics g, string s, Font f, Color c, Rectangle r, TextFormatFlags flags = TextFormatFlags.Left | TextFormatFlags.VerticalCenter) =>
        // Icon glyphs (1-2 chars) must never get an ellipsis; text gets one when it does not fit.
        TextRenderer.DrawText(g, s, f, r, c, flags | TextFormatFlags.NoPrefix | (s.Length <= 2 ? TextFormatFlags.NoClipping : TextFormatFlags.EndEllipsis));

    // -------------------------------------------------------- native dark chrome
    [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)] static extern int SetWindowTheme(IntPtr hwnd, string? app, string? idList);

    public static void DarkTitleBar(IntPtr hwnd)
    {
        int on = 1, caption = ColorTranslator.ToWin32(Bg), border = ColorTranslator.ToWin32(Border), text = ColorTranslator.ToWin32(Text);
        try
        {
            DwmSetWindowAttribute(hwnd, 20, ref on, 4);       // DWMWA_USE_IMMERSIVE_DARK_MODE
            DwmSetWindowAttribute(hwnd, 35, ref caption, 4);  // DWMWA_CAPTION_COLOR (Win11)
            DwmSetWindowAttribute(hwnd, 34, ref border, 4);   // DWMWA_BORDER_COLOR (Win11)
            DwmSetWindowAttribute(hwnd, 36, ref text, 4);     // DWMWA_TEXT_COLOR (Win11)
        }
        catch { }
    }

    /// <summary>Dark scrollbars / header for standard controls (Windows 10 1809+).</summary>
    public static void DarkScrollbars(Control c)
    {
        void Apply() { try { SetWindowTheme(c.Handle, "DarkMode_Explorer", null); } catch { } }
        if (c.IsHandleCreated) Apply(); else c.HandleCreated += (_, _) => Apply();
    }

    [DllImport("user32.dll")] static extern IntPtr SendMessage(IntPtr h, int msg, IntPtr w, IntPtr l);

    public static void DarkListHeader(ListView lv)
    {
        void Apply()
        {
            try
            {
                SetWindowTheme(lv.Handle, "DarkMode_Explorer", null); // dark scrollbars
                IntPtr header = SendMessage(lv.Handle, 0x101F /* LVM_GETHEADER */, IntPtr.Zero, IntPtr.Zero);
                if (header != IntPtr.Zero) SetWindowTheme(header, "DarkMode_ItemsView", null);
            }
            catch { }
        }
        if (lv.IsHandleCreated) Apply(); else lv.HandleCreated += (_, _) => Apply();
    }
}

/// <summary>Dark colours for context menus (used by <see cref="DarkSelect"/>).</summary>
public sealed class DarkMenuRenderer() : ToolStripProfessionalRenderer(new DarkMenuColors())
{
    protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
    {
        e.TextColor = e.Item.Selected ? Color.White : Theme.Text;
        base.OnRenderItemText(e);
    }

    sealed class DarkMenuColors : ProfessionalColorTable
    {
        public override Color ToolStripDropDownBackground => Theme.El;
        public override Color MenuBorder => Theme.BorderHover;
        public override Color MenuItemBorder => Theme.Orange;
        public override Color MenuItemSelected => Theme.Over(Theme.Orange, 0.25, Theme.El);
        public override Color ImageMarginGradientBegin => Theme.El;
        public override Color ImageMarginGradientMiddle => Theme.El;
        public override Color ImageMarginGradientEnd => Theme.El;
        public override Color SeparatorDark => Theme.Border;
    }
}
