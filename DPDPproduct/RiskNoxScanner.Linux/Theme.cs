// RiskNox visual theme for the Linux UI: same palette, sizes and shapes as the Windows build
// (../RiskNoxScanner/Theme.cs). WinForms point sizes are converted to Avalonia DIPs (pt * 96/72).
// Segoe UI -> Inter (embedded, so the look does not depend on the distro's fonts);
// Segoe Fluent Icons -> vector icons (Icons.cs).
using System.Globalization;
using Avalonia;
using Avalonia.Media;
using Avalonia.Media.Immutable;

namespace RiskNox;

public sealed record UiFont(Typeface Typeface, double Size);

public static class Ui
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
    public static readonly Color NavText = Hex("#BBBBBB");

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

    // ------------------------------------------------------------------ fonts
    public static readonly FontFamily Sans = new("fonts:Inter#Inter, $Default");
    public static readonly FontFamily MonoFamily = new("Cascadia Mono, DejaVu Sans Mono, Liberation Mono, Noto Sans Mono, Ubuntu Mono, monospace");

    static double Pt(double pt) => Math.Round(pt * 96 / 72, 2);
    static UiFont F(double pt, FontWeight w = FontWeight.Normal) => new(new Typeface(Sans, FontStyle.Normal, w), Pt(pt));

    public static readonly UiFont Base = F(9f);
    public static readonly UiFont Small = F(7.75f);
    public static readonly UiFont SmallBold = F(7.75f, FontWeight.SemiBold);
    public static readonly UiFont Label = F(8.25f, FontWeight.SemiBold);
    public static readonly UiFont Bold = F(9.5f, FontWeight.SemiBold);
    public static readonly UiFont Brand = F(11.5f, FontWeight.Bold);
    public static readonly UiFont Title = F(12f, FontWeight.Bold);
    public static readonly UiFont PageTitle = F(16f, FontWeight.Bold);
    public static readonly UiFont Big = F(20f, FontWeight.Bold);
    public static readonly UiFont Huge = F(24f, FontWeight.Bold);
    public static readonly UiFont Mono = new(new Typeface(MonoFamily), Pt(8.25f));

    // ------------------------------------------------------------------ colours / brushes
    public static Color Hex(string s) => Color.Parse(s);
    public static Color Alpha(Color c, double a) => Color.FromArgb((byte)(a * 255), c.R, c.G, c.B);

    /// <summary>Colour <paramref name="c"/> at opacity <paramref name="a"/> over <paramref name="bg"/> (opaque result).</summary>
    public static Color Over(Color c, double a, Color bg) => Color.FromRgb(
        (byte)(c.R * a + bg.R * (1 - a)), (byte)(c.G * a + bg.G * (1 - a)), (byte)(c.B * a + bg.B * (1 - a)));

    static readonly Dictionary<uint, IImmutableSolidColorBrush> _brushes = new();

    public static IImmutableSolidColorBrush B(Color c)
    {
        lock (_brushes)
        {
            if (!_brushes.TryGetValue(c.ToUInt32(), out var b)) _brushes[c.ToUInt32()] = b = new ImmutableSolidColorBrush(c);
            return b;
        }
    }

    public static IPen P(Color c, double thickness = 1, ImmutableDashStyle? dash = null) => new ImmutablePen(B(c), thickness, dash);

    public static readonly ImmutableDashStyle Dash = new ImmutableDashStyle([4, 3], 0);

    public static IBrush OrangeGradient(double angleDeg = 35) => new LinearGradientBrush
    {
        StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
        EndPoint = angleDeg == 0 ? new RelativePoint(1, 0, RelativeUnit.Relative) : new RelativePoint(1, Math.Tan(angleDeg * Math.PI / 180), RelativeUnit.Relative),
        GradientStops = { new GradientStop(Orange, 0), new GradientStop(OrangeDeep, 1) },
    };

    // ------------------------------------------------------------------ text
    public enum H { Left, Center, Right }
    public enum V { Top, Center }

    public static FormattedText Fmt(string s, UiFont f, Color c) =>
        new(s, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, f.Typeface, f.Size, B(c));

    public static Size Measure(string s, UiFont f) { var t = Fmt(s, f, Text); return new Size(t.WidthIncludingTrailingWhitespace, t.Height); }

    /// <summary>Draw single-line text in <paramref name="r"/> with an end ellipsis when it does not fit
    /// (or word-wrapped when <paramref name="wrap"/>). <paramref name="leading"/> trims from the start (paths).</summary>
    public static void Draw(DrawingContext g, string s, UiFont f, Color c, Rect r, H h = H.Left, V v = V.Center, bool wrap = false, bool leading = false)
    {
        if (string.IsNullOrEmpty(s) || r.Width <= 0) return;
        var t = Fmt(s, f, c);
        t.MaxTextWidth = r.Width;
        if (wrap) { t.MaxTextHeight = Math.Max(f.Size * 1.3, r.Height); t.Trimming = TextTrimming.WordEllipsis; }
        else { t.MaxLineCount = 1; t.Trimming = leading ? TextTrimming.PrefixCharacterEllipsis : TextTrimming.CharacterEllipsis; }
        t.TextAlignment = h switch { H.Center => TextAlignment.Center, H.Right => TextAlignment.Right, _ => TextAlignment.Left };
        double y = v == V.Center ? r.Y + (r.Height - t.Height) / 2 : r.Y;
        using (g.PushClip(new Rect(r.X - 2, r.Y - 4, r.Width + 4, r.Height + 8))) g.DrawText(t, new Point(r.X, y));
    }

    public static void FillRound(DrawingContext g, IBrush b, Rect r, double radius) => g.DrawRectangle(b, null, r, radius, radius);
    public static void DrawRound(DrawingContext g, IPen p, Rect r, double radius) => g.DrawRectangle(null, p, r, radius, radius);
}
