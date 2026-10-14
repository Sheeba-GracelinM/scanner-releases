// Vector icons replacing the Segoe Fluent glyphs of the Windows build (same names as Ui.G*).
// Paths are from Google's Material Icons (Apache License 2.0), 24x24 view box.
using Avalonia;
using Avalonia.Media;

namespace RiskNox;

public static class Icons
{
    static Geometry G(string d) => Geometry.Parse(d);

    public static readonly Geometry Settings = G("M3 17v2h6v-2H3zM3 5v2h10V5H3zm10 16v-2h8v-2h-8v-2h-2v6h2zM7 9v2H3v2h4v2h2V9H7zm14 4v-2H11v2h10zm-6-4h2V7h4V5h-4V3h-2v6z");
    public static readonly Geometry Folder = G("M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z");
    public static readonly Geometry Search = G("M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z");
    public static readonly Geometry Target = G("F1 M12 2A10 10 0 1 1 11.99 2Z M12 4.5A7.5 7.5 0 1 0 12.01 4.5Z M12 7A5 5 0 1 1 11.99 7Z M12 9.5A2.5 2.5 0 1 0 12.01 9.5Z");
    public static readonly Geometry Chart = G("M5 9.2h3V19H5zM10.6 5h2.8v14h-2.8zm5.6 8H19v6h-2.8z");
    public static readonly Geometry Play = G("M8 5v14l11-7z");
    public static readonly Geometry Stop = G("M6 6h12v12H6z");
    public static readonly Geometry Add = G("M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z");
    public static readonly Geometry Close = G("M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z");
    public static readonly Geometry Page = G("M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z");
    public static readonly Geometry Pin = G("M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5c-1.38 0-2.5-1.12-2.5-2.5s1.12-2.5 2.5-2.5 2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z");
    public static readonly Geometry List = G("M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z");
    public static readonly Geometry Download = G("M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z");
    public static readonly Geometry Warn = G("M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z");
    public static readonly Geometry Open = G("M19 19H5V5h7V3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z");
    public static readonly Geometry Clear = G("M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z");
    public static readonly Geometry Chevron = G("M7.41 8.59L12 13.17l4.59-4.58L18 10l-6 6-6-6 1.41-1.41z");
    public static readonly Geometry Upload = G("M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96zM14 13v4h-4v-4H7l5-5 5 5h-3z");

    /// <summary>Draw an icon centred in <paramref name="r"/> at <paramref name="size"/> DIPs.</summary>
    public static void Draw(DrawingContext g, Geometry? icon, Color c, Rect r, double size)
    {
        if (icon == null) return;
        double k = size / 24.0;
        var m = Matrix.CreateScale(k, k) * Matrix.CreateTranslation(r.X + (r.Width - size) / 2, r.Y + (r.Height - size) / 2);
        using (g.PushTransform(m)) g.DrawGeometry(Ui.B(c), null, icon);
    }
}
