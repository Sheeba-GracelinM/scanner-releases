// Avalonia application: dark Fluent base theme re-coloured to the RiskNox palette, then the
// main window with the startup password gate on top (same flow as Program.cs on Windows).
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Styling;
using Avalonia.Themes.Fluent;

namespace RiskNox;

public sealed class App : Application
{
    public static List<string> StartFolders { get; set; } = [];

    static WindowIcon? _icon;
    public static WindowIcon WindowIcon => _icon ??= MakeIcon();

    public override void Initialize()
    {
        RequestedThemeVariant = ThemeVariant.Dark;
        Styles.Add(new FluentTheme());

        var r = Resources;
        r["SystemAccentColor"] = Ui.Orange;
        r["SystemAccentColorLight1"] = Ui.Orange;
        r["SystemAccentColorDark1"] = Ui.OrangeDeep;
        // text fields
        r["TextControlBackground"] = Ui.B(Ui.In);
        r["TextControlBackgroundPointerOver"] = Ui.B(Ui.In);
        r["TextControlBackgroundFocused"] = Ui.B(Ui.In);
        r["TextControlBorderBrush"] = Ui.B(Ui.Border);
        r["TextControlBorderBrushPointerOver"] = Ui.B(Ui.BorderHover);
        r["TextControlBorderBrushFocused"] = Ui.B(Ui.Orange);
        r["TextControlForeground"] = Ui.B(Ui.Text);
        r["TextControlForegroundPointerOver"] = Ui.B(Ui.Text);
        r["TextControlForegroundFocused"] = Ui.B(Ui.Text);
        r["TextControlPlaceholderForeground"] = Ui.B(Ui.Muted);
        r["TextControlPlaceholderForegroundPointerOver"] = Ui.B(Ui.Muted);
        r["TextControlPlaceholderForegroundFocused"] = Ui.B(Ui.Muted);
        r["TextControlSelectionHighlightColor"] = Ui.B(Ui.Alpha(Ui.Orange, 0.45));
        r["TextControlBorderThemeThicknessFocused"] = new Thickness(1);
        // scroll bars
        r["ScrollBarThumbFill"] = Ui.B(Ui.BorderHover);
        r["ScrollBarThumbFillPointerOver"] = Ui.B(Ui.Muted);
        r["ScrollBarThumbFillPressed"] = Ui.B(Ui.Muted);

        // Form fields in dialogs (password / key).
        Styles.Add(new Style(x => x.OfType<TextBox>().Class("field"))
        {
            Setters =
            {
                new Setter(TemplatedControl.CornerRadiusProperty, new CornerRadius(6)),
                new Setter(TemplatedControl.PaddingProperty, new Thickness(8, 6)),
                new Setter(Layoutable.MinHeightProperty, 32.0),
                new Setter(TemplatedControl.FontFamilyProperty, Ui.Sans),
            },
        });
        // The search box draws its own rounded frame; the inner TextBox is borderless in every state.
        Styles.Add(new Style(x => x.OfType<TextBox>().Class("search").Template().OfType<Border>().Name("PART_BorderElement"))
        {
            Setters =
            {
                new Setter(Border.BackgroundProperty, Brushes.Transparent),
                new Setter(Border.BorderThicknessProperty, new Thickness(0)),
            },
        });
        // Menus from DarkMenu draw their own frame.
        Styles.Add(new Style(x => x.OfType<FlyoutPresenter>().Class("dark"))
        {
            Setters =
            {
                new Setter(TemplatedControl.BackgroundProperty, Brushes.Transparent),
                new Setter(TemplatedControl.BorderThicknessProperty, new Thickness(0)),
                new Setter(TemplatedControl.PaddingProperty, new Thickness(0)),
                new Setter(Layoutable.MinWidthProperty, 0.0),
                new Setter(Layoutable.MaxWidthProperty, double.PositiveInfinity),
                new Setter(TemplatedControl.CornerRadiusProperty, new CornerRadius(6)),
            },
        });
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.ShutdownMode = ShutdownMode.OnMainWindowClose;
            var main = new MainWindow(StartFolders);
            desktop.MainWindow = main;
            // Password pops up over the main window; closing it exits the app.
            bool gated = false;
            main.Opened += async (_, _) =>
            {
                if (gated) return;
                gated = true;
                var ok = await new LoginWindow().ShowDialog<bool>(main);
                if (!ok) main.Close();
            };
        }
        base.OnFrameworkInitializationCompleted();
    }

    /// <summary>Window/taskbar icon: the Risknox mark on the app background, rendered at startup.</summary>
    static WindowIcon MakeIcon()
    {
        var bmp = new RenderTargetBitmap(new PixelSize(64, 64));
        using (var g = bmp.CreateDrawingContext())
        {
            g.DrawRectangle(Ui.B(Ui.Bg), null, new Rect(0, 0, 64, 64), 14, 14);
            using (g.PushTransform(Matrix.CreateTranslation(8, 8))) Logo.Paint(g, new Size(48, 48));
        }
        using var ms = new MemoryStream();
        bmp.Save(ms);
        ms.Position = 0;
        return new WindowIcon(ms);
    }
}
