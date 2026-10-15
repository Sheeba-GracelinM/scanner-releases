// Modal dialogs: startup password gate (LoginForm), upload-key prompt (ApiKeyForm) and a dark
// message box (MessageBox.Show) — same texts, sizes and behaviour as the Windows build.
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;

namespace RiskNox;

public abstract class DialogWindow : Window
{
    protected readonly TextBlock Err = new() { Height = 20, Foreground = Ui.B(Ui.Crit), FontSize = Ui.Small.Size, Margin = new Thickness(0, 4, 0, 0) };
    protected readonly FlatButton Ok;

    protected DialogWindow(string title, double w, double h, string okText, double okWidth)
    {
        Title = title;
        Width = w; Height = h;
        CanResize = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        Background = Ui.B(Ui.Bg);
        FontFamily = Ui.Sans;
        FontSize = Ui.Base.Size;
        Icon = App.WindowIcon;
        Ok = new FlatButton(okText, ButtonKind.Primary) { Width = okWidth, Height = 34, HorizontalAlignment = HorizontalAlignment.Right };
        Ok.Click += (_, _) => Accept();
        KeyDown += (_, e) =>
        {
            if (e.Key == Key.Enter) { Accept(); e.Handled = true; }
            else if (e.Key == Key.Escape) { Close(false); e.Handled = true; }
        };
    }

    protected abstract void Accept();

    protected static Control Head()
    {
        var p = new DockPanel { Height = 40 };
        var logo = new Logo { Width = 36, Height = 36 };
        DockPanel.SetDock(logo, Dock.Left);
        p.Children.Add(logo);
        p.Children.Add(new TextBlock
        {
            Text = "Risknox", FontSize = Ui.Title.Size, FontWeight = FontWeight.Bold, Foreground = Ui.B(Ui.Text),
            VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(4, 0, 0, 0),
        });
        return p;
    }

    protected void Build(string hint, double hintH, TextBox box)
    {
        var body = new DockPanel { Margin = new Thickness(20, 16, 20, 14) };
        var bar = new Panel { Height = 34 };
        bar.Children.Add(Ok);
        DockPanel.SetDock(bar, Dock.Bottom);
        body.Children.Add(bar);
        var stack = new StackPanel();
        stack.Children.Add(Head());
        stack.Children.Add(new TextBlock { Text = hint, Height = hintH, Foreground = Ui.B(Ui.Muted), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) });
        stack.Children.Add(box);
        stack.Children.Add(Err);
        body.Children.Add(stack);
        Content = body;
        Opened += (_, _) => box.Focus();
    }
}

/// <summary>Startup password gate for the window. The CLI/headless path is not gated.</summary>
public sealed class LoginWindow : DialogWindow
{
    const string Password = "RiskNoX@2024";
    readonly TextBox _pw = new() { PasswordChar = '•', Classes = { "field" } };
    int _tries;

    public LoginWindow() : base("Risknox PII Scanner", 340, 200, "Unlock", 90)
    {
        Build("Enter password to continue", 26, _pw);
    }

    protected override void Accept()
    {
        if (_pw.Text == Password) { Close(true); return; }
        _pw.Clear(); _pw.Focus();
        Err.Text = ++_tries >= 5 ? "Too many attempts." : "Incorrect password.";
        if (_tries >= 5) Close(false);
    }
}

/// <summary>Prompts for the workspace upload key (from the Download Agent page) on first upload.</summary>
public sealed class ApiKeyWindow : DialogWindow
{
    readonly TextBox _key = new() { Classes = { "field" }, FontFamily = Ui.MonoFamily, FontSize = Ui.Mono.Size };
    public string EnteredKey => (_key.Text ?? "").Trim();

    public ApiKeyWindow() : base("Connect to your workspace", 420, 210, "Connect", 100)
    {
        Build("Paste the upload key from the Download Agent page in your workspace.", 40, _key);
    }

    protected override void Accept()
    {
        if (EnteredKey.StartsWith("sk_scan_")) { Close(true); return; }
        Err.Text = "That doesn't look like a valid key — it should start with sk_scan_.";
    }
}

/// <summary>Dark replacement for MessageBox.Show(text, caption, OK, icon).</summary>
public sealed class MessageWindow : Window
{
    public MessageWindow(string text, string caption, bool error)
    {
        Title = caption;
        Width = 440;
        SizeToContent = SizeToContent.Height;
        CanResize = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        Background = Ui.B(Ui.Bg);
        FontFamily = Ui.Sans;
        FontSize = Ui.Base.Size;
        Icon = App.WindowIcon;
        var ok = new FlatButton("OK", ButtonKind.Primary) { Width = 90, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 16, 0, 0) };
        ok.Click += (_, _) => Close();
        KeyDown += (_, e) => { if (e.Key is Key.Enter or Key.Escape) Close(); };
        var icon = new PathIcon
        {
            Data = Icons.Warn, Width = 26, Height = 26, Foreground = Ui.B(error ? Ui.Crit : Ui.Med),
            VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 2, 14, 0),
        };
        var row = new DockPanel();
        DockPanel.SetDock(icon, Dock.Left);
        row.Children.Add(icon);
        row.Children.Add(new SelectableTextBlock { Text = text, TextWrapping = TextWrapping.Wrap, Foreground = Ui.B(Ui.Text) });
        var stack = new StackPanel { Margin = new Thickness(20, 18, 20, 16) };
        stack.Children.Add(row);
        stack.Children.Add(ok);
        Content = stack;
    }

    public static Task Show(Window? owner, string text, string caption, bool error = false)
    {
        var w = new MessageWindow(text, caption, error);
        if (owner is { IsVisible: true }) return w.ShowDialog(owner);
        var tcs = new TaskCompletionSource();
        w.Closed += (_, _) => tcs.TrySetResult();
        w.WindowStartupLocation = WindowStartupLocation.CenterScreen;
        w.Show();
        return tcs.Task;
    }
}
