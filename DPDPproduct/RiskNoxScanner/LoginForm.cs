// Startup password gate for the window. The CLI/headless path is not gated.
namespace RiskNox;

public sealed class LoginForm : Form
{
    const string Password = "RiskNoX@2024";
    readonly TextBox _pw = new() { UseSystemPasswordChar = true, Dock = DockStyle.Top, BorderStyle = BorderStyle.FixedSingle, BackColor = Theme.In, ForeColor = Theme.Text, Font = Theme.Base };
    readonly Label _err = new() { Dock = DockStyle.Top, Height = 20, ForeColor = Theme.Crit, Font = Theme.Small };
    int _tries;

    public LoginForm()
    {
        Text = "Risknox PII Scanner";
        ClientSize = new Size(340, 200);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        ShowInTaskbar = false;
        BackColor = Theme.Bg;
        Font = Theme.Base;
        Theme.DarkTitleBar(Handle);

        var title = new Label { Text = "Risknox", Dock = DockStyle.Fill, Font = Theme.Title, ForeColor = Theme.Text, TextAlign = ContentAlignment.MiddleLeft };
        var logo = new Logo { Dock = DockStyle.Left, Width = 36 };
        var head = new Panel { Dock = DockStyle.Top, Height = 40 };
        head.Controls.Add(title); head.Controls.Add(logo);
        var hint = new Label { Text = "Enter password to continue", Dock = DockStyle.Top, Height = 26, ForeColor = Theme.Muted };
        var ok = new Button { Text = "Unlock", Dock = DockStyle.Right, Width = 90, FlatStyle = FlatStyle.Flat, BackColor = Theme.Orange, ForeColor = Color.Black };
        ok.FlatAppearance.BorderSize = 0;
        var bar = new Panel { Dock = DockStyle.Bottom, Height = 34 };
        bar.Controls.Add(ok);
        var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20, 16, 20, 14) };
        body.Controls.Add(bar); body.Controls.Add(_err); body.Controls.Add(_pw); body.Controls.Add(hint); body.Controls.Add(head);
        Controls.Add(body);
        AcceptButton = ok;
        ok.Click += (_, _) =>
        {
            if (_pw.Text == Password) { DialogResult = DialogResult.OK; return; }
            _pw.Clear(); _pw.Focus();
            _err.Text = ++_tries >= 5 ? "Too many attempts." : "Incorrect password.";
            if (_tries >= 5) DialogResult = DialogResult.Cancel;
        };
    }
}
