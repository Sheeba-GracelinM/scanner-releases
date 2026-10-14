// Prompts for the workspace upload key (from the Download Agent page) on first upload.
namespace RiskNox;

public sealed class ApiKeyForm : Form
{
    readonly TextBox _key = new() { Dock = DockStyle.Top, BorderStyle = BorderStyle.FixedSingle, BackColor = Theme.In, ForeColor = Theme.Text, Font = Theme.Mono };
    readonly Label _err = new() { Dock = DockStyle.Top, Height = 20, ForeColor = Theme.Crit, Font = Theme.Small };

    public string EnteredKey => _key.Text.Trim();

    public ApiKeyForm()
    {
        Text = "Connect to your workspace";
        ClientSize = new Size(420, 210);
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
        var hint = new Label { Text = "Paste the upload key from the Download Agent page in your workspace.", Dock = DockStyle.Top, Height = 40, ForeColor = Theme.Muted };
        var ok = new Button { Text = "Connect", Dock = DockStyle.Right, Width = 100, FlatStyle = FlatStyle.Flat, BackColor = Theme.Orange, ForeColor = Color.Black };
        ok.FlatAppearance.BorderSize = 0;
        var bar = new Panel { Dock = DockStyle.Bottom, Height = 34 };
        bar.Controls.Add(ok);
        var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(20, 16, 20, 14) };
        body.Controls.Add(bar); body.Controls.Add(_err); body.Controls.Add(_key); body.Controls.Add(hint); body.Controls.Add(head);
        Controls.Add(body);
        AcceptButton = ok;
        ok.Click += (_, _) =>
        {
            if (EnteredKey.StartsWith("sk_scan_")) { DialogResult = DialogResult.OK; return; }
            _err.Text = "That doesn't look like a valid key — it should start with sk_scan_.";
        };
    }
}
