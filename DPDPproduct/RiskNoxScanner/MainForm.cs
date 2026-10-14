// Native Windows UI in the RiskNox theme. Windows 11 app layout:
//   sidebar navigation (Scan / Findings / Insights / Skipped) | page content | status bar
// Results accumulate across scans (re-scanning a file replaces its row), like the web UI did.
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace RiskNox;

public sealed class MainForm : Form
{
    sealed class Row
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

    static readonly string[] Tiers = ["critical", "high", "medium", "low"];

    // ---- state
    readonly Dictionary<string, Row> _rows = new(StringComparer.OrdinalIgnoreCase);
    List<Row> _view = new();
    readonly ConcurrentQueue<Row> _incoming = new();
    readonly Dictionary<string, int> _skipped = new();
    readonly Dictionary<string, int> _unsupported = new();
    readonly List<(string Path, string Reason)> _skippedNotable = new();
    int _filesScanned, _filesSeen;
    double _lastDuration;
    JsonObject? _lastMeta;
    LiveStatus? _live;
    CancellationTokenSource? _cts;
    Task? _scanTask;
    string _tierFilter = "";
    int _sortCol = 0; bool _sortDesc = true;

    // ---- shell
    readonly Panel _content = new() { Dock = DockStyle.Fill, BackColor = Theme.Bg, Padding = new Padding(24, 20, 24, 16) };
    readonly Dictionary<string, (NavItem Nav, Control Page)> _pages = new();
    readonly StatusDot _statusDot = new();
    readonly Label _statusText = new() { AutoSize = false, ForeColor = Theme.Muted, BackColor = Theme.Card, Font = Theme.Small, TextAlign = ContentAlignment.MiddleLeft };
    readonly ProgressStrip _statusProgress = new() { Width = 160, Height = 6, Visible = false };
    readonly Label _engineText = new() { ForeColor = Theme.Muted, BackColor = Theme.Card, Font = Theme.Small };

    // ---- scan page
    readonly DarkSelect _role = new();
    readonly DarkSelect _maxMb = new();
    readonly DarkSelect _workers = new();
    readonly PathList _paths = new();
    readonly FlatButton _addFolder = new("Add folder", ButtonKind.Ghost, Theme.GAdd);
    readonly FlatButton _defaults = new("Full scan (all drives)", ButtonKind.Ghost);
    readonly FlatButton _start = new("Start scan", ButtonKind.Primary, Theme.GPlay) { Height = 42 };
    readonly DropZone _drop = new() { Height = 170 };
    readonly Card _idleCard = new();
    readonly Card _progressCard = new("Live progress", Theme.GSearch) { Visible = false };
    readonly Label _pct = new() { AutoSize = true, Font = Theme.Huge, ForeColor = Theme.Orange, BackColor = Theme.Card, Text = "0%" };
    readonly Label _elapsed = new() { AutoSize = true, Font = Theme.Mono, ForeColor = Theme.Muted, BackColor = Theme.Card };
    readonly ProgressStrip _bar = new();
    readonly Tile _tSeen = new("Files found", Theme.Muted, false, Theme.GList);
    readonly Tile _tScanned = new("Scanned", Theme.Muted, false, Theme.GPage);
    readonly Tile _tPii = new("Files with PII", Theme.Orange, true, Theme.GWarn);
    readonly Tile _tCache = new("Cache hits", Theme.Muted, false, Theme.GDownload);
    readonly Label _currentFile = new() { AutoEllipsis = true, Font = Theme.Mono, ForeColor = Theme.Muted, BackColor = Theme.Card, Height = 20 };
    readonly ChipsView _liveTypes = new();
    readonly Dictionary<string, Tile> _tierTiles = new();
    readonly Tile _iScanned = new("Files scanned", Theme.Text, false, Theme.GPage);
    readonly Tile _iWithPii = new("Files with PII", Theme.Text, false, Theme.GWarn);
    readonly Tile _iDuration = new("Duration (s)", Theme.Text, false, "");

    // ---- findings page
    readonly SearchBox _search = new("Search path or PII type…") { Width = 280 };
    readonly List<FlatButton> _chips = new();
    readonly ListView _list = new()
    {
        View = View.Details, FullRowSelect = true, VirtualMode = true, OwnerDraw = true, Dock = DockStyle.Fill,
        BorderStyle = BorderStyle.None, BackColor = Theme.Card, ForeColor = Theme.Text, HideSelection = false, MultiSelect = false,
    };
    readonly Label _emptyFindings = new() { ForeColor = Theme.Muted, BackColor = Theme.Card, TextAlign = ContentAlignment.MiddleCenter, Dock = DockStyle.Fill };
    readonly Panel _details = new() { Dock = DockStyle.Right, Width = 340, BackColor = Theme.Bg, Padding = new Padding(14, 0, 0, 0) };
    readonly Card _detailCard = new("Details", Theme.GPage);
    readonly Label _dName = new() { Font = Theme.Bold, ForeColor = Theme.Text, BackColor = Theme.Card, AutoEllipsis = true, Height = 24 };
    readonly Label _dPath = new() { Font = Theme.Mono, ForeColor = Theme.Muted, BackColor = Theme.Card, Height = 48 };
    readonly Label _dMeta = new() { Font = Theme.Small, ForeColor = Theme.Text, BackColor = Theme.Card, Height = 84 };
    readonly SimpleTable _dTypes = new();
    readonly FlatButton _dExplorer = new("Show in Explorer", ButtonKind.Secondary, Theme.GOpen) { Height = 36 };

    // ---- insights / skipped pages
    readonly Breakdown _breakdown = new();
    readonly LocationView _locations = new();
    readonly SimpleTable _skipList = new() { EmptyText = "Nothing skipped yet." };

    readonly System.Windows.Forms.Timer _timer = new() { Interval = 250 };

    public MainForm(List<string>? folders = null)
    {
        AutoScaleDimensions = new SizeF(96f, 96f);
        AutoScaleMode = AutoScaleMode.Dpi;
        Text = "Risknox PII Scanner";
        Font = Theme.Base;
        BackColor = Theme.Bg;
        ForeColor = Theme.Text;
        StartPosition = FormStartPosition.CenterScreen;
        Size = new Size(1360, 880);
        MinimumSize = new Size(1080, 680);
        try { Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath!); } catch { }

        foreach (var (k, label) in new[] { ("general", "General — Desktop, Documents, Downloads"), ("hr", "HR — includes HR share paths"), ("finance", "Finance — includes Finance share paths") })
            if (Profile.All.ContainsKey(k)) _role.Options.Add((k, label));
        foreach (var k in Profile.All.Keys.Where(k => _role.Options.All(o => o.Value != k))) _role.Options.Add((k, k));
        foreach (var mb in new[] { 10, 25, 50, 100, 250, 500 }) _maxMb.Options.Add((mb.ToString(), $"{mb} MB"));
        _maxMb.Value = "50";
        int cores = Math.Max(1, Environment.ProcessorCount);
        foreach (var w in Enumerable.Range(1, cores)) _workers.Options.Add((w.ToString(), w == Math.Max(1, cores - 1) ? $"{w} (recommended)" : w.ToString()));
        _workers.Value = Math.Max(1, cores - 1).ToString();
        _role.Value = "general";

        if (folders is { Count: > 0 }) _paths.Set(folders.Select(f => Path.GetFullPath(Scanner.ExpandUser(f))));
        else ResetDefaultFolders();

        BuildShell();
        WireEvents();
        UpdateEngineText();
        ShowPage("scan");
        RefreshAll();
        ShowDetail();
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        Theme.DarkTitleBar(Handle);
    }

    // ================================================================== layout helpers
    static Label Caption(string s) => new()
    {
        Text = s.ToUpperInvariant(), Font = Theme.SmallBold, ForeColor = Theme.Muted, BackColor = Theme.Card,
        AutoSize = false, Height = 22, TextAlign = ContentAlignment.BottomLeft,
    };

    static Panel Gap(int h, Color? bg = null) => new() { Height = h, BackColor = bg ?? Theme.Card };

    /// <summary>Stack controls top-to-bottom inside a container (Dock=Top, added in reverse).</summary>
    static void Stack(Control parent, params Control[] items)
    {
        foreach (var c in items.Reverse()) { c.Dock = DockStyle.Top; parent.Controls.Add(c); }
    }

    /// <summary>Size a card to its docked children.</summary>
    static void Fit(Card c) => c.Height = c.Padding.Vertical + c.Controls.Cast<Control>().Where(x => x.Visible && x.Dock == DockStyle.Top).Sum(x => x.Height);

    static Panel ScrollPage()
    {
        var p = new Panel { Dock = DockStyle.Fill, AutoScroll = true, BackColor = Theme.Bg };
        Theme.DarkScrollbars(p);
        return p;
    }

    /// <summary>Equal-width row of controls.</summary>
    static TableLayoutPanel HRow(int height, Color bg, params Control[] items)
    {
        var t = new TableLayoutPanel { Height = height, ColumnCount = items.Length, RowCount = 1, BackColor = bg, Margin = Padding.Empty, Padding = Padding.Empty };
        t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        for (int i = 0; i < items.Length; i++)
        {
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / items.Length));
            items[i].Dock = DockStyle.Fill;
            items[i].Margin = new Padding(i == 0 ? 0 : 5, 0, i == items.Length - 1 ? 0 : 5, 0);
            t.Controls.Add(items[i], i, 0);
        }
        return t;
    }

    static Control PageHeader(string title, string sub)
    {
        var p = new Panel { Height = 62, BackColor = Theme.Bg };
        p.Controls.Add(new Label { Text = title, Font = new Font("Segoe UI", 16f, FontStyle.Bold), ForeColor = Theme.Text, BackColor = Theme.Bg, AutoSize = true, Location = new Point(-2, 0) });
        p.Controls.Add(new Label { Text = sub, ForeColor = Theme.Muted, BackColor = Theme.Bg, AutoSize = true, Location = new Point(0, 34) });
        return p;
    }

    // ================================================================== shell
    void BuildShell()
    {
        // sidebar
        var side = new Panel { Dock = DockStyle.Left, Width = 236, BackColor = Theme.Bg, Padding = new Padding(0, 14, 0, 14) };
        var brand = new Panel { Dock = DockStyle.Top, Height = 66, BackColor = Theme.Bg };
        brand.Controls.Add(new Logo { Location = new Point(20, 10) });
        brand.Controls.Add(new Label { Text = "Risknox", Font = Theme.Brand, ForeColor = Theme.Text, BackColor = Theme.Bg, AutoSize = true, Location = new Point(64, 8) });
        brand.Controls.Add(new Label { Text = "PII Scanner · DPDP", Font = Theme.Small, ForeColor = Theme.Muted, BackColor = Theme.Bg, AutoSize = true, Location = new Point(66, 32) });
        var nav = new Panel { Dock = DockStyle.Top, Height = 4 * 42 + 10, BackColor = Theme.Bg };
        var foot = new Label
        {
            Dock = DockStyle.Bottom, Height = 64, ForeColor = Theme.Muted, BackColor = Theme.Bg, Font = Theme.Small, Padding = new Padding(20, 0, 16, 0),
            Text = "Endpoint PII posture only — not a DPDP compliance verdict. File contents are never stored.",
        };
        side.Controls.Add(nav);
        side.Controls.Add(brand);
        side.Controls.Add(foot);
        var sideLine = new Panel { Dock = DockStyle.Left, Width = 1, BackColor = Theme.Border };

        // status bar
        var status = new Panel { Dock = DockStyle.Bottom, Height = 32, BackColor = Theme.Card, Padding = new Padding(16, 0, 16, 0) };
        var statusLine = new Panel { Dock = DockStyle.Bottom, Height = 1, BackColor = Theme.Border };
        _statusDot.Dock = DockStyle.Left; _statusDot.Width = 110;
        var progHost = new Panel { Dock = DockStyle.Left, Width = 176, BackColor = Theme.Card };
        progHost.Controls.Add(_statusProgress);
        progHost.Resize += (_, _) => _statusProgress.Location = new Point(0, (progHost.Height - _statusProgress.Height) / 2);
        _statusText.Dock = DockStyle.Fill;
        _engineText.Dock = DockStyle.Right; _engineText.Width = 420; _engineText.TextAlign = ContentAlignment.MiddleRight;
        status.Controls.Add(_statusText);
        status.Controls.Add(progHost);
        status.Controls.Add(_statusDot);
        status.Controls.Add(_engineText);

        AddPage("scan", "Scan", Theme.GSearch, BuildScanPage(), nav, 0);
        AddPage("findings", "Findings", Theme.GList, BuildFindingsPage(), nav, 1);
        AddPage("insights", "Insights", Theme.GChart, BuildInsightsPage(), nav, 2);
        AddPage("skipped", "Skipped files", Theme.GWarn, BuildSkippedPage(), nav, 3);

        Controls.Add(_content);
        Controls.Add(sideLine);
        Controls.Add(side);
        Controls.Add(statusLine);
        Controls.Add(status);
    }

    void AddPage(string key, string title, string glyph, Control page, Panel nav, int index)
    {
        var item = new NavItem(title, glyph) { Width = 236, Location = new Point(0, 4 + index * 42) };
        item.Click += (_, _) => ShowPage(key);
        nav.Controls.Add(item);
        page.Visible = false;
        _content.Controls.Add(page);
        _pages[key] = (item, page);
    }

    void ShowPage(string key)
    {
        foreach (var (k, (nav, page)) in _pages)
        {
            nav.Selected = k == key;
            page.Visible = k == key;
        }
    }

    // ================================================================== scan page
    Control BuildScanPage()
    {
        var page = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, BackColor = Theme.Bg };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 420));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var left = ScrollPage(); left.Padding = new Padding(0, 0, 10, 0); left.Margin = Padding.Empty;
        var right = ScrollPage(); right.Padding = new Padding(10, 0, 4, 0); right.Margin = Padding.Empty;
        grid.Controls.Add(left, 0, 0);
        grid.Controls.Add(right, 1, 0);

        var header = PageHeader("Scan this computer", "Find Aadhaar, PAN, card, bank and other personal data in local files.");
        header.Dock = DockStyle.Top;
        page.Controls.Add(grid);
        page.Controls.Add(header);

        var cfg = new Card("Scan configuration", Theme.GSettings);
        var pathButtons = HRow(36, Theme.Card, _addFolder, _defaults);
        var limits = HRow(22, Theme.Card, Caption("Max file size"), Caption("Parallel workers"));
        var limitSel = HRow(34, Theme.Card, _maxMb, _workers);
        Stack(cfg, Caption("Folders to scan"), Gap(6), _paths, Gap(8), pathButtons,
            Gap(14), limits, Gap(6), limitSel, Gap(20), _start);
        _paths.Resize += (_, _) => Fit(cfg);
        Fit(cfg);

        var fileCard = new Card("Scan specific files", Theme.GFolder);
        _drop.Line1 = "Drop files or folders here";
        _drop.Line2 = "or click to choose files · .pdf .docx .xlsx .pptx .csv .txt .json .xml .log .eml .png .jpg";
        Stack(fileCard, _drop);
        Fit(fileCard);

        Stack(left, cfg, Gap(14, Theme.Bg), fileCard, Gap(8, Theme.Bg));

        var idleIcon = new Label { Text = Theme.GSearch, Font = Theme.IconsBig, ForeColor = Theme.Orange, BackColor = Theme.Card, TextAlign = ContentAlignment.MiddleCenter, Height = 70 };
        var idleTitle = new Label { Text = "Ready to scan", Font = Theme.Title, ForeColor = Theme.Text, BackColor = Theme.Card, TextAlign = ContentAlignment.MiddleCenter, Height = 30 };
        var idleText = new Label
        {
            Text = "Choose folders on the left and press Start scan — or drop files to scan them instantly.",
            ForeColor = Theme.Muted, BackColor = Theme.Card, TextAlign = ContentAlignment.MiddleCenter, Height = 26,
        };
        var idleDetects = new Label
        {
            Text = "Detects: Aadhaar · PAN · Passport · Bank account · IFSC · Credit/Debit card · UPI · Voter ID · DOB · Phone · Email",
            ForeColor = Theme.Muted, BackColor = Theme.Card, Font = Theme.Small, TextAlign = ContentAlignment.MiddleCenter, Height = 44, Padding = new Padding(24, 0, 24, 0),
        };
        Stack(_idleCard, Gap(18), idleIcon, idleTitle, idleText, idleDetects, Gap(10));
        Fit(_idleCard);

        var pctRow = new Panel { Height = 56, BackColor = Theme.Card };
        pctRow.Controls.Add(_pct);
        pctRow.Controls.Add(_elapsed);
        void PlaceElapsed() => _elapsed.Location = new Point(pctRow.Width - _elapsed.Width, 22);
        pctRow.Resize += (_, _) => { _pct.Location = new Point(-4, 0); PlaceElapsed(); };
        _elapsed.TextChanged += (_, _) => PlaceElapsed();
        _bar.Height = 10;
        var tiles = HRow(104, Theme.Card, _tSeen, _tScanned, _tPii, _tCache);
        _liveTypes.Resize += (_, _) => Fit(_progressCard);
        Stack(_progressCard, pctRow, _bar, Gap(16), tiles, Gap(14), Caption("Currently scanning"), Gap(4), _currentFile, Gap(10), Caption("PII detected so far"), Gap(6), _liveTypes);
        Fit(_progressCard);

        var risk = new Card("Risk summary", Theme.GTarget);
        foreach (var t in Tiers)
            _tierTiles[t] = new Tile(t switch { "critical" => "Critical files", "high" => "High risk", "medium" => "Medium risk", _ => "Low risk" }, Theme.TierColors[t], true);
        var viewFindings = new FlatButton("View findings", ButtonKind.Secondary, Theme.GList) { Height = 30 };
        viewFindings.Click += (_, _) => ShowPage("findings");
        risk.SetHeaderRight(viewFindings);
        Stack(risk, HRow(104, Theme.Card, [.. Tiers.Select(t => (Control)_tierTiles[t])]), Gap(10), HRow(104, Theme.Card, _iScanned, _iWithPii, _iDuration));
        Fit(risk);

        Stack(right, _idleCard, _progressCard, Gap(14, Theme.Bg), risk, Gap(8, Theme.Bg));
        return page;
    }

    // ================================================================== findings page
    Control BuildFindingsPage()
    {
        var page = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
        var header = PageHeader("Findings", "Files containing personal data, highest risk first. Select a file for details.");
        header.Dock = DockStyle.Top;

        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 48, BackColor = Theme.Bg, WrapContents = false, Padding = new Padding(0, 2, 0, 0) };
        bar.Controls.Add(_search);
        _search.Margin = new Padding(0, 0, 12, 0);
        foreach (var (key, label) in new[] { ("", "All"), ("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low") })
        {
            var chip = new FlatButton(label, ButtonKind.Chip) { Height = 32, Active = key == "", Tag = key, Margin = new Padding(0, 1, 6, 0), Font = Theme.Small };
            chip.Accent = key == "" ? Theme.Orange : Theme.TierColors[key];
            chip.Width = TextRenderer.MeasureText(label, Theme.Small).Width + 30;
            chip.Click += (_, _) => { _tierFilter = (string)chip.Tag!; foreach (var c in _chips) { c.Active = c == chip; c.Invalidate(); } RefreshView(); };
            _chips.Add(chip);
            bar.Controls.Add(chip);
        }
        var export = new FlatButton("Export", ButtonKind.Secondary, Theme.GDownload) { Height = 32, Margin = new Padding(12, 1, 6, 0) };
        var upload = new FlatButton("Upload report", ButtonKind.Primary, Theme.GDownload) { Height = 32, Margin = new Padding(0, 1, 6, 0) };
        var clear = new FlatButton("Clear", ButtonKind.Secondary, Theme.GClear) { Height = 32, Margin = new Padding(0, 1, 0, 0) };
        export.Click += (_, _) =>
        {
            var menu = new ContextMenuStrip { Renderer = new DarkMenuRenderer(), ShowImageMargin = false, Font = Theme.Base, BackColor = Theme.El };
            menu.Items.Add(new ToolStripMenuItem("Full report (JSON)…", null, (_, _) => ExportJson()) { ForeColor = Theme.Text });
            menu.Items.Add(new ToolStripMenuItem("Findings table (CSV)…", null, (_, _) => ExportCsv()) { ForeColor = Theme.Text });
            menu.Closed += (_, _) => BeginInvoke(menu.Dispose);
            menu.Show(export, new Point(0, export.Height + 2));
        };
        upload.Click += async (_, _) => await UploadReport(upload);
        clear.Click += (_, _) => { if (_scanTask is not { IsCompleted: false }) { ClearResults(); RefreshAll(); ShowDetail(); } };
        bar.Controls.AddRange([export, upload, clear]);

        var listCard = new Card { Dock = DockStyle.Fill, Padding = new Padding(2), Margin = Padding.Empty };
        string[] cols = ["Risk", "File", "PII types", "Score", "Location"];
        int[] widths = [96, 200, 220, 60, 132];
        for (int i = 0; i < cols.Length; i++) _list.Columns.Add(cols[i], widths[i]);
        _list.SmallImageList = new ImageList { ImageSize = new Size(1, 48) };
        Theme.DarkListHeader(_list);
        listCard.Controls.Add(_list);
        listCard.Controls.Add(_emptyFindings);
        _list.Resize += (_, _) => FitFileColumn();

        _dTypes.Columns.AddRange([new("Type", 0), new("High", 46, true), new("Med", 38, true), new("Low", 36, true), new("Uniq", 48, true)]);
        _dTypes.EmptyText = "—";
        _dTypes.SetRows([]);
        _dTypes.Resize += (_, _) => Fit(_detailCard);
        _dExplorer.Click += (_, _) => ShowInExplorer();
        Stack(_detailCard, _dName, _dPath, Gap(4), _dMeta, Gap(8), Caption("PII in this file"), Gap(4), _dTypes, Gap(12), _dExplorer);
        Fit(_detailCard);
        _detailCard.Dock = DockStyle.Top;
        _details.Controls.Add(_detailCard);

        var body = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
        body.Controls.Add(listCard);
        body.Controls.Add(_details);

        page.Controls.Add(body);
        page.Controls.Add(bar);
        page.Controls.Add(header);
        return page;
    }

    void FitFileColumn()
    {
        if (_list.Columns.Count < 5 || _list.ClientSize.Width <= 0) return;
        // File and PII-type columns share the space left by the fixed columns (no horizontal scrolling).
        int fixedW = _list.Columns[0].Width + _list.Columns[3].Width + _list.Columns[4].Width;
        int free = Math.Max(200, _list.ClientSize.Width - fixedW - SystemInformation.VerticalScrollBarWidth - 2);
        int file = free * 45 / 100, types = free - file;
        if (_list.Columns[1].Width != file) _list.Columns[1].Width = file;
        if (_list.Columns[2].Width != types) _list.Columns[2].Width = types;
    }

    // ================================================================== insights / skipped
    Control BuildInsightsPage()
    {
        var page = ScrollPage();
        page.Padding = new Padding(0, 0, 8, 0);
        var header = PageHeader("Insights", "What kinds of personal data were found, and whether they sit where policy allows.");
        var types = new Card("PII type breakdown", Theme.GChart);
        Stack(types, _breakdown);
        _breakdown.Resize += (_, _) => Fit(types);
        Fit(types);
        var loc = new Card("Location classification", Theme.GPin);
        Stack(loc, _locations);
        Fit(loc);
        Stack(page, header, types, Gap(14, Theme.Bg), loc);
        return page;
    }

    Control BuildSkippedPage()
    {
        var page = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
        var header = PageHeader("Skipped files", "Files that were not scanned and why — unsupported types, encrypted or corrupt files, size limits.");
        header.Dock = DockStyle.Top;
        var card = new Card { Dock = DockStyle.Fill, Padding = new Padding(16, 10, 8, 10) };
        var scroll = ScrollPage();
        scroll.BackColor = Theme.Card;
        _skipList.Columns.AddRange([new("Reason", 300), new("Files / path", 0)]);
        _skipList.Dock = DockStyle.Top;
        _skipList.SetRows([]);
        scroll.Controls.Add(_skipList);
        card.Controls.Add(scroll);
        page.Controls.Add(card);
        page.Controls.Add(header);
        return page;
    }

    // ================================================================== events
    void WireEvents()
    {
        _start.Click += (_, _) =>
        {
            if (_scanTask is { IsCompleted: false })
            {
                _cts?.Cancel();
                _start.Enabled = false;
                _statusText.Text = "Stopping…";
            }
            else StartScan(_paths.Paths.ToList());
        };
        _addFolder.Click += (_, _) => AddFolder();
        _defaults.Click += (_, _) => _paths.Set(DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady).Select(d => d.RootDirectory.FullName));
        _workers.SelectionChanged += (_, _) => UpdateEngineText();
        _drop.Click += (_, _) => { if (_drop.Enabled) PickFiles(); };
        _timer.Tick += (_, _) => Tick();

        _list.RetrieveVirtualItem += (_, e) => e.Item = new ListViewItem(["", "", "", "", ""]);
        _list.DrawColumnHeader += DrawHeader;
        _list.DrawItem += (_, e) => e.DrawDefault = false;
        _list.DrawSubItem += DrawCell;
        _list.ColumnClick += (_, e) =>
        {
            if (_sortCol == e.Column) _sortDesc = !_sortDesc; else { _sortCol = e.Column; _sortDesc = e.Column is 0 or 2 or 3; }
            RefreshView();
        };
        _list.SelectedIndexChanged += (_, _) => ShowDetail();
        _list.DoubleClick += (_, _) => ShowInExplorer();
        _search.Box.TextChanged += (_, _) => RefreshView();

        // drag & drop anywhere: folders are added to the list, files are scanned right away
        foreach (Control c in new Control[] { this, _drop })
        {
            c.AllowDrop = true;
            c.DragEnter += (_, e) =>
            {
                if (e.Data?.GetDataPresent(DataFormats.FileDrop) == true) { e.Effect = DragDropEffects.Copy; _drop.SetDragOver(true); }
            };
            c.DragLeave += (_, _) => _drop.SetDragOver(false);
            c.DragDrop += (_, e) =>
            {
                _drop.SetDragOver(false);
                if (e.Data?.GetData(DataFormats.FileDrop) is not string[] items) return;
                foreach (var d in items.Where(Directory.Exists)) _paths.Add(d);
                var files = items.Where(File.Exists).ToList();
                if (files.Count > 0) StartScan(files);
            };
        }
        FormClosing += (_, _) => _cts?.Cancel();
    }

    void UpdateEngineText() =>
        _engineText.Text = $"Native engine v{Scanner.Version}  ·  {_workers.Value} workers  ·  OCR: {(Ocr.Available ? "Windows built-in" : "not available")}";

    void AddFolder()
    {
        using var dlg = new FolderBrowserDialog { Description = "Choose folders to scan", UseDescriptionForTitle = true, Multiselect = true };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        foreach (var p in dlg.SelectedPaths) _paths.Add(p);
    }

    void ResetDefaultFolders()
    {
        var role = Profile.All.GetValueOrDefault(_role.Value) ?? Profile.All["general"];
        _paths.Set(role.DefaultScan.Select(Scanner.ExpandUser).Where(Directory.Exists));
    }

    void PickFiles()
    {
        using var dlg = new OpenFileDialog { Title = "Choose files to scan", Multiselect = true };
        if (dlg.ShowDialog(this) == DialogResult.OK) StartScan([.. dlg.FileNames]);
    }

    // ================================================================== scanning
    void ClearResults()
    {
        _rows.Clear(); _view.Clear(); _list.VirtualListSize = 0;
        while (_incoming.TryDequeue(out _)) { }
        _skipped.Clear(); _unsupported.Clear(); _skippedNotable.Clear();
        _filesScanned = _filesSeen = 0; _lastDuration = 0; _lastMeta = null;
        _statusDot.State = "idle";
        _statusText.Text = "Results cleared.";
    }

    void SetRunning(bool running)
    {
        // One action button: Start (orange) while idle, Stop (red outline) while scanning.
        _start.Kind = running ? ButtonKind.Danger : ButtonKind.Primary;
        _start.Text = running ? "Stop scan" : "Start scan";
        _start.Glyph = running ? Theme.GStop : Theme.GPlay;
        _start.Font = running ? Theme.Base : Theme.Bold;
        _start.Enabled = true;
        _start.Invalidate();
        _paths.Enabled = _role.Enabled = _maxMb.Enabled = _workers.Enabled = _addFolder.Enabled = _defaults.Enabled = _drop.Enabled = !running;
        _idleCard.Visible = false;
        _progressCard.Visible = running;
        _statusProgress.Visible = running;
        if (running) { _statusDot.State = "scanning"; _timer.Start(); }
    }

    void StartScan(List<string> paths)
    {
        if (_scanTask is { IsCompleted: false }) { _statusText.Text = "A scan is already running."; return; }
        if (paths.Count == 0) { _statusText.Text = "Add at least one folder to scan."; ShowPage("scan"); return; }
        string role = _role.Value;
        var profile = Profile.All[role];
        var o = new ScanOptions { Paths = paths, Role = role, MaxMb = int.Parse(_maxMb.Value), Workers = int.Parse(_workers.Value) };
        o.OnFinding = (path, size, mod, types) => _incoming.Enqueue(MakeRow(path, size, mod, types, null, profile));
        _live = new LiveStatus();
        _cts = new CancellationTokenSource();
        var live = _live; var token = _cts.Token;
        bool fileScan = paths.All(File.Exists);
        UpdateEngineText();
        _liveTypes.Items = new(); _liveTypes.Invalidate();
        _pct.Text = "0%"; _bar.Value = 0;
        SetRunning(true);
        ShowPage("scan");
        _statusText.Text = "Scanning…";
        _scanTask = Task.Run(() => Scanner.Run(o, live, token)).ContinueWith(t => BeginInvoke(() => ScanFinished(t, fileScan)));
    }

    static Row MakeRow(string path, long size, DateTime mod, Dictionary<string, TypeCount> types, string? sha, Profile profile)
    {
        double sc = Detectors.ScoreTypes(types);
        bool reportable = types.Values.Any(v => v.High > 0 || v.Medium > 0);
        return new Row
        {
            Path = path, Size = size, Modified = mod, Types = types, Score = sc, Sha = sha,
            Tier = Detectors.Tier(sc), Location = reportable ? profile.Classify(path) : "n/a",
        };
    }

    void Tick()
    {
        bool added = false;
        while (_incoming.TryDequeue(out var r)) { _rows[r.Path] = r; added = true; }
        if (added) RefreshAll();
        if (_live == null || _scanTask is not { IsCompleted: false }) return;
        int seen = _live.FilesSeen;
        double frac = seen > 0 ? (double)_live.FilesDone / seen : 0;
        _pct.Text = $"{frac * 100:0}%";
        _bar.Value = frac;
        _statusProgress.Value = frac;
        _elapsed.Text = $"{(DateTime.Now - _live.Started).TotalSeconds:0.0}s elapsed";
        _tSeen.Value = seen.ToString("N0");
        _tScanned.Value = _live.FilesScanned.ToString("N0");
        _tPii.Value = _live.FilesWithPii.ToString("N0");
        _tCache.Value = _live.CacheHits.ToString("N0");
        _currentFile.Text = _live.CurrentFile;
        var bt = _live.ToJson("running")["findings_by_type"]!.AsObject();
        _liveTypes.Items = bt.Select(kv => (kv.Key, (int)kv.Value!["high"]! + (int)kv.Value!["medium"]! + (int)kv.Value!["low"]!))
            .OrderByDescending(x => x.Item2).ToList();
        _liveTypes.Invalidate();
        _statusText.Text = $"Scanning · {_live.FilesDone:N0} of {seen:N0} files · {_live.FilesWithPii:N0} with PII";
    }

    void ScanFinished(Task<JsonObject> t, bool fileScan)
    {
        _timer.Stop();
        while (_incoming.TryDequeue(out _)) { }
        SetRunning(false);
        if (t.IsFaulted)
        {
            _statusDot.State = "error";
            _statusText.Text = "Scan failed: " + t.Exception!.GetBaseException().Message;
            RefreshAll();
            return;
        }
        var rep = t.Result;
        MergeReport(rep);
        bool stopped = _cts?.IsCancellationRequested == true;
        _statusDot.State = stopped ? "stopped" : "done";
        var s = rep["summary"]!;
        _statusText.Text = $"{(stopped ? "Stopped" : "Finished")} · {s["files_scanned"]:N0} of {s["files_seen"]:N0} files scanned · " +
                           $"{s["files_with_pii"]} with PII · {rep["meta"]!["duration_s"]}s";
        var missing = rep["missing_paths"]!.AsArray();
        if (missing.Count > 0) _statusText.Text += $" · {missing.Count} folder(s) not found";
        RefreshAll();
        ShowDetail();
        if (fileScan)
        {
            if (rep["findings"]!.AsArray().Count > 0) ShowPage("findings");
            else
            {
                var sk = rep["summary"]!["skipped_by_reason"]!.AsObject();
                _statusText.Text = sk.Count > 0
                    ? "No PII found — skipped: " + string.Join(", ", sk.Select(kv => $"{kv.Key} ({kv.Value})"))
                    : "No personal data found in the selected file(s).";
            }
        }
    }

    void MergeReport(JsonObject rep)
    {
        var profile = Profile.All.GetValueOrDefault((string?)rep["meta"]!["role"] ?? "general") ?? Profile.All["general"];
        foreach (var f in rep["findings"]!.AsArray())
        {
            var types = new Dictionary<string, TypeCount>();
            foreach (var (k, v) in f!["types"]!.AsObject())
                types[k] = new TypeCount { High = (int)v!["high"]!, Medium = (int)v["medium"]!, Low = (int)v["low"]!, Unique = (int)v["unique"]! };
            string path = (string)f["path"]!;
            _rows[path] = MakeRow(path, (long)f["size"]!, DateTime.TryParse((string?)f["modified"], out var d) ? d : default, types, (string?)f["sha256"], profile);
        }
        var s = rep["summary"]!;
        _filesScanned += (int)s["files_scanned"]!;
        _filesSeen += (int)s["files_seen"]!;
        foreach (var (k, v) in s["skipped_by_reason"]!.AsObject()) _skipped[k] = _skipped.GetValueOrDefault(k) + (int)v!;
        foreach (var (k, v) in s["unsupported_by_extension"]!.AsObject()) _unsupported[k] = _unsupported.GetValueOrDefault(k) + (int)v!;
        foreach (var n in rep["skipped_notable"]!.AsArray())
            if (_skippedNotable.Count < 500) _skippedNotable.Add(((string)n!["path"]!, (string)n["reason"]!));
        _lastDuration = (double)rep["meta"]!["duration_s"]!;
        _lastMeta = rep["meta"]!.DeepClone().AsObject();
    }

    // ================================================================== views
    void RefreshAll()
    {
        RefreshView();
        var rep = _rows.Values.Where(r => r.Location != "n/a").ToList();
        foreach (var t in Tiers) _tierTiles[t].Value = rep.Count(r => r.Tier == t).ToString("N0");
        _iScanned.Value = Math.Max(_filesScanned, _live?.FilesScanned ?? 0).ToString("N0");
        _iWithPii.Value = rep.Count.ToString("N0");
        _iDuration.Value = _lastDuration > 0 ? _lastDuration.ToString("0.0") : "—";
        _pages["findings"].Nav.Badge = rep.Count > 0 ? rep.Count.ToString("N0") : "";
        int skippedTotal = _skipped.Values.Sum();
        _pages["skipped"].Nav.Badge = skippedTotal > 0 ? skippedTotal.ToString("N0") : "";
        if (_scanTask is not { IsCompleted: false }) _idleCard.Visible = _rows.Count == 0 && _filesSeen == 0;

        var totals = new Dictionary<string, (int H, int M, int L)>();
        foreach (var r in _rows.Values)
            foreach (var (t, c) in r.Types)
            {
                var x = totals.GetValueOrDefault(t);
                totals[t] = (x.H + c.High, x.M + c.Medium, x.L + c.Low);
            }
        _breakdown.SetItems(totals.Select(kv => (kv.Key, kv.Value.H, kv.Value.M, kv.Value.L)));
        _locations.Counts = rep.GroupBy(r => r.Location).ToDictionary(g => g.Key, g => g.Count());
        _locations.Invalidate();

        var skipRows = new List<(string[], bool)>();
        foreach (var (reason, n) in _skipped.OrderByDescending(kv => kv.Value))
            skipRows.Add(([reason.Replace('_', ' '), n.ToString("N0") + " files"], true));
        foreach (var (ext, n) in _unsupported.OrderByDescending(kv => kv.Value))
            skipRows.Add((["    unsupported " + ext, n.ToString("N0") + " files"], false));
        foreach (var (path, reason) in _skippedNotable)
            skipRows.Add((["    " + reason.Replace('_', ' '), path], false));
        _skipList.SetRows(skipRows);
    }

    void RefreshView()
    {
        string q = _search.Box.Text.Trim();
        IEnumerable<Row> rows = _rows.Values;
        if (_tierFilter.Length > 0) rows = rows.Where(r => r.Tier == _tierFilter);
        if (q.Length > 0) rows = rows.Where(r => r.Path.Contains(q, StringComparison.OrdinalIgnoreCase) || r.Types.Keys.Any(k => k.Contains(q, StringComparison.OrdinalIgnoreCase)));
        Func<Row, IComparable> key = _sortCol switch
        {
            0 or 3 => r => r.Score,
            1 => r => Path.GetFileName(r.Path),
            2 => r => r.Total,
            _ => r => r.Location,
        };
        string? selected = SelectedRow()?.Path;
        _view = (_sortDesc ? rows.OrderByDescending(key) : rows.OrderBy(key)).ThenBy(r => r.Path, StringComparer.OrdinalIgnoreCase).ToList();
        _list.VirtualListSize = _view.Count;
        _list.Invalidate();
        _emptyFindings.Visible = _view.Count == 0;
        _list.Visible = _view.Count > 0;
        FitFileColumn();
        _emptyFindings.Text = _rows.Count == 0 ? "No findings yet — run a scan from the Scan page." : "No findings match the current filter.";
        if (selected != null)
        {
            int i = _view.FindIndex(r => r.Path == selected);
            if (i >= 0 && !_list.SelectedIndices.Contains(i)) { _list.SelectedIndices.Clear(); _list.SelectedIndices.Add(i); }
        }
    }

    Row? SelectedRow()
    {
        if (_list.SelectedIndices.Count == 0) return null;
        int i = _list.SelectedIndices[0];
        return i >= 0 && i < _view.Count ? _view[i] : null;
    }

    void ShowDetail()
    {
        var r = SelectedRow();
        if (r == null)
        {
            _dName.Text = "No file selected";
            _dPath.Text = "Select a finding to see its details.";
            _dMeta.Text = "";
            _dExplorer.Enabled = false;
            _dTypes.SetRows([]);
            return;
        }
        _dName.Text = Path.GetFileName(r.Path);
        _dPath.Text = Path.GetDirectoryName(r.Path) ?? "";
        _dMeta.Text = $"Risk:  {r.Tier.ToUpperInvariant()}  (score {r.Score:0.#})\n" +
                      $"Location:  {LocationLabel(r.Location)}\n" +
                      $"Size:  {FormatSize(r.Size)}   ·   Modified:  {(r.Modified == default ? "—" : r.Modified.ToString("yyyy-MM-dd HH:mm"))}\n" +
                      $"SHA-256:  {(r.Sha is { } s ? s[..16] + "…" : "computed when the scan finishes")}";
        _dTypes.SetRows(r.Types.OrderByDescending(kv => kv.Value.Count).Select(kv =>
            (new[] { kv.Key.Replace('_', ' '), kv.Value.High.ToString("N0"), kv.Value.Medium.ToString("N0"), kv.Value.Low.ToString("N0"), kv.Value.Unique.ToString("N0") }, false)));
        _dExplorer.Enabled = File.Exists(r.Path);
    }

    static string LocationLabel(string l) => l switch
    {
        "violation" => "Policy violation", "review" => "Needs review", "expected_location" => "Expected location", _ => "—",
    };

    static string FormatSize(long b) => b >= 1 << 20 ? $"{b / 1048576.0:F1} MB" : b >= 1024 ? $"{b / 1024.0:F0} KB" : $"{b} B";

    // ------------------------------------------------------------------ owner-drawn lists
    void DrawHeader(object? sender, DrawListViewColumnHeaderEventArgs e)
    {
        var g = e.Graphics;
        using (var b = new SolidBrush(Theme.Card)) g.FillRectangle(b, e.Bounds);
        using (var p = new Pen(Theme.Border)) g.DrawLine(p, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
        string text = e.Header!.Text.ToUpperInvariant();
        if (sender == _list && e.ColumnIndex == _sortCol) text += _sortDesc ? "  ↓" : "  ↑";
        int pad = sender == _list ? 10 : 6;
        Theme.Draw(g, text, Theme.SmallBold, Theme.Muted, new Rectangle(e.Bounds.X + pad, e.Bounds.Y, e.Bounds.Width - pad - 2, e.Bounds.Height));
    }

    void DrawCell(object? sender, DrawListViewSubItemEventArgs e)
    {
        if (e.ItemIndex < 0 || e.ItemIndex >= _view.Count) return;
        var g = e.Graphics;
        var r = _view[e.ItemIndex];
        bool sel = _list.SelectedIndices.Contains(e.ItemIndex);
        var bounds = e.Bounds;
        using (var b = new SolidBrush(sel ? Theme.Over(Theme.Orange, 0.12, Theme.Card) : Theme.Card)) g.FillRectangle(b, bounds);
        using (var p = new Pen(Theme.Border)) g.DrawLine(p, bounds.Left, bounds.Bottom - 1, bounds.Right, bounds.Bottom - 1);
        if (sel && e.ColumnIndex == 0)
            using (var a = new SolidBrush(Theme.Orange)) g.FillRectangle(a, bounds.Left, bounds.Top + 12, 3, bounds.Height - 24);
        Theme.Hq(g);
        var inner = new Rectangle(bounds.X + 10, bounds.Y, bounds.Width - 14, bounds.Height);
        switch (e.ColumnIndex)
        {
            case 0: Pill(g, r.Tier.ToUpperInvariant(), Theme.TierColors.GetValueOrDefault(r.Tier, Theme.Muted), inner.X, inner.Y + inner.Height / 2); break;
            case 1:
                Theme.Draw(g, Path.GetFileName(r.Path), Theme.Bold, Theme.Text, new Rectangle(inner.X, inner.Y + 5, inner.Width, 20));
                Theme.Draw(g, Path.GetDirectoryName(r.Path) ?? "", Theme.Small, Theme.Muted, new Rectangle(inner.X, inner.Y + 25, inner.Width, 18),
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.PathEllipsis);
                break;
            case 2:
            {
                int x = inner.X, y = inner.Y + inner.Height / 2;
                var ordered = r.Types.OrderByDescending(kv => kv.Value.Count).ToList();
                for (int i = 0; i < ordered.Count; i++)
                {
                    var (t, c) = (ordered[i].Key, ordered[i].Value);
                    string s = $"{t.Replace('_', ' ')} {c.Count:N0}";
                    int w = TextRenderer.MeasureText(s, Theme.Small).Width + 12;
                    if (x + w > inner.Right - 28 && i < ordered.Count - 1)
                    {
                        Theme.Draw(g, $"+{ordered.Count - i}", Theme.SmallBold, Theme.Muted, new Rectangle(x, inner.Y, 30, inner.Height));
                        break;
                    }
                    Pill(g, s, Theme.TypeColor(t), x, y, Theme.Small);
                    x += w + 4;
                }
                break;
            }
            case 3: Theme.Draw(g, r.Score.ToString("0.#"), Theme.Bold, Theme.TierColors.GetValueOrDefault(r.Tier, Theme.Text), inner); break;
            case 4: if (r.Location != "n/a") Pill(g, LocationLabel(r.Location), Theme.LocationColors.GetValueOrDefault(r.Location, Theme.Muted), inner.X, inner.Y + inner.Height / 2); break;
        }
    }

    static void Pill(Graphics g, string s, Color c, int x, int cy, Font? font = null)
    {
        font ??= Theme.SmallBold;
        var sz = TextRenderer.MeasureText(s, font);
        var r = new RectangleF(x, cy - 10, sz.Width + 12, 20);
        using (var b = new SolidBrush(Theme.Over(c, 0.14, Theme.Card))) Theme.FillRound(g, b, r, 10);
        using (var p = new Pen(Theme.Over(c, 0.30, Theme.Card))) Theme.DrawRound(g, p, r, 10);
        Theme.Draw(g, s, font, c, Rectangle.Round(r), TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
    }

    void ShowInExplorer()
    {
        var r = SelectedRow();
        if (r == null || !File.Exists(r.Path)) return;
        try { Process.Start("explorer.exe", $"/select,\"{r.Path}\""); } catch { }
    }

    // ================================================================== export
    JsonObject BuildExport()
    {
        var rep = _rows.Values.Where(r => r.Location != "n/a").ToList();
        var findings = new JsonArray();
        foreach (var r in _rows.Values.OrderByDescending(r => r.Score).ThenBy(r => r.Path, StringComparer.Ordinal))
        {
            var types = new JsonObject();
            foreach (var (t, c) in r.Types)
                types[t] = new JsonObject { ["high"] = c.High, ["medium"] = c.Medium, ["low"] = c.Low, ["count"] = c.Count, ["unique"] = c.Unique };
            findings.Add(new JsonObject
            {
                ["path"] = r.Path, ["size"] = r.Size, ["modified"] = r.Modified.ToString("yyyy-MM-ddTHH:mm:ss"), ["sha256"] = r.Sha,
                ["types"] = types, ["score"] = r.Score, ["tier"] = r.Tier, ["location_class"] = r.Location,
            });
        }
        var byType = new JsonObject();
        foreach (var g in _rows.Values.SelectMany(r => r.Types).GroupBy(kv => kv.Key))
            byType[g.Key] = new JsonObject { ["high"] = g.Sum(x => x.Value.High), ["medium"] = g.Sum(x => x.Value.Medium), ["low"] = g.Sum(x => x.Value.Low) };
        static JsonObject Counts(IEnumerable<KeyValuePair<string, int>> kv) { var o = new JsonObject(); foreach (var (k, v) in kv) o[k] = v; return o; }
        return new JsonObject
        {
            ["meta"] = _lastMeta?.DeepClone() ?? new JsonObject(),
            ["summary"] = new JsonObject
            {
                ["files_seen"] = _filesSeen, ["files_scanned"] = _filesScanned, ["files_with_pii"] = rep.Count,
                ["by_tier"] = Counts(rep.GroupBy(r => r.Tier).Select(g => KeyValuePair.Create(g.Key, g.Count()))),
                ["by_location_class"] = Counts(rep.GroupBy(r => r.Location).Select(g => KeyValuePair.Create(g.Key, g.Count()))),
                ["findings_by_type"] = byType, ["skipped_by_reason"] = Counts(_skipped), ["unsupported_by_extension"] = Counts(_unsupported),
            },
            ["findings"] = findings,
            ["skipped_notable"] = new JsonArray([.. _skippedNotable.Select(s => (JsonNode)new JsonObject { ["path"] = s.Path, ["reason"] = s.Reason })]),
        };
    }

    void ExportJson()
    {
        if (_rows.Count == 0 && _filesSeen == 0) { _statusText.Text = "Nothing to export yet — run a scan first."; return; }
        using var dlg = new SaveFileDialog { Filter = "JSON report|*.json", FileName = $"pii_report_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmm}.json" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        File.WriteAllText(dlg.FileName, BuildExport().ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        _statusText.Text = "Report saved: " + dlg.FileName;
    }

    async Task UploadReport(FlatButton trigger)
    {
        if (_rows.Count == 0 && _filesSeen == 0) { _statusText.Text = "Nothing to upload yet — run a scan first."; return; }

        string? key = Uploader.SavedKey;
        if (key == null)
        {
            using var dlg = new ApiKeyForm();
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            key = Uploader.SavedKey = dlg.EnteredKey;
        }

        trigger.Enabled = false;
        _statusText.Text = "Uploading report…";
        var result = await Uploader.UploadAsync(BuildExport(), key);
        trigger.Enabled = true;

        if (result.Success) { _statusText.Text = result.Message; return; }

        _statusText.Text = "Upload failed.";
        if (result.Message.Contains("Invalid or revoked", StringComparison.OrdinalIgnoreCase)) Uploader.SavedKey = null;
        MessageBox.Show(result.Message, "Upload failed", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
    }

    void ExportCsv()
    {
        if (_rows.Count == 0) { _statusText.Text = "Nothing to export yet — run a scan first."; return; }
        using var dlg = new SaveFileDialog { Filter = "CSV|*.csv", FileName = $"pii_findings_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmm}.csv" };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        static string Q(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";
        var sb = new StringBuilder("tier,score,path,pii_types,location_class,size_bytes,modified,sha256\r\n");
        foreach (var r in _view)
        {
            string types = string.Join("; ", r.Types.OrderByDescending(t => t.Value.Count).Select(t => $"{t.Key}={t.Value.Count}"));
            sb.Append($"{r.Tier},{r.Score:0.#},{Q(r.Path)},{Q(types)},{r.Location},{r.Size},{r.Modified:yyyy-MM-ddTHH:mm:ss},{r.Sha}\r\n");
        }
        File.WriteAllText(dlg.FileName, sb.ToString(), new UTF8Encoding(true));
        _statusText.Text = "CSV saved: " + dlg.FileName;
    }
}
