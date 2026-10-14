// Linux UI in the RiskNox theme: a port of the Windows build's MainForm.cs with the same layout
//   sidebar navigation (Scan / Findings / Insights / Skipped) | page content | status bar
// and the same behaviour. Results accumulate across scans (re-scanning a file replaces its row).
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;

namespace RiskNox;

public sealed class MainWindow : Window
{
    static readonly string[] Tiers = ["critical", "high", "medium", "low"];
    static readonly StringComparer PathCmp = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;

    // ---- state
    readonly Dictionary<string, FindingRow> _rows = new(PathCmp);
    List<FindingRow> _view = new();
    readonly ConcurrentQueue<FindingRow> _incoming = new();
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

    // ---- shell
    readonly Panel _content = new() { Background = Ui.B(Ui.Bg), Margin = new Thickness(24, 20, 24, 16) };
    readonly Dictionary<string, (NavItem Nav, Control Page)> _pages = new();
    readonly StatusDot _statusDot = new() { VerticalAlignment = VerticalAlignment.Center };
    readonly TextBlock _statusText = Txt("", Ui.Small, Ui.Muted);
    readonly ProgressStrip _statusProgress = new() { Width = 160, Height = 6, IsVisible = false, VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Left };
    readonly TextBlock _engineText = Txt("", Ui.Small, Ui.Muted);

    // ---- scan page
    readonly DarkSelect _role = new();
    readonly DarkSelect _maxMb = new();
    readonly DarkSelect _workers = new();
    readonly PathList _paths = new();
    readonly FlatButton _addFolder = new("Add folder", ButtonKind.Ghost, Icons.Add);
    readonly FlatButton _defaults = new("Full scan (all drives)", ButtonKind.Ghost);
    readonly FlatButton _start = new("Start scan", ButtonKind.Primary, Icons.Play) { Height = 42 };
    readonly DropZone _drop = new() { Height = 170 };
    readonly Card _idleCard = new();
    readonly Card _progressCard = new("Live progress", Icons.Search) { IsVisible = false };
    readonly TextBlock _pct = Txt("0%", Ui.Huge, Ui.Orange);
    readonly TextBlock _elapsed = Txt("", Ui.Mono, Ui.Muted);
    readonly ProgressStrip _bar = new() { Height = 10 };
    readonly Tile _tSeen = new("Files found", Ui.Muted, false, Icons.List);
    readonly Tile _tScanned = new("Scanned", Ui.Muted, false, Icons.Page);
    readonly Tile _tPii = new("Files with PII", Ui.Orange, true, Icons.Warn);
    readonly Tile _tCache = new("Cache hits", Ui.Muted, false, Icons.Download);
    readonly TextBlock _currentFile = Txt("", Ui.Mono, Ui.Muted);
    readonly ChipsView _liveTypes = new();
    readonly Dictionary<string, Tile> _tierTiles = new();
    readonly Tile _iScanned = new("Files scanned", Ui.Text, false, Icons.Page);
    readonly Tile _iWithPii = new("Files with PII", Ui.Text, false, Icons.Warn);
    readonly Tile _iDuration = new("Duration (s)", Ui.Text, false);

    // ---- findings page
    readonly SearchBox _search = new("Search path or PII type…") { Width = 280 };
    readonly List<FlatButton> _chips = new();
    readonly FindingsList _list = new();
    readonly TextBlock _emptyFindings = Txt("", Ui.Base, Ui.Muted);
    readonly Card _detailCard = new("Details", Icons.Page);
    readonly TextBlock _dName = Txt("", Ui.Bold, Ui.Text);
    readonly TextBlock _dPath = Txt("", Ui.Mono, Ui.Muted);
    readonly TextBlock _dMeta = Txt("", Ui.Small, Ui.Text);
    readonly SimpleTable _dTypes = new();
    readonly FlatButton _dExplorer = new("Show in file manager", ButtonKind.Secondary, Icons.Open) { Height = 36 };

    // ---- insights / skipped pages
    readonly Breakdown _breakdown = new();
    readonly LocationView _locations = new();
    readonly SimpleTable _skipList = new() { EmptyText = "Nothing skipped yet." };

    readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromMilliseconds(250) };

    public MainWindow(List<string>? folders = null)
    {
        Title = "Risknox PII Scanner";
        FontFamily = Ui.Sans;
        FontSize = Ui.Base.Size;
        Background = Ui.B(Ui.Bg);
        Foreground = Ui.B(Ui.Text);
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        Width = 1360; Height = 880;
        MinWidth = 1080; MinHeight = 680;
        Icon = App.WindowIcon;

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

    // ================================================================== layout helpers
    static TextBlock Txt(string s, UiFont f, Color c) => new()
    {
        Text = s, FontFamily = f.Typeface.FontFamily, FontSize = f.Size, FontWeight = f.Typeface.Weight,
        Foreground = Ui.B(c), TextTrimming = TextTrimming.CharacterEllipsis,
    };

    static Control Caption(string s)
    {
        var t = Txt(s.ToUpperInvariant(), Ui.SmallBold, Ui.Muted);
        t.VerticalAlignment = VerticalAlignment.Bottom;
        t.LetterSpacing = 0.4;
        return new Border { Height = 22, Child = t };
    }

    static Control Gap(double h) => new Border { Height = h };

    /// <summary>Equal-width row of controls.</summary>
    static Grid HRow(double height, params Control[] items)
    {
        var g = new Grid { Height = height };
        for (int i = 0; i < items.Length; i++)
        {
            g.ColumnDefinitions.Add(new ColumnDefinition(1, GridUnitType.Star));
            items[i].Margin = new Thickness(i == 0 ? 0 : 5, 0, i == items.Length - 1 ? 0 : 5, 0);
            items[i].HorizontalAlignment = HorizontalAlignment.Stretch;
            Grid.SetColumn(items[i], i);
            g.Children.Add(items[i]);
        }
        return g;
    }

    static Control PageHeader(string title, string sub)
    {
        var p = new Grid { Height = 62 };
        var t = Txt(title, Ui.PageTitle, Ui.Text);
        t.VerticalAlignment = VerticalAlignment.Top;
        var s = Txt(sub, Ui.Base, Ui.Muted);
        s.VerticalAlignment = VerticalAlignment.Top;
        s.Margin = new Thickness(0, 34, 0, 0);
        p.Children.Add(t);
        p.Children.Add(s);
        return p;
    }

    static ScrollViewer ScrollPage(Control content, Thickness padding) => new()
    {
        Content = content, Padding = padding, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled,
        VerticalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Auto,
    };

    static T Dock<T>(T c, Dock d) where T : Control { DockPanel.SetDock(c, d); return c; }

    // ================================================================== shell
    void BuildShell()
    {
        // sidebar
        var side = new DockPanel { Width = 236, Background = Ui.B(Ui.Bg), Margin = new Thickness(0, 14, 0, 14) };
        var brand = new Canvas { Height = 66 };
        var logo = new Logo();
        Canvas.SetLeft(logo, 20); Canvas.SetTop(logo, 10);
        var brandName = Txt("Risknox", Ui.Brand, Ui.Text);
        Canvas.SetLeft(brandName, 64); Canvas.SetTop(brandName, 8);
        var brandSub = Txt("PII Scanner · DPDP", Ui.Small, Ui.Muted);
        Canvas.SetLeft(brandSub, 66); Canvas.SetTop(brandSub, 32);
        brand.Children.Add(logo); brand.Children.Add(brandName); brand.Children.Add(brandSub);
        var nav = new Canvas { Height = 4 * 42 + 10 };
        var foot = Txt("Endpoint PII posture only — not a DPDP compliance verdict. File contents are never stored.", Ui.Small, Ui.Muted);
        foot.TextWrapping = TextWrapping.Wrap;
        foot.TextTrimming = TextTrimming.None;
        foot.Margin = new Thickness(20, 0, 16, 0);
        foot.Height = 64;
        foot.VerticalAlignment = VerticalAlignment.Center;
        side.Children.Add(Dock(brand, Avalonia.Controls.Dock.Top));
        side.Children.Add(Dock(nav, Avalonia.Controls.Dock.Top));
        side.Children.Add(Dock(foot, Avalonia.Controls.Dock.Bottom));
        side.Children.Add(new Panel());
        var sideLine = new Border { Width = 1, Background = Ui.B(Ui.Border) };

        // status bar
        var status = new DockPanel { Height = 32, Background = Ui.B(Ui.Card) };
        var statusInner = new DockPanel { Margin = new Thickness(16, 0, 16, 0) };
        status.Children.Add(statusInner);
        var statusLine = new Border { Height = 1, Background = Ui.B(Ui.Border) };
        var progHost = new Panel { Width = 176 };
        progHost.Children.Add(_statusProgress);
        _statusText.VerticalAlignment = VerticalAlignment.Center;
        _engineText.VerticalAlignment = VerticalAlignment.Center;
        _engineText.TextAlignment = TextAlignment.Right;
        _engineText.Width = 420;
        statusInner.Children.Add(Dock(_statusDot, Avalonia.Controls.Dock.Left));
        statusInner.Children.Add(Dock(progHost, Avalonia.Controls.Dock.Left));
        statusInner.Children.Add(Dock(_engineText, Avalonia.Controls.Dock.Right));
        statusInner.Children.Add(_statusText);

        AddPage("scan", "Scan", Icons.Search, BuildScanPage(), nav, 0);
        AddPage("findings", "Findings", Icons.List, BuildFindingsPage(), nav, 1);
        AddPage("insights", "Insights", Icons.Chart, BuildInsightsPage(), nav, 2);
        AddPage("skipped", "Skipped files", Icons.Warn, BuildSkippedPage(), nav, 3);

        var root = new DockPanel { Background = Ui.B(Ui.Bg) };
        root.Children.Add(Dock(status, Avalonia.Controls.Dock.Bottom));
        root.Children.Add(Dock(statusLine, Avalonia.Controls.Dock.Bottom));
        root.Children.Add(Dock(side, Avalonia.Controls.Dock.Left));
        root.Children.Add(Dock(sideLine, Avalonia.Controls.Dock.Left));
        root.Children.Add(_content);
        Content = root;
    }

    void AddPage(string key, string title, Geometry glyph, Control page, Canvas nav, int index)
    {
        var item = new NavItem(title, glyph) { Width = 236 };
        Canvas.SetLeft(item, 0); Canvas.SetTop(item, 4 + index * 42);
        item.Click += (_, _) => ShowPage(key);
        nav.Children.Add(item);
        page.IsVisible = false;
        _content.Children.Add(page);
        _pages[key] = (item, page);
    }

    void ShowPage(string key)
    {
        foreach (var (k, (nav, page)) in _pages)
        {
            nav.Selected = k == key;
            page.IsVisible = k == key;
        }
    }

    // ================================================================== scan page
    Control BuildScanPage()
    {
        var page = new DockPanel();
        page.Children.Add(Dock(PageHeader("Scan this computer", "Find Aadhaar, PAN, card, bank and other personal data in local files."), Avalonia.Controls.Dock.Top));
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions("420,*") };
        var left = new StackPanel();
        var right = new StackPanel();
        var ls = ScrollPage(left, new Thickness(0, 0, 10, 0));
        var rs = ScrollPage(right, new Thickness(10, 0, 4, 0));
        Grid.SetColumn(rs, 1);
        grid.Children.Add(ls);
        grid.Children.Add(rs);
        page.Children.Add(grid);

        var cfg = new Card("Scan configuration", Icons.Settings);
        cfg.Add(Caption("Folders to scan"), Gap(6), _paths, Gap(8), HRow(36, _addFolder, _defaults),
            Gap(14), HRow(22, Caption("Max file size"), Caption("Parallel workers")), Gap(6), HRow(34, _maxMb, _workers), Gap(20), _start);

        var fileCard = new Card("Scan specific files", Icons.Folder);
        _drop.Line1 = "Drop files or folders here";
        _drop.Line2 = "or click to choose files · .pdf .docx .xlsx .pptx .csv .txt .json .xml .log .eml .png .jpg";
        fileCard.Add(_drop);

        left.Children.Add(cfg); left.Children.Add(Gap(14)); left.Children.Add(fileCard); left.Children.Add(Gap(8));

        var idleIcon = new PathIcon { Data = Icons.Search, Width = 40, Height = 40, Foreground = Ui.B(Ui.Orange), Margin = new Thickness(0, 15, 0, 15) };
        TextBlock Centered(string s, UiFont f, Color c, double h)
        {
            var t = Txt(s, f, c);
            t.TextAlignment = TextAlignment.Center; t.HorizontalAlignment = HorizontalAlignment.Stretch;
            t.TextWrapping = TextWrapping.Wrap; t.TextTrimming = TextTrimming.None; t.MinHeight = h;
            return t;
        }
        var idleDetects = Centered("Detects: Aadhaar · PAN · Passport · Bank account · IFSC · Credit/Debit card · UPI · Voter ID · DOB · Phone · Email", Ui.Small, Ui.Muted, 44);
        idleDetects.Margin = new Thickness(24, 6, 24, 0);
        _idleCard.Add(Gap(18), idleIcon, Centered("Ready to scan", Ui.Title, Ui.Text, 30),
            Centered("Choose folders on the left and press Start scan — or drop files to scan them instantly.", Ui.Base, Ui.Muted, 26),
            idleDetects, Gap(10));

        var pctRow = new Grid { Height = 56 };
        _pct.Margin = new Thickness(-2, 0, 0, 0);
        _elapsed.HorizontalAlignment = HorizontalAlignment.Right;
        _elapsed.VerticalAlignment = VerticalAlignment.Top;
        _elapsed.Margin = new Thickness(0, 22, 0, 0);
        pctRow.Children.Add(_pct); pctRow.Children.Add(_elapsed);
        _currentFile.Height = 20;
        _progressCard.Add(pctRow, _bar, Gap(16), HRow(104, _tSeen, _tScanned, _tPii, _tCache), Gap(14), Caption("Currently scanning"), Gap(4),
            _currentFile, Gap(10), Caption("PII detected so far"), Gap(6), _liveTypes);

        var risk = new Card("Risk summary", Icons.Target);
        foreach (var t in Tiers)
            _tierTiles[t] = new Tile(t switch { "critical" => "Critical files", "high" => "High risk", "medium" => "Medium risk", _ => "Low risk" }, Ui.TierColors[t], true);
        var viewFindings = new FlatButton("View findings", ButtonKind.Secondary, Icons.List) { Height = 30 };
        viewFindings.Click += (_, _) => ShowPage("findings");
        risk.SetHeaderRight(viewFindings);
        risk.Add(HRow(104, [.. Tiers.Select(t => (Control)_tierTiles[t])]), Gap(10), HRow(104, _iScanned, _iWithPii, _iDuration));

        right.Children.Add(_idleCard); right.Children.Add(_progressCard); right.Children.Add(Gap(14)); right.Children.Add(risk); right.Children.Add(Gap(8));
        return page;
    }

    // ================================================================== findings page
    Control BuildFindingsPage()
    {
        var page = new DockPanel();
        page.Children.Add(Dock(PageHeader("Findings", "Files containing personal data, highest risk first. Select a file for details."), Avalonia.Controls.Dock.Top));

        var bar = new StackPanel { Orientation = Orientation.Horizontal, Height = 48, Margin = new Thickness(0, 2, 0, 0), VerticalAlignment = VerticalAlignment.Top };
        _search.Margin = new Thickness(0, 0, 12, 0);
        _search.VerticalAlignment = VerticalAlignment.Top;
        bar.Children.Add(_search);
        foreach (var (key, label) in new[] { ("", "All"), ("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low") })
        {
            var chip = new FlatButton(label, ButtonKind.Chip) { Height = 32, Active = key == "", Data = key, Margin = new Thickness(0, 1, 6, 0), Font = Ui.Small, VerticalAlignment = VerticalAlignment.Top };
            chip.Accent = key == "" ? Ui.Orange : Ui.TierColors[key];
            chip.Click += (_, _) => { _tierFilter = (string)chip.Data!; foreach (var c in _chips) { c.Active = c == chip; c.InvalidateVisual(); } RefreshView(); };
            _chips.Add(chip);
            bar.Children.Add(chip);
        }
        var export = new FlatButton("Export", ButtonKind.Secondary, Icons.Download) { Height = 32, Margin = new Thickness(12, 1, 6, 0), VerticalAlignment = VerticalAlignment.Top };
        var upload = new FlatButton("Upload report", ButtonKind.Primary, Icons.Download) { Height = 32, Margin = new Thickness(0, 1, 6, 0), VerticalAlignment = VerticalAlignment.Top };
        var clear = new FlatButton("Clear", ButtonKind.Secondary, Icons.Clear) { Height = 32, Margin = new Thickness(0, 1, 0, 0), VerticalAlignment = VerticalAlignment.Top };
        export.Click += (_, _) => DarkMenu.Show(export,
        [
            ("Full report (JSON)…", false, () => _ = ExportJson()),
            ("Findings table (CSV)…", false, () => _ = ExportCsv()),
        ]);
        upload.Click += async (_, _) => await UploadReport(upload);
        clear.Click += (_, _) => { if (_scanTask is not { IsCompleted: false }) { ClearResults(); RefreshAll(); ShowDetail(); } };
        bar.Children.Add(export); bar.Children.Add(upload); bar.Children.Add(clear);
        page.Children.Add(Dock(bar, Avalonia.Controls.Dock.Top));

        // details panel
        _dName.Height = 24;
        _dPath.Height = 48; _dPath.TextWrapping = TextWrapping.Wrap;
        _dMeta.Height = 84; _dMeta.TextWrapping = TextWrapping.Wrap; _dMeta.LineHeight = Ui.Small.Size * 1.55;
        _dTypes.Columns.AddRange([new("Type", 0), new("High", 46, true), new("Med", 38, true), new("Low", 36, true), new("Uniq", 48, true)]);
        _dTypes.EmptyText = "—";
        _dTypes.SetRows([]);
        _dExplorer.Click += (_, _) => ShowInFileManager();
        _detailCard.Add(_dName, _dPath, Gap(4), _dMeta, Gap(8), Caption("PII in this file"), Gap(4), _dTypes, Gap(12), _dExplorer);
        _detailCard.VerticalAlignment = VerticalAlignment.Top;
        var details = new Panel { Width = 340, Margin = new Thickness(14, 0, 0, 0) };
        details.Children.Add(_detailCard);

        var listCard = new Card(fill: true);
        listCard.BodyHost!.Margin = new Thickness(2);
        _emptyFindings.HorizontalAlignment = HorizontalAlignment.Center;
        _emptyFindings.VerticalAlignment = VerticalAlignment.Center;
        listCard.BodyHost.Children.Add(_list);
        listCard.BodyHost.Children.Add(_emptyFindings);

        var body = new DockPanel();
        body.Children.Add(Dock(details, Avalonia.Controls.Dock.Right));
        body.Children.Add(listCard);
        page.Children.Add(body);
        return page;
    }

    // ================================================================== insights / skipped
    Control BuildInsightsPage()
    {
        var stack = new StackPanel();
        var types = new Card("PII type breakdown", Icons.Chart);
        types.Add(_breakdown);
        var loc = new Card("Location classification", Icons.Pin);
        loc.Add(_locations);
        stack.Children.Add(PageHeader("Insights", "What kinds of personal data were found, and whether they sit where policy allows."));
        stack.Children.Add(types); stack.Children.Add(Gap(14)); stack.Children.Add(loc);
        return ScrollPage(stack, new Thickness(0, 0, 8, 0));
    }

    Control BuildSkippedPage()
    {
        var page = new DockPanel();
        page.Children.Add(Dock(PageHeader("Skipped files", "Files that were not scanned and why — unsupported types, encrypted or corrupt files, size limits."), Avalonia.Controls.Dock.Top));
        var card = new Card(fill: true);
        card.BodyHost!.Margin = new Thickness(16, 10, 8, 10);
        _skipList.Columns.AddRange([new("Reason", 300), new("Files / path", 0)]);
        _skipList.SetRows([]);
        _skipList.VerticalAlignment = VerticalAlignment.Top;
        card.BodyHost.Children.Add(ScrollPage(_skipList, new Thickness(0, 0, 8, 0)));
        page.Children.Add(card);
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
                _start.IsEnabled = false;
                _statusText.Text = "Stopping…";
            }
            else StartScan(_paths.Paths.ToList());
        };
        _addFolder.Click += async (_, _) => await AddFolder();
        _defaults.Click += (_, _) => _paths.Set(AllDrives());
        _workers.SelectionChanged += (_, _) => UpdateEngineText();
        _drop.Click += async (_, _) => { if (_drop.IsEffectivelyEnabled) await PickFiles(); };
        _timer.Tick += (_, _) => Tick();

        _list.ColumnClick += (_, col) =>
        {
            if (_list.SortCol == col) _list.SortDesc = !_list.SortDesc; else { _list.SortCol = col; _list.SortDesc = col is 0 or 2 or 3; }
            RefreshView();
        };
        _list.SelectionChanged += (_, _) => ShowDetail();
        _list.ItemActivated += (_, _) => ShowInFileManager();
        _search.Box.TextChanged += (_, _) => RefreshView();

        // drag & drop anywhere: folders are added to the list, files are scanned right away
        DragDrop.SetAllowDrop(this, true);
        AddHandler(DragDrop.DragEnterEvent, OnDragOver);
        AddHandler(DragDrop.DragOverEvent, OnDragOver);
        AddHandler(DragDrop.DragLeaveEvent, (_, _) => _drop.SetDragOver(false));
        AddHandler(DragDrop.DropEvent, (_, e) =>
        {
            _drop.SetDragOver(false);
            if (_scanTask is { IsCompleted: false }) return;
            var items = e.DataTransfer.TryGetFiles()?.Select(f => f.TryGetLocalPath()).OfType<string>().ToList();
            if (items == null) return;
            foreach (var d in items.Where(Directory.Exists)) _paths.Add(d);
            var files = items.Where(File.Exists).ToList();
            if (files.Count > 0) StartScan(files);
        });
        Closing += (_, _) => _cts?.Cancel();
    }

    void OnDragOver(object? sender, DragEventArgs e)
    {
        if (e.DataTransfer.Contains(DataFormat.File) && _scanTask is not { IsCompleted: false })
        {
            e.DragEffects = DragDropEffects.Copy;
            _drop.SetDragOver(true);
        }
        else e.DragEffects = DragDropEffects.None;
    }

    void UpdateEngineText() =>
        _engineText.Text = $"Native engine v{Scanner.Version}  ·  {_workers.Value} workers  ·  OCR: {(Ocr.Available ? Ocr.Description : "not available")}";

    async Task AddFolder()
    {
        try
        {
            var picked = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = "Choose folders to scan", AllowMultiple = true });
            foreach (var f in picked) if (f.TryGetLocalPath() is { } p) _paths.Add(p);
        }
        catch (Exception e) { _statusText.Text = "Folder picker unavailable: " + e.Message; }
    }

    async Task PickFiles()
    {
        try
        {
            var picked = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Choose files to scan", AllowMultiple = true });
            var files = picked.Select(f => f.TryGetLocalPath()).OfType<string>().ToList();
            if (files.Count > 0) StartScan(files);
        }
        catch (Exception e) { _statusText.Text = "File picker unavailable: " + e.Message; }
    }

    void ResetDefaultFolders()
    {
        var role = Profile.All.GetValueOrDefault(_role.Value) ?? Profile.All["general"];
        _paths.Set(role.DefaultScan.Select(Scanner.ExpandUser)
            .Select(p => Directory.Exists(p) ? p : Scanner.XdgUserDir(p) ?? p)
            .Where(Directory.Exists));
    }

    /// <summary>"Full scan (all drives)": every fixed, mounted filesystem. The walker crosses mount
    /// points, so nested mounts (e.g. /home under /) are covered by their parent.</summary>
    static List<string> AllDrives()
    {
        string[] pseudo = ["/proc", "/sys", "/dev", "/run", "/snap"];
        var roots = DriveInfo.GetDrives()
            .Where(d => { try { return d.DriveType == DriveType.Fixed && d.IsReady; } catch { return false; } })
            .Select(d => d.RootDirectory.FullName.TrimEnd('/') is { Length: > 0 } r ? r : "/")
            .Where(r => !pseudo.Any(p => r == p || r.StartsWith(p + "/")))
            .Distinct().OrderBy(r => r.Length).ToList();
        var outp = new List<string>();
        foreach (var r in roots)
            if (!outp.Any(o => o == "/" || r == o || r.StartsWith(o + "/"))) outp.Add(r);
        return outp.Count > 0 ? outp : ["/"];
    }

    // ================================================================== scanning
    void ClearResults()
    {
        _rows.Clear(); _view.Clear(); _list.SetItems([]);
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
        _start.Glyph = running ? Icons.Stop : Icons.Play;
        _start.Font = running ? Ui.Base : Ui.Bold;
        _start.IsEnabled = true;
        _start.InvalidateVisual();
        _paths.IsEnabled = _role.IsEnabled = _maxMb.IsEnabled = _workers.IsEnabled = _addFolder.IsEnabled = _defaults.IsEnabled = _drop.IsEnabled = !running;
        _idleCard.IsVisible = false;
        _progressCard.IsVisible = running;
        _statusProgress.IsVisible = running;
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
        _liveTypes.Items = new();
        _pct.Text = "0%"; _bar.Value = 0;
        SetRunning(true);
        ShowPage("scan");
        _statusText.Text = "Scanning…";
        _scanTask = Task.Run(() => Scanner.Run(o, live, token)).ContinueWith(t => Dispatcher.UIThread.Post(() => ScanFinished(t, fileScan)));
    }

    static FindingRow MakeRow(string path, long size, DateTime mod, Dictionary<string, TypeCount> types, string? sha, Profile profile)
    {
        double sc = Detectors.ScoreTypes(types);
        bool reportable = types.Values.Any(v => v.High > 0 || v.Medium > 0);
        return new FindingRow
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
        _statusText.Text = $"{(stopped ? "Stopped" : "Finished")} · {s["files_scanned"]} of {s["files_seen"]} files scanned · " +
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
        if (_scanTask is not { IsCompleted: false }) _idleCard.IsVisible = _rows.Count == 0 && _filesSeen == 0;

        var totals = new Dictionary<string, (int H, int M, int L)>();
        foreach (var r in _rows.Values)
            foreach (var (t, c) in r.Types)
            {
                var x = totals.GetValueOrDefault(t);
                totals[t] = (x.H + c.High, x.M + c.Medium, x.L + c.Low);
            }
        _breakdown.SetItems(totals.Select(kv => (kv.Key, kv.Value.H, kv.Value.M, kv.Value.L)));
        _locations.Counts = rep.GroupBy(r => r.Location).ToDictionary(g => g.Key, g => g.Count());
        _locations.InvalidateVisual();

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
        string q = (_search.Box.Text ?? "").Trim();
        IEnumerable<FindingRow> rows = _rows.Values;
        if (_tierFilter.Length > 0) rows = rows.Where(r => r.Tier == _tierFilter);
        if (q.Length > 0) rows = rows.Where(r => r.Path.Contains(q, StringComparison.OrdinalIgnoreCase) || r.Types.Keys.Any(k => k.Contains(q, StringComparison.OrdinalIgnoreCase)));
        Func<FindingRow, IComparable> key = _list.SortCol switch
        {
            0 or 3 => r => r.Score,
            1 => r => Path.GetFileName(r.Path),
            2 => r => r.Total,
            _ => r => r.Location,
        };
        string? selected = _list.Selected?.Path;
        _view = (_list.SortDesc ? rows.OrderByDescending(key) : rows.OrderBy(key)).ThenBy(r => r.Path, StringComparer.OrdinalIgnoreCase).ToList();
        _list.SetItems(_view);
        _emptyFindings.IsVisible = _view.Count == 0;
        _list.IsVisible = _view.Count > 0;
        _emptyFindings.Text = _rows.Count == 0 ? "No findings yet — run a scan from the Scan page." : "No findings match the current filter.";
        int i = selected == null ? -1 : _view.FindIndex(r => r.Path == selected);
        _list.Select(i, raise: false);
        if (selected != null && i < 0) ShowDetail();
    }

    void ShowDetail()
    {
        var r = _list.Selected;
        if (r == null)
        {
            _dName.Text = "No file selected";
            _dPath.Text = "Select a finding to see its details.";
            _dMeta.Text = "";
            _dExplorer.IsEnabled = false;
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
        _dExplorer.IsEnabled = File.Exists(r.Path);
    }

    public static string LocationLabel(string l) => l switch
    {
        "violation" => "Policy violation", "review" => "Needs review", "expected_location" => "Expected location", _ => "—",
    };

    static string FormatSize(long b) => b >= 1 << 20 ? $"{b / 1048576.0:F1} MB" : b >= 1024 ? $"{b / 1024.0:F0} KB" : $"{b} B";

    /// <summary>Linux counterpart of "explorer.exe /select,": ask the desktop's file manager to reveal
    /// the file (org.freedesktop.FileManager1), else open its folder with xdg-open.</summary>
    void ShowInFileManager()
    {
        var r = _list.Selected;
        if (r == null || !File.Exists(r.Path)) return;
        string path = r.Path;
        Task.Run(() =>
        {
            static bool Run(string exe, params string[] args)
            {
                try
                {
                    var psi = new ProcessStartInfo(exe) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
                    foreach (var a in args) psi.ArgumentList.Add(a);
                    using var p = Process.Start(psi);
                    if (p == null) return false;
                    if (!p.WaitForExit(5000)) return true; // still running: a file manager window is opening
                    return p.ExitCode == 0;
                }
                catch { return false; }
            }
            string uri = new Uri(path).AbsoluteUri;
            if (Run("dbus-send", "--session", "--print-reply", "--dest=org.freedesktop.FileManager1", "--type=method_call",
                    "/org/freedesktop/FileManager1", "org.freedesktop.FileManager1.ShowItems", $"array:string:{uri}", "string:")) return;
            Run("xdg-open", Path.GetDirectoryName(path) ?? "/");
        });
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

    async Task<string?> SaveAs(string title, string fileName, string typeName, string pattern, byte[] data)
    {
        try
        {
            var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = title, SuggestedFileName = fileName, DefaultExtension = Path.GetExtension(fileName).TrimStart('.'),
                ShowOverwritePrompt = true, FileTypeChoices = [new FilePickerFileType(typeName) { Patterns = [pattern] }],
            });
            if (file == null) return null;
            await using (var s = await file.OpenWriteAsync())
            {
                s.SetLength(0);
                await s.WriteAsync(data);
            }
            return file.TryGetLocalPath() ?? file.Name;
        }
        catch (Exception e)
        {
            _statusText.Text = "Could not save: " + e.Message;
            return null;
        }
    }

    async Task ExportJson()
    {
        if (_rows.Count == 0 && _filesSeen == 0) { _statusText.Text = "Nothing to export yet — run a scan first."; return; }
        var json = Encoding.UTF8.GetBytes(BuildExport().ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        var saved = await SaveAs("Save report", $"pii_report_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmm}.json", "JSON report", "*.json", json);
        if (saved != null) _statusText.Text = "Report saved: " + saved;
    }

    async Task UploadReport(FlatButton trigger)
    {
        if (_rows.Count == 0 && _filesSeen == 0) { _statusText.Text = "Nothing to upload yet — run a scan first."; return; }

        string? key = Uploader.SavedKey;
        if (key == null)
        {
            var dlg = new ApiKeyWindow();
            if (!await dlg.ShowDialog<bool>(this)) return;
            key = Uploader.SavedKey = dlg.EnteredKey;
        }

        trigger.IsEnabled = false;
        _statusText.Text = "Uploading report…";
        var result = await Uploader.UploadAsync(BuildExport(), key);
        trigger.IsEnabled = true;

        if (result.Success) { _statusText.Text = result.Message; return; }

        _statusText.Text = "Upload failed.";
        if (result.Message.Contains("Invalid or revoked", StringComparison.OrdinalIgnoreCase)) Uploader.SavedKey = null;
        await MessageWindow.Show(this, result.Message, "Upload failed");
    }

    async Task ExportCsv()
    {
        if (_rows.Count == 0) { _statusText.Text = "Nothing to export yet — run a scan first."; return; }
        static string Q(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";
        var sb = new StringBuilder("tier,score,path,pii_types,location_class,size_bytes,modified,sha256\r\n");
        foreach (var r in _view)
        {
            string types = string.Join("; ", r.Types.OrderByDescending(t => t.Value.Count).Select(t => $"{t.Key}={t.Value.Count}"));
            sb.Append($"{r.Tier},{r.Score:0.#},{Q(r.Path)},{Q(types)},{r.Location},{r.Size},{r.Modified:yyyy-MM-ddTHH:mm:ss},{r.Sha}\r\n");
        }
        var enc = new UTF8Encoding(true);
        byte[] data = [.. enc.GetPreamble(), .. enc.GetBytes(sb.ToString())];
        var saved = await SaveAs("Save findings", $"pii_findings_{Environment.MachineName}_{DateTime.Now:yyyyMMdd_HHmm}.csv", "CSV", "*.csv", data);
        if (saved != null) _statusText.Text = "CSV saved: " + saved;
    }
}
