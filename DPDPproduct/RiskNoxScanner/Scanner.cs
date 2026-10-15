// Scan driver: port of pii_scan.run_scan with a parallel pipeline.
//   one enumerator thread -> bounded channel -> N worker threads -> merged report
// The report JSON has the same shape as the Python reference so the UI and tools are shared.
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Channels;

namespace RiskNox;

public sealed class Profile
{
    public List<string> Approved { get; init; } = [];
    public List<string> Disallowed { get; init; } = [];
    public List<string> DefaultScan { get; init; } = [];

    static readonly List<string> DisallowedDefault =
        ["downloads", "desktop", "temp", "tmp", "onedrive - personal", "dropbox", "google drive", "icloud", "/media/", "/mnt/", "\\usb"];
    static readonly List<string> Home = ["~/Desktop", "~/Documents", "~/Downloads"];

    public static readonly Dictionary<string, Profile> All = new()
    {
        ["general"] = new() { Disallowed = DisallowedDefault, DefaultScan = Home },
        ["hr"] = new() { Approved = ["hr_share", "hr-share", "hrshare"], Disallowed = DisallowedDefault, DefaultScan = Home },
        ["finance"] = new() { Approved = ["finance_share", "finance-share"], Disallowed = DisallowedDefault, DefaultScan = Home },
    };

    public string Classify(string path)
    {
        string p = path.ToLowerInvariant().Replace('\\', '/');
        foreach (var f in Approved) if (p.Contains(f.ToLowerInvariant().Replace('\\', '/'))) return "expected_location";
        foreach (var f in Disallowed) if (p.Contains(f.ToLowerInvariant().Replace('\\', '/'))) return "violation";
        return "review";
    }

    /// <summary>Load extra/override profiles from the same JSON format pii_scan.py accepts.</summary>
    public static void LoadFile(string file)
    {
        var root = JsonNode.Parse(File.ReadAllText(file))!.AsObject();
        foreach (var (name, node) in root)
        {
            List<string> L(string k) => node?[k]?.AsArray().Select(x => x!.GetValue<string>()).ToList() ?? [];
            All[name] = new Profile { Approved = L("approved_fragments"), Disallowed = L("disallowed_fragments"), DefaultScan = L("default_scan") };
        }
    }
}

public sealed class ScanOptions
{
    public List<string> Paths { get; set; } = [];
    public string Role { get; set; } = "general";
    public int MaxMb { get; set; } = 50;
    public bool Samples { get; set; }
    public string? CacheFile { get; set; }
    public int Workers { get; set; } = Math.Max(1, Environment.ProcessorCount - 1);
    public int ThrottleMs { get; set; }
    /// <summary>Called from worker threads for each file with findings (path, size, modified, types).</summary>
    public Action<string, long, DateTime, Dictionary<string, TypeCount>>? OnFinding { get; set; }
}

/// <summary>Live counters the UI polls while a scan runs.</summary>
public sealed class LiveStatus
{
    public int FilesSeen, FilesScanned, FilesWithPii, CacheHits, FilesDone;
    public volatile string CurrentFile = "";
    public readonly DateTime Started = DateTime.Now;
    readonly Dictionary<string, TypeCount> _byType = new();

    public void AddTypes(Dictionary<string, TypeCount> types)
    {
        lock (_byType)
            foreach (var (t, v) in types)
            {
                if (!_byType.TryGetValue(t, out var c)) _byType[t] = c = new TypeCount();
                c.High += v.High; c.Medium += v.Medium; c.Low += v.Low;
            }
    }

    public JsonObject ToJson(string state)
    {
        var bt = new JsonObject();
        lock (_byType)
            foreach (var (t, c) in _byType)
                bt[t] = new JsonObject { ["high"] = c.High, ["medium"] = c.Medium, ["low"] = c.Low };
        return new JsonObject
        {
            ["state"] = state, ["current_file"] = CurrentFile,
            ["elapsed_s"] = Math.Round((DateTime.Now - Started).TotalSeconds, 1),
            ["files_seen"] = FilesSeen, ["files_scanned"] = FilesScanned,
            ["files_with_pii"] = FilesWithPii, ["cache_hits"] = CacheHits, ["findings_by_type"] = bt,
        };
    }
}

public static class Scanner
{
    public const string Version = "1.0.0";
    static readonly HashSet<string> ExcludeDirs = new(StringComparer.OrdinalIgnoreCase)
        { ".git", "node_modules", "__pycache__", "venv", ".venv", "site-packages", "$recycle.bin" };

    // Linux/Unix only: kernel and runtime pseudo-filesystems (endless or device files) and the desktop
    // trash, the counterpart of $recycle.bin. Empty on Windows, so Windows behaviour is unchanged.
    static readonly HashSet<string> ExcludeRoots = OperatingSystem.IsWindows() ? [] :
        ["/proc", "/sys", "/dev", "/run", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local/share/Trash")];

    static bool Excluded(string dir)
    {
        string name = Path.GetFileName(dir);
        if (ExcludeDirs.Contains(name)) return true;
        if (OperatingSystem.IsWindows()) return false;
        return ExcludeRoots.Contains(dir) || name == ".Trash" || name.StartsWith(".Trash-", StringComparison.Ordinal);
    }

    sealed record FileResult(string Path, long Size, DateTime Modified, string? Sha, Dictionary<string, TypeCount>? Types,
        Dictionary<string, List<string>>? Samples, string? Skip, string Ext);

    sealed class CacheEntry
    {
        public long Size { get; set; }
        public long MtimeTicks { get; set; }
        public Dictionary<string, int[]> Types { get; set; } = new(); // type -> [high, medium, low, unique]
        public Dictionary<string, List<string>>? Samples { get; set; }
    }

    /// <summary>Same as os.path.splitext(name)[1].lower(): leading dots are not an extension.</summary>
    public static string Ext(string name)
    {
        string n = name.TrimStart('.');
        int i = n.LastIndexOf('.');
        return i < 0 ? "" : n[i..].ToLowerInvariant();
    }

    public static string ExpandUser(string p)
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (p == "~") return home;
        if (p.StartsWith("~/") || p.StartsWith("~\\")) return Path.Combine(home, p[2..]);
        return p;
    }

    /// <summary>Linux/Unix: ~/Desktop, ~/Documents, ~/Downloads may be renamed/localised through
    /// xdg-user-dirs (~/.config/user-dirs.dirs). Returns the real folder, or null.</summary>
    public static string? XdgUserDir(string path)
    {
        try
        {
            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string key = Path.GetRelativePath(home, path) switch
            {
                "Desktop" => "XDG_DESKTOP_DIR", "Documents" => "XDG_DOCUMENTS_DIR", "Downloads" => "XDG_DOWNLOAD_DIR", _ => "",
            };
            if (key.Length == 0) return null;
            string cfg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME") is { Length: > 0 } x ? x : Path.Combine(home, ".config");
            string file = Path.Combine(cfg, "user-dirs.dirs");
            if (!File.Exists(file)) return null;
            foreach (var line in File.ReadLines(file))
            {
                var t = line.Trim();
                if (!t.StartsWith(key + "=")) continue;
                string v = t[(key.Length + 1)..].Trim().Trim('"').Replace("$HOME", home);
                return v.Length > 0 && Directory.Exists(v) && Path.GetFullPath(v) != Path.GetFullPath(home) ? v : null;
            }
        }
        catch { }
        return null;
    }

    static IEnumerable<string> Walk(string root, CancellationToken ct)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0 && !ct.IsCancellationRequested)
        {
            string dir = stack.Pop();
            string[] files, dirs;
            try { files = Directory.GetFiles(dir); dirs = Directory.GetDirectories(dir); }
            catch { continue; } // access denied etc.: skipped silently like os.walk
            foreach (var f in files) yield return f;
            for (int i = dirs.Length - 1; i >= 0; i--)
            {
                var d = dirs[i];
                if (Excluded(d)) continue;
                try { if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0) continue; } // no symlink/junction follow
                catch { continue; }
                stack.Push(d);
            }
        }
    }

    static string Sha256(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 20, FileOptions.SequentialScan);
        return Convert.ToHexStringLower(SHA256.HashData(fs));
    }

    static FileResult ScanOne(string path, ScanOptions o, Dictionary<string, CacheEntry> cache, ConcurrentDictionary<string, CacheEntry> newCache, LiveStatus live)
    {
        string fn = Path.GetFileName(path), ext = Ext(fn);
        FileInfo fi;
        try
        {
            if (fn.StartsWith("~$")) throw new SkipException("office_lock_file");
            fi = new FileInfo(path);
            if (!fi.Exists) throw new FileNotFoundException();
            if (fi.LinkTarget != null) throw new SkipException("symlink");
            if (!Readers.Supported.Contains(ext) && !Readers.LegacyExt.Contains(ext)) throw new SkipException("unsupported_type");
            if (fi.Length > o.MaxMb * 1024L * 1024L) throw new SkipException("too_large");
            Dictionary<string, TypeCount> types;
            Dictionary<string, List<string>>? samples = null;
            long mt = fi.LastWriteTimeUtc.Ticks;
            if (cache.TryGetValue(path, out var c) && c.Size == fi.Length && c.MtimeTicks == mt)
            {
                types = c.Types.ToDictionary(kv => kv.Key, kv => new TypeCount { High = kv.Value[0], Medium = kv.Value[1], Low = kv.Value[2], Unique = kv.Value[3] });
                samples = c.Samples;
                Interlocked.Increment(ref live.CacheHits);
            }
            else
            {
                var agg = new Agg(o.Samples);
                Readers.ScanFile(path, ext, agg);
                types = agg.Result();
                samples = o.Samples ? agg.Samples : null;
            }
            newCache[path] = new CacheEntry
            {
                Size = fi.Length, MtimeTicks = mt, Samples = samples,
                Types = types.ToDictionary(kv => kv.Key, kv => new[] { kv.Value.High, kv.Value.Medium, kv.Value.Low, kv.Value.Unique }),
            };
            Interlocked.Increment(ref live.FilesScanned);
            if (types.Count == 0) return new FileResult(path, fi.Length, fi.LastWriteTime, null, null, null, null, ext);
            if (types.Values.Any(v => v.High > 0 || v.Medium > 0)) Interlocked.Increment(ref live.FilesWithPii);
            live.AddTypes(types);
            o.OnFinding?.Invoke(path, fi.Length, fi.LastWriteTime, types);
            return new FileResult(path, fi.Length, fi.LastWriteTime, Sha256(path), types, samples, null, ext);
        }
        catch (SkipException s) { return new FileResult(path, 0, default, null, null, null, s.Reason, ext); }
        catch (Exception e) { return new FileResult(path, 0, default, null, null, null, "error:" + e.GetType().Name, ext); }
    }

    public static JsonObject Run(ScanOptions o, LiveStatus live, CancellationToken ct)
    {
        var profile = Profile.All.GetValueOrDefault(o.Role) ?? Profile.All["general"];
        Pdf.Configure(o.Workers);
        var started = DateTime.Now;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var cache = new Dictionary<string, CacheEntry>();
        if (o.CacheFile != null && File.Exists(o.CacheFile))
        {
            try { cache = JsonSerializer.Deserialize<Dictionary<string, CacheEntry>>(File.ReadAllText(o.CacheFile)) ?? new(); }
            catch { cache = new(); }
        }
        var newCache = new ConcurrentDictionary<string, CacheEntry>();
        var results = new ConcurrentBag<FileResult>();
        var missing = new List<string>();

        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(4096) { SingleWriter = true });
        var workers = Enumerable.Range(0, Math.Max(1, o.Workers)).Select(_ => new Thread(() =>
        {
            Thread.CurrentThread.Priority = ThreadPriority.BelowNormal;
            var reader = channel.Reader;
            while (reader.WaitToReadAsync().AsTask().GetAwaiter().GetResult())
                while (reader.TryRead(out var path))
                {
                    if (ct.IsCancellationRequested) continue; // drain
                    live.CurrentFile = path;
                    results.Add(ScanOne(path, o, cache, newCache, live));
                    Interlocked.Increment(ref live.FilesDone);
                    if (o.ThrottleMs > 0) Thread.Sleep(o.ThrottleMs);
                }
        }) { IsBackground = true, Name = "scan-worker" }).ToList();
        workers.ForEach(w => w.Start());

        try
        {
            foreach (var p0 in o.Paths)
            {
                if (ct.IsCancellationRequested) break;
                string root = ExpandUser(p0);
                if (!Directory.Exists(root) && !File.Exists(root))
                {
                    // Known folders are often redirected into OneDrive.
                    string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    string od = Path.Combine(home, "OneDrive", Path.GetRelativePath(home, root));
                    if (Directory.Exists(od)) root = od;
                    else if (!OperatingSystem.IsWindows() && XdgUserDir(root) is { } xdg) root = xdg;
                }
                if (File.Exists(root))
                {
                    Interlocked.Increment(ref live.FilesSeen);
                    channel.Writer.WriteAsync(root).AsTask().GetAwaiter().GetResult();
                    continue;
                }
                if (!Directory.Exists(root)) { missing.Add(root); Console.Error.WriteLine($"WARNING: path not found, skipped: {root}"); continue; }
                foreach (var f in Walk(root, ct))
                {
                    Interlocked.Increment(ref live.FilesSeen);
                    channel.Writer.WriteAsync(f, ct).AsTask().GetAwaiter().GetResult();
                }
            }
        }
        catch (OperationCanceledException) { }
        channel.Writer.Complete();
        workers.ForEach(w => w.Join());

        if (o.CacheFile != null)
        {
            try { File.WriteAllText(o.CacheFile, JsonSerializer.Serialize(newCache)); } catch { }
        }
        return BuildReport(o, profile, results, missing, live, started, sw.Elapsed.TotalSeconds);
    }

    static JsonObject TypesJson(Dictionary<string, TypeCount> types)
    {
        var o = new JsonObject();
        foreach (var (t, c) in types)
            o[t] = new JsonObject { ["high"] = c.High, ["medium"] = c.Medium, ["low"] = c.Low, ["count"] = c.Count, ["unique"] = c.Unique };
        return o;
    }

    static JsonObject Counts(IEnumerable<KeyValuePair<string, int>> kv)
    {
        var o = new JsonObject();
        foreach (var (k, v) in kv) o[k] = v;
        return o;
    }

    static JsonObject BuildReport(ScanOptions o, Profile profile, IEnumerable<FileResult> all, List<string> missing,
        LiveStatus live, DateTime started, double seconds)
    {
        var findings = new List<(double Score, string Path, JsonObject Obj)>();
        var skipped = new Dictionary<string, int>();
        var unsupported = new Dictionary<string, int>();
        var notable = new JsonArray();
        var typeTotals = new Dictionary<string, TypeCount>();
        var tiers = new Dictionary<string, int>();
        var loc = new Dictionary<string, int>();

        foreach (var r in all.OrderBy(r => r.Path, StringComparer.Ordinal))
        {
            if (r.Skip != null)
            {
                skipped[r.Skip] = skipped.GetValueOrDefault(r.Skip) + 1;
                if (r.Skip == "unsupported_type")
                {
                    string k = r.Ext.Length > 0 ? r.Ext : "(no extension)";
                    unsupported[k] = unsupported.GetValueOrDefault(k) + 1;
                }
                if (r.Skip is not ("unsupported_type" or "symlink" or "office_lock_file") && notable.Count < 200)
                    notable.Add(new JsonObject { ["path"] = r.Path, ["reason"] = r.Skip });
                continue;
            }
            if (r.Types == null) continue;
            foreach (var (t, v) in r.Types)
            {
                if (!typeTotals.TryGetValue(t, out var tt)) typeTotals[t] = tt = new TypeCount();
                tt.High += v.High; tt.Medium += v.Medium; tt.Low += v.Low;
            }
            double sc = Detectors.ScoreTypes(r.Types);
            bool reportable = r.Types.Values.Any(v => v.High > 0 || v.Medium > 0);
            string lc = reportable ? profile.Classify(r.Path) : "n/a";
            string tier = Detectors.Tier(sc);
            if (lc != "n/a")
            {
                tiers[tier] = tiers.GetValueOrDefault(tier) + 1;
                loc[lc] = loc.GetValueOrDefault(lc) + 1;
            }
            var f = new JsonObject
            {
                ["path"] = r.Path, ["size"] = r.Size, ["modified"] = r.Modified.ToString("yyyy-MM-ddTHH:mm:ss"),
                ["sha256"] = r.Sha, ["types"] = TypesJson(r.Types), ["score"] = sc, ["tier"] = tier, ["location_class"] = lc,
            };
            if (o.Samples && r.Samples != null)
                f["samples"] = JsonSerializer.SerializeToNode(r.Samples);
            findings.Add((sc, r.Path, f));
        }

        var bt = new JsonObject();
        foreach (var (t, c) in typeTotals) bt[t] = new JsonObject { ["high"] = c.High, ["medium"] = c.Medium, ["low"] = c.Low };
        var fArr = new JsonArray();
        foreach (var f in findings.OrderByDescending(f => f.Score).ThenBy(f => f.Path, StringComparer.Ordinal)) fArr.Add(f.Obj);

        return new JsonObject
        {
            ["meta"] = new JsonObject
            {
                ["scanner_version"] = Version, ["engine"] = "RiskNox native (.NET)", ["host"] = Environment.MachineName,
                ["os"] = RuntimeInformation.OSDescription, ["role"] = o.Role,
                ["paths"] = new JsonArray(o.Paths.Select(p => (JsonNode?)JsonValue.Create(p)).ToArray()),
                ["started"] = started.ToString("yyyy-MM-ddTHH:mm:ss"), ["duration_s"] = Math.Round(seconds, 1),
                ["workers"] = o.Workers, ["ocr_available"] = Ocr.Available,
                ["note"] = "Endpoint PII posture only; not a DPDP compliance verdict. Scores/tiers are tunable heuristics. " +
                           $"No file content is stored. OCR ({Ocr.EngineName} engine) is used for image files and image-only PDFs when available.",
            },
            ["summary"] = new JsonObject
            {
                ["files_seen"] = live.FilesSeen, ["files_scanned"] = live.FilesScanned,
                ["files_with_pii"] = live.FilesWithPii, ["cache_hits"] = live.CacheHits,
                ["by_tier"] = Counts(tiers), ["by_location_class"] = Counts(loc), ["findings_by_type"] = bt,
                ["skipped_by_reason"] = Counts(skipped),
                ["unsupported_by_extension"] = Counts(unsupported.OrderByDescending(kv => kv.Value).Take(20)),
            },
            ["findings"] = fArr, ["skipped_notable"] = notable,
            ["missing_paths"] = new JsonArray(missing.Select(p => (JsonNode?)JsonValue.Create(p)).ToArray()),
        };
    }
}
