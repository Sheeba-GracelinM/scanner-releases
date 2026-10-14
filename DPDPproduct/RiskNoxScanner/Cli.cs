// Command-line scan (same flags as pii_scan.py, for EDR/script push). Shared by the Windows
// and Linux builds so both behave identically.
using System.Text.Json;

namespace RiskNox;

public static class Cli
{
    public static string ExeName => OperatingSystem.IsWindows() ? "RiskNoxScanner.exe" : "RiskNoxScanner";

    static string Help()
    {
        string e = ExeName;
        int col = e.Length + 22;
        return string.Join(Environment.NewLine,
            e.PadRight(col) + "open the scanner window",
            (e + " --gui DIR [DIR..]").PadRight(col) + "open the window with these folders preselected",
            (e + " --paths DIR [DIR..]").PadRight(col) + "command-line scan",
            "  --role general|hr|finance   --profile file.json   --output report.json",
            "  --samples   --max-mb 50   --cache cache.json   --workers N",
            "  --throttle-ms 0   --progress");
    }

    public static int Run(string[] args)
    {
        var o = new ScanOptions();
        string output = "pii_report.json";
        bool progress = false, pathsGiven = false;
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            string Next() => i + 1 < args.Length ? args[++i] : throw new ArgumentException("missing value for " + a);
            switch (a)
            {
                case "--paths":
                    pathsGiven = true;
                    while (i + 1 < args.Length && !args[i + 1].StartsWith("--")) o.Paths.Add(args[++i]);
                    break;
                case "--role": o.Role = Next(); break;
                case "--profile": Profile.LoadFile(Next()); break;
                case "--output": output = Next(); break;
                case "--samples": o.Samples = true; break;
                case "--max-mb": o.MaxMb = int.Parse(Next()); break;
                case "--throttle-ms": o.ThrottleMs = int.Parse(Next()); break;
                case "--cache": o.CacheFile = Next(); break;
                case "--workers": o.Workers = Math.Max(1, int.Parse(Next())); break;
                case "--progress": progress = true; break;
                case "--version": Console.WriteLine(Scanner.Version); return 0;
                case "-h" or "--help": Console.WriteLine(Help()); return 0;
                default: Console.Error.WriteLine("unknown argument: " + a); return 2;
            }
        }
        if (!Profile.All.ContainsKey(o.Role))
        {
            Console.Error.WriteLine($"unknown role '{o.Role}'; known: {string.Join(", ", Profile.All.Keys)}");
            return 2;
        }
        if (!pathsGiven || o.Paths.Count == 0) o.Paths = [.. Profile.All[o.Role].DefaultScan];

        var live = new LiveStatus();
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
        System.Threading.Timer? ticker = progress
            ? new System.Threading.Timer(_ => Console.Error.Write($"\r[{live.FilesScanned}/{live.FilesSeen} files] {Tail(live.CurrentFile, 80),-80}"), null, 0, 250)
            : null;
        var rep = Scanner.Run(o, live, cts.Token);
        ticker?.Dispose();
        if (progress) Console.Error.WriteLine();
        File.WriteAllText(output, rep.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        var s = rep["summary"]!;
        Console.WriteLine($"Scanned {s["files_scanned"]} files ({s["files_seen"]} seen) in {rep["meta"]!["duration_s"]}s " +
                          $"with {o.Workers} workers | files with PII: {s["files_with_pii"]} | by tier: {s["by_tier"]!.ToJsonString()} | " +
                          $"locations: {s["by_location_class"]!.ToJsonString()}");
        Console.WriteLine("Skipped: " + s["skipped_by_reason"]!.ToJsonString());
        Console.WriteLine("Unsupported types (top): " + s["unsupported_by_extension"]!.ToJsonString());
        if (!Ocr.Available) Console.WriteLine(Ocr.MissingNote);
        var miss = rep["missing_paths"]!.AsArray();
        if (miss.Count > 0) Console.WriteLine($"WARNING: {miss.Count} path(s) did not exist and were NOT scanned: {miss.ToJsonString()}");
        Console.WriteLine("Report: " + output);
        return 0;
    }

    static string Tail(string s, int n) => s.Length <= n ? s : s[^n..];
}
