// RiskNox PII Scanner - single-exe entry point.
//   (no args)            open the native Windows UI (double-click behaviour)
//   --paths ... [opts]   command-line scan, same flags as pii_scan.py (for EDR/script push)
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace RiskNox;

public static class Program
{
    [DllImport("kernel32")] static extern bool AttachConsole(int processId);

    [STAThread]
    public static int Main(string[] args)
    {
        // Below-normal priority keeps the user's machine responsive while scanning.
        try { Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.BelowNormal; } catch { }
        if (args.Length == 0 || args[0] == "--gui")
        {
            Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            // Never fail silently: log unexpected UI errors and tell the user where the log is.
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += (_, e) => ReportCrash(e.Exception);
            AppDomain.CurrentDomain.UnhandledException += (_, e) => ReportCrash(e.ExceptionObject as Exception);
            var main = new MainForm(args.Skip(1).ToList());
            // Password pops up over the main window; closing it exits the app.
            main.Shown += (_, _) =>
            {
                using var login = new LoginForm();
                if (login.ShowDialog(main) != DialogResult.OK) main.Close();
            };
            Application.Run(main);
            return 0;
        }
        // GUI-subsystem exe: borrow the parent console (cmd/PowerShell) for CLI output.
        AttachConsole(-1);
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }
        return Cli(args);
    }

    static int Cli(string[] args)
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
                case "-h" or "--help":
                    Console.WriteLine("""
                        RiskNoxScanner.exe                      open the scanner window
                        RiskNoxScanner.exe --gui DIR [DIR..]    open the window with these folders preselected
                        RiskNoxScanner.exe --paths DIR [DIR..]  command-line scan
                          --role general|hr|finance   --profile file.json   --output report.json
                          --samples   --max-mb 50   --cache cache.json   --workers N
                          --throttle-ms 0   --progress
                        """);
                    return 0;
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
        if (!Ocr.Available) Console.WriteLine("NOTE: Windows OCR engine not available; image files and scanned PDFs were skipped.");
        var miss = rep["missing_paths"]!.AsArray();
        if (miss.Count > 0) Console.WriteLine($"WARNING: {miss.Count} path(s) did not exist and were NOT scanned: {miss.ToJsonString()}");
        Console.WriteLine("Report: " + output);
        return 0;
    }

    public static readonly string CrashLog = Path.Combine(Path.GetTempPath(), "RiskNoxScanner_error.log");

    static void ReportCrash(Exception? e)
    {
        string n = Environment.NewLine;
        try { File.AppendAllText(CrashLog, $"[{DateTime.Now:s}] {e}{n}{n}"); } catch { }
        MessageBox.Show($"Something went wrong: {e?.Message}{n}{n}Details were written to:{n}{CrashLog}", "RiskNox PII Scanner",
            MessageBoxButtons.OK, MessageBoxIcon.Error);
    }

    static string Tail(string s, int n) => s.Length <= n ? s : s[^n..];
}
