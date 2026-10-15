// RiskNox PII Scanner for Linux - single-file entry point (same behaviour as the Windows exe).
//   (no args)            open the scanner window (double-click / desktop launcher)
//   --gui DIR [DIR..]    open the window with these folders preselected
//   --paths ... [opts]   command-line scan (shared Cli.cs), same flags as pii_scan.py (for EDR/script push)
using System.Diagnostics;
using System.Text;
using Avalonia;
using Avalonia.Threading;

namespace RiskNox;

public static class Program
{
    public static readonly string CrashLog = Path.Combine(Path.GetTempPath(), "RiskNoxScanner_error.log");

    [STAThread]
    public static int Main(string[] args)
    {
        // Below-normal priority (nice) keeps the user's machine responsive while scanning.
        try { Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.BelowNormal; } catch { }
        if (args.Length == 0 || args[0] == "--gui")
        {
            if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("DISPLAY")) &&
                string.IsNullOrEmpty(Environment.GetEnvironmentVariable("WAYLAND_DISPLAY")))
            {
                Console.Error.WriteLine("RiskNoxScanner: no graphical display found (DISPLAY / WAYLAND_DISPLAY not set).");
                Console.Error.WriteLine("For a headless scan use:  RiskNoxScanner --paths DIR [DIR..] --output report.json   (see --help)");
                return 1;
            }
            // Never fail silently: log unexpected UI errors and tell the user where the log is.
            AppDomain.CurrentDomain.UnhandledException += (_, e) => LogCrash(e.ExceptionObject as Exception);
            App.StartFolders = args.Skip(1).ToList();
            try
            {
                return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args.Length > 0 ? args.Skip(1).ToArray() : args);
            }
            catch (Exception e)
            {
                LogCrash(e);
                Console.Error.WriteLine($"RiskNoxScanner: could not start the window: {e.Message}{Environment.NewLine}Details: {CrashLog}");
                return 1;
            }
        }
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }
        return Cli.Run(args);
    }

    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>()
        .UsePlatformDetect()
        .WithInterFont()
        .With(new X11PlatformOptions { WmClass = "RiskNoxScanner" })
        .AfterSetup(_ => Dispatcher.UIThread.UnhandledException += (_, e) => { e.Handled = true; ReportCrash(e.Exception); })
        .LogToTrace();

    static void LogCrash(Exception? e)
    {
        string n = Environment.NewLine;
        try { File.AppendAllText(CrashLog, $"[{DateTime.Now:s}] {e}{n}{n}"); } catch { }
    }

    static void ReportCrash(Exception? e)
    {
        LogCrash(e);
        string n = Environment.NewLine;
        var owner = (Avalonia.Application.Current?.ApplicationLifetime as Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime)?.MainWindow;
        _ = MessageWindow.Show(owner, $"Something went wrong: {e?.Message}{n}{n}Details were written to:{n}{CrashLog}", "RiskNox PII Scanner", error: true);
    }
}
