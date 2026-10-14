// RiskNox PII Scanner - single-exe entry point.
//   (no args)            open the native Windows UI (double-click behaviour)
//   --paths ... [opts]   command-line scan (Cli.cs), same flags as pii_scan.py (for EDR/script push)
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

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
        return RiskNox.Cli.Run(args);
    }

    public static readonly string CrashLog = Path.Combine(Path.GetTempPath(), "RiskNoxScanner_error.log");

    static void ReportCrash(Exception? e)
    {
        string n = Environment.NewLine;
        try { File.AppendAllText(CrashLog, $"[{DateTime.Now:s}] {e}{n}{n}"); } catch { }
        MessageBox.Show($"Something went wrong: {e?.Message}{n}{n}Details were written to:{n}{CrashLog}", "RiskNox PII Scanner",
            MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
