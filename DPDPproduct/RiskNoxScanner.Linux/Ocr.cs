// Linux build: OCR through the system Tesseract engine (the counterpart of the Windows
// built-in Windows.Media.Ocr engine used by ../RiskNoxScanner/Ocr.cs). Nothing is bundled:
// if the `tesseract` command is installed (apt/dnf/pacman/zypper package "tesseract" or
// "tesseract-ocr"), image files and image-only PDFs are OCR'd, otherwise they are skipped
// with the same skip reasons as on Windows.
//   RISKNOX_TESSERACT  path of the tesseract binary (default: found on PATH)
//   RISKNOX_OCR_LANG   tesseract language(s), e.g. "eng+hin" (default: eng, else first installed)
using System.Diagnostics;
using System.Text;

namespace RiskNox;

public static class Ocr
{
    public const string EngineName = "Tesseract";
    public const string MissingNote =
        "NOTE: Tesseract OCR engine not available; image files and scanned PDFs were skipped. " +
        "Install it with your package manager (e.g. sudo apt install tesseract-ocr).";

    const int TimeoutMs = 120_000;

    sealed record Engine(string Exe, string Lang, string Version);

    static readonly Lazy<Engine?> _engine = new(Probe);

    public static bool Available => _engine.Value != null;

    /// <summary>"Tesseract 5.3.4 (eng)" for the status bar, or null when not installed.</summary>
    public static string? Description => _engine.Value is { } e ? $"{EngineName} {e.Version} ({e.Lang})" : null;

    /// <summary>Largest image side handed to the engine (same limit as the Windows engine).</summary>
    public static int MaxDimension => 10000;

    static string? FindExe()
    {
        string? env = Environment.GetEnvironmentVariable("RISKNOX_TESSERACT");
        if (!string.IsNullOrWhiteSpace(env)) return File.Exists(env) ? env : null;
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(':', StringSplitOptions.RemoveEmptyEntries)
                     .Concat(["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/snap/bin"]))
        {
            string p = Path.Combine(dir, "tesseract");
            if (File.Exists(p)) return p;
        }
        return null;
    }

    static Engine? Probe()
    {
        try
        {
            string? exe = FindExe();
            if (exe == null) return null;
            var (code, outp, err) = Exec(exe, ["--version"], 10_000);
            if (code != 0) return null;
            string first = (outp + "\n" + err).Split('\n').FirstOrDefault(l => l.StartsWith("tesseract", StringComparison.OrdinalIgnoreCase)) ?? "";
            string version = first.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1).FirstOrDefault()?.TrimStart('v') ?? "";

            var (lc, lo, _) = Exec(exe, ["--list-langs"], 10_000);
            if (lc != 0) return null;
            var langs = lo.Split('\n').Select(l => l.Trim())
                .Where(l => l.Length > 0 && !l.Contains(' ') && !l.EndsWith(':') && l != "osd").ToList();
            string? want = Environment.GetEnvironmentVariable("RISKNOX_OCR_LANG");
            string? lang = !string.IsNullOrWhiteSpace(want) ? want.Trim()
                : langs.Contains("eng") ? "eng" : langs.FirstOrDefault();
            return lang == null ? null : new Engine(exe, lang, version);
        }
        catch { return null; }
    }

    static (int Code, string Out, string Err) Exec(string exe, IEnumerable<string> args, int timeoutMs)
    {
        var psi = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        // The scanner already runs one OCR per worker; keep each tesseract single-threaded.
        psi.Environment["OMP_THREAD_LIMIT"] = "1";
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("tesseract did not start");
        var so = p.StandardOutput.ReadToEndAsync();
        var se = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(timeoutMs))
        {
            try { p.Kill(true); } catch { }
            throw new TimeoutException("tesseract timed out");
        }
        p.WaitForExit();
        return (p.ExitCode, so.Result, se.Result);
    }

    /// <summary>OCR an image file; returns one line per text line so "Aadhaar: ..." context survives.</summary>
    static string RunFile(string imagePath)
    {
        var e = _engine.Value ?? throw new SkipException("ocr_engine_missing");
        var (code, outp, _) = Exec(e.Exe, [imagePath, "stdout", "-l", e.Lang], TimeoutMs);
        if (code != 0) throw new InvalidDataException("tesseract could not read the image");
        var lines = outp.Replace("\f", "").Replace("\r", "").Split('\n').Where(l => l.Trim().Length > 0);
        return string.Join("\n", lines);
    }

    static string TempFile(string ext)
    {
        string dir = Path.Combine(Path.GetTempPath(), "risknox_ocr_" + Environment.ProcessId);
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, Guid.NewGuid().ToString("N") + ext);
    }

    /// <summary>OCR a top-down BGRA buffer (rendered PDF page).</summary>
    public static string Recognize(byte[] bgra, int width, int height)
    {
        // Binary PPM (P6): readable by every Tesseract/Leptonica build, no encoder needed.
        string file = TempFile(".ppm");
        try
        {
            using (var fs = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16))
            {
                fs.Write(Encoding.ASCII.GetBytes($"P6\n{width} {height}\n255\n"));
                var row = new byte[width * 3];
                for (int y = 0; y < height; y++)
                {
                    int src = y * width * 4;
                    for (int x = 0; x < width; x++, src += 4)
                    {
                        row[x * 3] = bgra[src + 2];
                        row[x * 3 + 1] = bgra[src + 1];
                        row[x * 3 + 2] = bgra[src];
                    }
                    fs.Write(row);
                }
            }
            return RunFile(file);
        }
        finally { try { File.Delete(file); } catch { } }
    }

    public static void ScanImage(string path, Agg agg)
    {
        if (!Available) throw new SkipException("ocr_engine_missing");
        string text;
        try { text = RunFile(path); }
        catch (SkipException) { throw; }
        catch (Exception e) { throw new SkipException("image_unreadable:" + e.GetType().Name); }
        if (text.Trim().Length == 0) throw new SkipException("ocr_no_text");
        agg.AddAll(text);
    }

    static Ocr()
    {
        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try { Directory.Delete(Path.Combine(Path.GetTempPath(), "risknox_ocr_" + Environment.ProcessId), true); } catch { }
        };
    }
}
