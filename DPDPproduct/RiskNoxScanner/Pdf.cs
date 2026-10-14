// PDF text extraction and page rendering through PDFium (bblanchon/pdfium-binaries).
//
// PDFium keeps global state and is not thread-safe, so one loaded copy can serve only one
// thread at a time (measured: that lock was 100% of PDF scan time). To scan PDFs in
// parallel we load N independent copies of pdfium.dll under different file names: Windows
// maps each as a separate module with its own globals, and each worker borrows one engine.
using System.Collections.Concurrent;
using System.Runtime.InteropServices;

namespace RiskNox;

public static class Pdf
{
    sealed unsafe class Engine
    {
        public readonly delegate* unmanaged<IntPtr, nuint, IntPtr, IntPtr> LoadMemDocument64;
        public readonly delegate* unmanaged<uint> GetLastError;
        public readonly delegate* unmanaged<IntPtr, int> GetPageCount;
        public readonly delegate* unmanaged<IntPtr, int, IntPtr> LoadPage;
        public readonly delegate* unmanaged<IntPtr, void> ClosePage;
        public readonly delegate* unmanaged<IntPtr, void> CloseDocument;
        public readonly delegate* unmanaged<IntPtr, IntPtr> TextLoadPage;
        public readonly delegate* unmanaged<IntPtr, void> TextClosePage;
        public readonly delegate* unmanaged<IntPtr, int> TextCountChars;
        public readonly delegate* unmanaged<IntPtr, int, int, ushort*, int> TextGetText;
        public readonly delegate* unmanaged<IntPtr, float> PageWidth;
        public readonly delegate* unmanaged<IntPtr, float> PageHeight;
        public readonly delegate* unmanaged<int, int, int, IntPtr> BitmapCreate;
        public readonly delegate* unmanaged<IntPtr, int, int, int, int, uint, int> BitmapFillRect;
        public readonly delegate* unmanaged<IntPtr, IntPtr, int, int, int, int, int, int, void> RenderPageBitmap;
        public readonly delegate* unmanaged<IntPtr, IntPtr> BitmapGetBuffer;
        public readonly delegate* unmanaged<IntPtr, int> BitmapGetStride;
        public readonly delegate* unmanaged<IntPtr, void> BitmapDestroy;

        public Engine(IntPtr lib)
        {
            IntPtr F(string name) => NativeLibrary.GetExport(lib, name);
            LoadMemDocument64 = (delegate* unmanaged<IntPtr, nuint, IntPtr, IntPtr>)F("FPDF_LoadMemDocument64");
            GetLastError = (delegate* unmanaged<uint>)F("FPDF_GetLastError");
            GetPageCount = (delegate* unmanaged<IntPtr, int>)F("FPDF_GetPageCount");
            LoadPage = (delegate* unmanaged<IntPtr, int, IntPtr>)F("FPDF_LoadPage");
            ClosePage = (delegate* unmanaged<IntPtr, void>)F("FPDF_ClosePage");
            CloseDocument = (delegate* unmanaged<IntPtr, void>)F("FPDF_CloseDocument");
            TextLoadPage = (delegate* unmanaged<IntPtr, IntPtr>)F("FPDFText_LoadPage");
            TextClosePage = (delegate* unmanaged<IntPtr, void>)F("FPDFText_ClosePage");
            TextCountChars = (delegate* unmanaged<IntPtr, int>)F("FPDFText_CountChars");
            TextGetText = (delegate* unmanaged<IntPtr, int, int, ushort*, int>)F("FPDFText_GetText");
            PageWidth = (delegate* unmanaged<IntPtr, float>)F("FPDF_GetPageWidthF");
            PageHeight = (delegate* unmanaged<IntPtr, float>)F("FPDF_GetPageHeightF");
            BitmapCreate = (delegate* unmanaged<int, int, int, IntPtr>)F("FPDFBitmap_Create");
            BitmapFillRect = (delegate* unmanaged<IntPtr, int, int, int, int, uint, int>)F("FPDFBitmap_FillRect");
            RenderPageBitmap = (delegate* unmanaged<IntPtr, IntPtr, int, int, int, int, int, int, void>)F("FPDF_RenderPageBitmap");
            BitmapGetBuffer = (delegate* unmanaged<IntPtr, IntPtr>)F("FPDFBitmap_GetBuffer");
            BitmapGetStride = (delegate* unmanaged<IntPtr, int>)F("FPDFBitmap_GetStride");
            BitmapDestroy = (delegate* unmanaged<IntPtr, void>)F("FPDFBitmap_Destroy");
            ((delegate* unmanaged<void>)F("FPDF_InitLibrary"))();
        }

        /// <summary>Open a document from memory; caller must keep <paramref name="pin"/> alive until close.</summary>
        public IntPtr Open(byte[] data, out GCHandle pin)
        {
            pin = GCHandle.Alloc(data, GCHandleType.Pinned);
            IntPtr doc = LoadMemDocument64(pin.AddrOfPinnedObject(), (nuint)data.Length, IntPtr.Zero);
            if (doc == IntPtr.Zero)
            {
                uint err = GetLastError();
                pin.Free();
                throw new SkipException(err == 4 /* FPDF_ERR_PASSWORD */ ? "encrypted" : "pdf_unreadable_or_corrupt");
            }
            return doc;
        }
    }

    static readonly object InitGate = new();
    static BlockingCollection<Engine>? _pool;
    static string? _copyDir;

    /// <summary>Create the engine pool. Call once with the number of scan workers.</summary>
    public static void Configure(int engines)
    {
        lock (InitGate)
        {
            if (_pool != null) return;
            engines = Math.Max(1, engines);
            IntPtr first = NativeLibrary.Load("pdfium", typeof(Pdf).Assembly, null);
            var pool = new BlockingCollection<Engine> { new Engine(first) };
            if (engines > 1)
            {
                string? src = ModulePath(first);
                if (src != null)
                {
                    _copyDir = Path.Combine(Path.GetTempPath(), "risknox_pdfium_" + Environment.ProcessId);
                    Directory.CreateDirectory(_copyDir);
                    for (int i = 1; i < engines; i++)
                    {
                        try
                        {
                            string dst = Path.Combine(_copyDir, $"pdfium_{i}.dll");
                            File.Copy(src, dst, true);
                            pool.Add(new Engine(NativeLibrary.Load(dst)));
                        }
                        catch { break; } // fewer engines is still correct, only slower
                    }
                }
            }
            _pool = pool;
            AppDomain.CurrentDomain.ProcessExit += (_, _) => { try { if (_copyDir != null) Directory.Delete(_copyDir, true); } catch { } };
        }
    }

    public static int EngineCount => _pool?.Count ?? 0;

    [DllImport("kernel32", CharSet = CharSet.Unicode)] static extern uint GetModuleFileNameW(IntPtr module, char[] buf, uint size);

    static string? ModulePath(IntPtr module)
    {
        var buf = new char[32768];
        uint n = GetModuleFileNameW(module, buf, (uint)buf.Length);
        return n == 0 ? null : new string(buf, 0, (int)n);
    }

    static T With<T>(Func<Engine, T> f)
    {
        if (_pool == null) Configure(1);
        var e = _pool!.Take();
        try { return f(e); }
        finally { _pool.Add(e); }
    }

    static unsafe List<string> ExtractText(byte[] data) => With(e =>
    {
        var pages = new List<string>();
        IntPtr doc = e.Open(data, out var pin);
        try
        {
            int n = e.GetPageCount(doc);
            for (int i = 0; i < n; i++)
            {
                IntPtr page = e.LoadPage(doc, i);
                if (page == IntPtr.Zero) { pages.Add(""); continue; }
                string s = "";
                IntPtr tp = e.TextLoadPage(page);
                if (tp != IntPtr.Zero)
                {
                    int count = e.TextCountChars(tp);
                    if (count > 0)
                    {
                        var buf = new ushort[count + 1];
                        fixed (ushort* p = buf)
                        {
                            int written = e.TextGetText(tp, 0, count, p);
                            s = new string((char*)p, 0, Math.Max(0, written - 1));
                        }
                    }
                    e.TextClosePage(tp);
                }
                e.ClosePage(page);
                pages.Add(s);
            }
        }
        finally { e.CloseDocument(doc); pin.Free(); }
        return pages;
    });

    /// <summary>Render one page to a top-down opaque BGRA buffer (scale 1.0 = 72 dpi).</summary>
    static unsafe (byte[] Bgra, int Width, int Height)? RenderPage(byte[] data, int index, double scale, int maxDim) => With(e =>
    {
        IntPtr doc = e.Open(data, out var pin);
        try
        {
            IntPtr page = e.LoadPage(doc, index);
            if (page == IntPtr.Zero) return ((byte[], int, int)?)null;
            try
            {
                double w = e.PageWidth(page) * scale, h = e.PageHeight(page) * scale;
                double k = Math.Min(1.0, maxDim / Math.Max(w, h));
                int W = Math.Max(1, (int)(w * k)), H = Math.Max(1, (int)(h * k));
                IntPtr bmp = e.BitmapCreate(W, H, 0);
                if (bmp == IntPtr.Zero) return null;
                try
                {
                    e.BitmapFillRect(bmp, 0, 0, W, H, 0xFFFFFFFF);
                    e.RenderPageBitmap(bmp, page, 0, 0, W, H, 0, 0);
                    int stride = e.BitmapGetStride(bmp);
                    IntPtr src = e.BitmapGetBuffer(bmp);
                    var outp = new byte[W * H * 4];
                    for (int y = 0; y < H; y++)
                        Marshal.Copy(src + y * stride, outp, y * W * 4, W * 4);
                    for (int i = 3; i < outp.Length; i += 4) outp[i] = 255; // BGRx -> opaque BGRA
                    return (outp, W, H);
                }
                finally { e.BitmapDestroy(bmp); }
            }
            finally { e.ClosePage(page); }
        }
        finally { e.CloseDocument(doc); pin.Free(); }
    });

    public static void Scan(string path, Agg agg)
    {
        byte[] data = File.ReadAllBytes(path);
        var texts = ExtractText(data);
        if (texts.Sum(t => t.Trim().Length) >= 20)
        {
            foreach (var t in texts) agg.AddAll(t);
            return;
        }
        // Image-only / scanned PDF: OCR every page with the Windows engine if present.
        if (!Ocr.Available) throw new SkipException("pdf_no_text_layer_ocr_needed");
        bool found = false;
        for (int i = 0; i < texts.Count; i++)
        {
            var img = RenderPage(data, i, 2.0, Ocr.MaxDimension);
            if (img == null) continue;
            string text = Ocr.Recognize(img.Value.Bgra, img.Value.Width, img.Value.Height);
            if (text.Trim().Length > 0) { found = true; agg.AddAll(text); }
        }
        if (!found) throw new SkipException("ocr_no_text");
    }
}
