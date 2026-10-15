// OCR through the engine built into Windows 10/11 (Windows.Media.Ocr): nothing to install
// or ship, unlike Tesseract. Uses the user's installed OCR languages.
using Windows.Graphics.Imaging;
using Windows.Media.Ocr;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;

namespace RiskNox;

public static class Ocr
{
    /// <summary>Shown in the UI/report; the Linux build reports its own engine here.</summary>
    public const string EngineName = "Windows built-in";
    public const string MissingNote = "NOTE: Windows OCR engine not available; image files and scanned PDFs were skipped.";

    static readonly Lazy<bool> _available = new(() =>
    {
        try { return OcrEngine.TryCreateFromUserProfileLanguages() != null; }
        catch { return false; }
    });

    public static bool Available => _available.Value;

    public static int MaxDimension
    {
        get { try { return (int)OcrEngine.MaxImageDimension; } catch { return 4000; } }
    }

    static string Run(SoftwareBitmap bmp)
    {
        var engine = OcrEngine.TryCreateFromUserProfileLanguages() ?? throw new SkipException("ocr_engine_missing");
        var result = engine.RecognizeAsync(bmp).AsTask().GetAwaiter().GetResult();
        // One line per OCR line so line-oriented context ("Aadhaar: ...") survives.
        return string.Join("\n", result.Lines.Select(l => l.Text));
    }

    public static string Recognize(byte[] bgra, int width, int height)
    {
        using var bmp = SoftwareBitmap.CreateCopyFromBuffer(
            CryptographicBuffer.CreateFromByteArray(bgra), BitmapPixelFormat.Bgra8, width, height, BitmapAlphaMode.Premultiplied);
        return Run(bmp);
    }

    public static void ScanImage(string path, Agg agg)
    {
        if (!Available) throw new SkipException("ocr_engine_missing");
        string text;
        try
        {
            byte[] data = File.ReadAllBytes(path);
            using var stream = new InMemoryRandomAccessStream();
            stream.WriteAsync(CryptographicBuffer.CreateFromByteArray(data)).AsTask().GetAwaiter().GetResult();
            stream.Seek(0);
            var decoder = BitmapDecoder.CreateAsync(stream).AsTask().GetAwaiter().GetResult();
            uint w = decoder.PixelWidth, h = decoder.PixelHeight, max = (uint)MaxDimension;
            var transform = new BitmapTransform();
            if (w > max || h > max)
            {
                double k = (double)max / Math.Max(w, h);
                transform.ScaledWidth = Math.Max(1, (uint)(w * k));
                transform.ScaledHeight = Math.Max(1, (uint)(h * k));
            }
            using var bmp = decoder.GetSoftwareBitmapAsync(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied, transform,
                ExifOrientationMode.RespectExifOrientation, ColorManagementMode.DoNotColorManage).AsTask().GetAwaiter().GetResult();
            text = Run(bmp);
        }
        catch (SkipException) { throw; }
        catch (Exception e) { throw new SkipException("image_unreadable:" + e.GetType().Name); }
        if (text.Trim().Length == 0) throw new SkipException("ocr_no_text");
        agg.AddAll(text);
    }
}
