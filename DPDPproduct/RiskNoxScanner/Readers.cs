// File readers: port of pii_scan.py scan_plain/scan_csv/scan_xlsx/scan_zipxml, plus PDF via
// PDFium and OCR via the Windows built-in engine (replaces pypdf/pdftotext/Tesseract).
using System.Globalization;
using System.IO.Compression;
using System.Numerics;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace RiskNox;

public sealed class SkipException(string reason) : Exception(reason)
{
    public string Reason { get; } = reason;
}

public static partial class Readers
{
    public static readonly HashSet<string> TextExt = [".txt", ".log", ".json", ".xml", ".md", ".html", ".htm", ".sql", ".yaml", ".yml", ".ini", ".conf", ".cfg", ".eml"];
    public static readonly HashSet<string> ImageExt = [".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp", ".gif"];
    public static readonly Dictionary<string, char> CsvExt = new() { [".csv"] = ',', [".tsv"] = '\t' };
    public static readonly HashSet<string> XlsxExt = [".xlsx", ".xlsm"];
    public static readonly Dictionary<string, Regex> ZipXmlExt = new()
    {
        [".docx"] = new Regex(@"^word/(document|header\d*|footer\d*)\.xml$", RegexOptions.Compiled),
        [".pptx"] = new Regex(@"^ppt/slides/slide\d+\.xml$", RegexOptions.Compiled),
    };
    public static readonly HashSet<string> LegacyExt = [".xls", ".doc", ".ppt"];
    public static readonly HashSet<string> Supported = [.. TextExt, .. CsvExt.Keys, .. XlsxExt, .. ZipXmlExt.Keys, ".pdf", .. ImageExt];
    const long MaxUncompressed = 200L * 1024 * 1024;

    public static void ScanFile(string path, string ext, Agg agg)
    {
        if (TextExt.Contains(ext)) ScanPlain(path, agg);
        else if (CsvExt.TryGetValue(ext, out var delim)) ScanCsv(path, delim, agg);
        else if (XlsxExt.Contains(ext) || ZipXmlExt.ContainsKey(ext))
        {
            var head = new byte[4];
            using (var fs = File.OpenRead(path)) fs.ReadAtLeast(head, 4, throwOnEndOfStream: false);
            if (head[0] == 0xD0 && head[1] == 0xCF && head[2] == 0x11 && head[3] == 0xE0) throw new SkipException("encrypted_office");
            ZipArchive z;
            try { z = ZipFile.OpenRead(path); }
            catch (InvalidDataException) { throw new SkipException("corrupt_or_unreadable"); }
            using (z)
            {
                if (z.Entries.Sum(e => e.Length) > MaxUncompressed) throw new SkipException("too_large_uncompressed");
                if (XlsxExt.Contains(ext)) ScanXlsx(z, agg); else ScanZipXml(z, ZipXmlExt[ext], agg);
            }
        }
        else if (ext == ".pdf") Pdf.Scan(path, agg);
        else if (ImageExt.Contains(ext)) Ocr.ScanImage(path, agg);
        else if (LegacyExt.Contains(ext)) throw new SkipException("legacy_office_not_supported");
        else throw new SkipException("unsupported_type");
    }

    /// <summary>utf-16 if BOM says so, else utf-8 (BOM stripped), invalid bytes replaced.</summary>
    static StreamReader OpenText(string path)
    {
        var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
        return new StreamReader(fs, new UTF8Encoding(false, false), detectEncodingFromByteOrderMarks: true, 1 << 16);
    }

    static void ScanPlain(string path, Agg agg)
    {
        const int CH = 1 << 20, OV = 128;
        var buf = new char[CH];
        string tail = "";
        using var rd = OpenText(path);
        while (true)
        {
            int n = rd.ReadBlock(buf, 0, CH);
            if (n == 0) break;
            string text = tail + new string(buf, 0, n);
            foreach (var h in Detectors.ScanText(text))
                if (h.End > tail.Length) agg.Add(h);
            tail = text.Length > OV ? text[^OV..] : text;
        }
    }

    // --------------------------------------------------------------- CSV
    /// <summary>Streaming reader with the semantics of Python's csv.reader (excel dialect, newline='').</summary>
    static IEnumerable<List<string>> CsvRows(TextReader rd, char delim)
    {
        var row = new List<string>();
        var field = new StringBuilder();
        int state = 0; // 0 start-of-field, 1 in unquoted, 2 in quoted, 3 quote-in-quoted, 4 start-of-record
        bool any = false;
        state = 4;
        int ch;
        while ((ch = rd.Read()) != -1)
        {
            char c = (char)ch;
            switch (state)
            {
                case 4:
                case 0:
                    if (c == '\r' || c == '\n')
                    {
                        if (state == 0) { row.Add(field.ToString()); field.Clear(); }
                        if (c == '\r' && rd.Peek() == '\n') rd.Read();
                        yield return row; row = new List<string>(); any = false; state = 4; continue;
                    }
                    any = true;
                    if (c == '"') state = 2;
                    else if (c == delim) { row.Add(field.ToString()); field.Clear(); state = 0; }
                    else { field.Append(c); state = 1; }
                    break;
                case 1:
                    if (c == delim) { row.Add(field.ToString()); field.Clear(); state = 0; }
                    else if (c == '\r' || c == '\n')
                    {
                        row.Add(field.ToString()); field.Clear();
                        if (c == '\r' && rd.Peek() == '\n') rd.Read();
                        yield return row; row = new List<string>(); any = false; state = 4;
                    }
                    else field.Append(c);
                    break;
                case 2:
                    if (c == '"') state = 3; else field.Append(c);
                    break;
                case 3:
                    if (c == '"') { field.Append('"'); state = 2; }
                    else if (c == delim) { row.Add(field.ToString()); field.Clear(); state = 0; }
                    else if (c == '\r' || c == '\n')
                    {
                        row.Add(field.ToString()); field.Clear();
                        if (c == '\r' && rd.Peek() == '\n') rd.Read();
                        yield return row; row = new List<string>(); any = false; state = 4;
                    }
                    else { field.Append(c); state = 1; }
                    break;
            }
        }
        if (state != 4 || any)
        {
            row.Add(field.ToString());
            yield return row;
        }
    }

    [GeneratedRegex(@"^[\s+()-]*\d[\d\s+()-]*$")] private static partial Regex NumericCell();
    [GeneratedRegex(@"(?i)credit\s*card|debit\s*card|card\s*(?:number|no\.?|#)|card_number|\bcvv\b|\bpan\b|expiry|expiration|visa|mastercard|master\s*card|rupay|amex")] private static partial Regex StrongFinancial();

    static bool ColumnIsGeneratedId(List<string>? values)
    {
        if (values == null) return false;
        var vals = values.Select(v => v.Trim()).Where(v => v.Length > 0).ToList();
        if (vals.Count < 4) return false;
        var sample = vals.Take(1000).ToList();
        var numeric = sample.Where(v => NumericCell().IsMatch(v)).Select(v => new string(v.Where(char.IsDigit).ToArray())).ToList();
        double uniqueRatio = Math.Round(sample.Distinct().Count() / (double)sample.Count, 3);
        double numericRatio = Math.Round(numeric.Count / (double)sample.Count, 3);
        bool consistentLen = sample.Select(v => v.Length).Distinct().Count() <= 2;
        bool sequential = false;
        if (numeric.Count >= 4 && numeric.Count == sample.Count)
        {
            var nums = numeric.Select(x => BigInteger.Parse(x.Select(ch => (char)('0' + (int)char.GetNumericValue(ch))).ToArray())).ToList();
            sequential = true;
            for (int i = 0; i + 1 < nums.Count; i++)
            {
                var d = nums[i + 1] - nums[i];
                if (d <= 0 || d > 1000) { sequential = false; break; }
            }
        }
        return numericRatio >= 0.95 && uniqueRatio >= 0.90 && consistentLen && sequential;
    }

    static void ScanCsv(string path, char delim, Agg agg)
    {
        // Pass 1: learn column behaviour from a bounded sample (first 1001 rows).
        var samples = new Dictionary<int, List<string>>();
        using (var rd = OpenText(path))
        {
            int rowNo = 0;
            foreach (var row in CsvRows(rd, delim))
            {
                for (int i = 0; i < row.Count; i++)
                {
                    if (row[i].Trim().Length == 0) continue;
                    if (!samples.TryGetValue(i, out var l)) samples[i] = l = new List<string>();
                    if (l.Count < 1000) l.Add(row[i]);
                }
                if (rowNo++ >= 1000) break;
            }
        }
        var generated = samples.ToDictionary(kv => kv.Key, kv => ColumnIsGeneratedId(kv.Value));

        List<string>? header = null;
        using var rd2 = OpenText(path);
        foreach (var row in CsvRows(rd2, delim))
        {
            if (header == null) { header = row; continue; }
            for (int i = 0; i < row.Count; i++)
            {
                string cell = row[i];
                if (cell.Trim().Length == 0) continue;
                string h = i < header.Count ? header[i].Trim() : "";
                string context = h.Length > 0 ? h + ": " + cell : cell;
                foreach (var f in Detectors.ScanText(context))
                {
                    if (f.Type == "card" && generated.GetValueOrDefault(i) && !StrongFinancial().IsMatch(context))
                        continue;
                    agg.Add(f);
                }
            }
        }
    }

    // --------------------------------------------------------------- XLSX / DOCX / PPTX
    static readonly XmlReaderSettings XmlSettings = new() { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, IgnoreWhitespace = false, IgnoreComments = true };

    static int ColIndex(string? cellRef)
    {
        int n = 0;
        foreach (char ch in string.IsNullOrEmpty(cellRef) ? "A" : cellRef)
        {
            if (ch < 'A' || ch > 'Z') break;
            n = n * 26 + ch - 64;
        }
        return n;
    }

    [GeneratedRegex(@"^\d+\.0+$")] private static partial Regex IntFloat();
    [GeneratedRegex(@"^([+-]?)(\d+)(?:\.(\d+))?[eE]([+-]?\d+)$")] private static partial Regex SciNum();

    /// <summary>Same as pii_scan._norm_num: "123.0" -> "123", "1.23E+11" -> "123000000000".</summary>
    public static string NormNum(string v)
    {
        v = v.Trim();
        if (IntFloat().IsMatch(v)) return v.Split('.')[0];
        var m = SciNum().Match(v);
        if (!m.Success) return v;
        string sign = m.Groups[1].Value == "-" ? "-" : "";
        string intPart = m.Groups[2].Value, frac = m.Groups[3].Value;
        if (!int.TryParse(m.Groups[4].Value, out int exp)) return v;
        string digits = intPart + frac;
        int point = intPart.Length + exp; // position of decimal point within digits
        string s;
        if (point >= digits.Length) s = digits + new string('0', point - digits.Length);
        else if (point <= 0) s = "0." + new string('0', -point) + digits;
        else s = digits[..point] + "." + digits[point..];
        // Decimal drops redundant leading zeros of the integer part
        int dot = s.IndexOf('.');
        string ip = (dot < 0 ? s : s[..dot]).TrimStart('0');
        if (ip.Length == 0) ip = "0";
        s = dot < 0 ? ip : ip + s[dot..];
        if (s.Contains('.')) s = s.TrimEnd('0').TrimEnd('.');
        return sign + s;
    }

    /// <summary>Concatenated text of all descendant elements named "t" (current reader positioned on start element).</summary>
    static string DescendantT(XmlReader r)
    {
        if (r.IsEmptyElement) return "";
        var sb = new StringBuilder();
        int depth = r.Depth;
        int tDepth = -1;
        while (r.Read())
        {
            if (r.NodeType == XmlNodeType.EndElement && r.Depth == depth) break;
            if (r.NodeType == XmlNodeType.Element)
            {
                if (r.LocalName == "t" && !r.IsEmptyElement && tDepth < 0) tDepth = r.Depth;
            }
            else if (r.NodeType == XmlNodeType.EndElement && r.Depth == tDepth) tDepth = -1;
            else if (tDepth >= 0 && r.Depth == tDepth + 1 &&
                     r.NodeType is XmlNodeType.Text or XmlNodeType.Whitespace or XmlNodeType.SignificantWhitespace or XmlNodeType.CDATA)
                sb.Append(r.Value);
        }
        return sb.ToString();
    }

    static void ScanXlsx(ZipArchive z, Agg agg)
    {
        var shared = new List<string>();
        var sst = z.GetEntry("xl/sharedStrings.xml");
        if (sst != null)
        {
            using var r = XmlReader.Create(sst.Open(), XmlSettings);
            while (r.Read())
                if (r.NodeType == XmlNodeType.Element && r.LocalName == "si")
                    shared.Add(DescendantT(r));
        }
        var sheetRx = new Regex(@"^xl/worksheets/[^/]+\.xml$");
        foreach (var entry in z.Entries.Where(e => sheetRx.IsMatch(e.FullName)).OrderBy(e => e.FullName, StringComparer.Ordinal))
        {
            Dictionary<int, string>? header = null;
            using var r = XmlReader.Create(entry.Open(), XmlSettings);
            while (r.Read())
            {
                if (r.NodeType != XmlNodeType.Element || r.LocalName != "row" || r.IsEmptyElement)
                {
                    if (r.NodeType == XmlNodeType.Element && r.LocalName == "row" && header == null) header = new();
                    continue;
                }
                var vals = new Dictionary<int, string>();
                int rowDepth = r.Depth;
                while (r.Read() && !(r.NodeType == XmlNodeType.EndElement && r.Depth == rowDepth))
                {
                    if (r.NodeType != XmlNodeType.Element || r.LocalName != "c" || r.Depth != rowDepth + 1) continue;
                    string? t = r.GetAttribute("t"), cref = r.GetAttribute("r");
                    string? v = null;
                    if (!r.IsEmptyElement)
                    {
                        int cDepth = r.Depth;
                        while (r.Read() && !(r.NodeType == XmlNodeType.EndElement && r.Depth == cDepth))
                        {
                            if (r.NodeType != XmlNodeType.Element || r.Depth != cDepth + 1) continue;
                            if (r.LocalName == "v")
                            {
                                string? txt = r.IsEmptyElement ? null : r.ReadElementContentAsString();
                                if (txt != null)
                                {
                                    if (t == "s")
                                        v = int.TryParse(txt, out int ix) && ix >= 0 && ix < shared.Count ? shared[ix] : null;
                                    else
                                        v = t is "str" or "inlineStr" or "b" or "e" ? txt : NormNum(txt);
                                }
                                if (r.NodeType == XmlNodeType.EndElement && r.Depth == cDepth) break;
                            }
                            else if (r.LocalName == "is") v = DescendantT(r);
                        }
                    }
                    if (!string.IsNullOrEmpty(v)) vals[ColIndex(cref)] = v;
                }
                if (header == null) header = new Dictionary<int, string>(vals);
                foreach (var (ci, val) in vals)
                {
                    string h = header.GetValueOrDefault(ci, "");
                    agg.AddAll(h.Length > 0 && h != val ? h + ": " + val : val);
                }
            }
        }
    }

    static void ScanZipXml(ZipArchive z, Regex member, Agg agg)
    {
        foreach (var entry in z.Entries)
        {
            if (!member.IsMatch(entry.FullName)) continue;
            using var r = XmlReader.Create(entry.Open(), XmlSettings);
            // Every open <p> collects all descendant <t> text (nested paragraphs counted in
            // both, exactly like ElementTree iter() in the Python reference).
            var open = new List<(int Depth, StringBuilder Sb)>();
            int tDepth = -1;
            while (r.Read())
            {
                switch (r.NodeType)
                {
                    case XmlNodeType.Element:
                        if (r.LocalName == "p")
                        {
                            if (r.IsEmptyElement) break;
                            open.Add((r.Depth, new StringBuilder()));
                        }
                        else if (r.LocalName == "t" && !r.IsEmptyElement && tDepth < 0) tDepth = r.Depth;
                        break;
                    case XmlNodeType.EndElement:
                        if (r.Depth == tDepth) tDepth = -1;
                        if (r.LocalName == "p" && open.Count > 0 && open[^1].Depth == r.Depth)
                        {
                            string txt = open[^1].Sb.ToString();
                            open.RemoveAt(open.Count - 1);
                            if (txt.Trim().Length > 0) agg.AddAll(txt);
                        }
                        break;
                    case XmlNodeType.Text or XmlNodeType.Whitespace or XmlNodeType.SignificantWhitespace or XmlNodeType.CDATA:
                        if (tDepth >= 0 && r.Depth == tDepth + 1)
                            foreach (var o in open) o.Sb.Append(r.Value);
                        break;
                }
            }
        }
    }
}
