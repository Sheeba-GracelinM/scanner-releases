// Port of pii_scan.py detectors/validators/scoring. Behaviour must stay identical to the
// Python reference: evaluate parity with tools/parity.py before changing anything here.
using System.Text;
using System.Text.RegularExpressions;

namespace RiskNox;

public readonly record struct Hit(string Type, string Conf, string Value, int Start, int End);

public static partial class Detectors
{
    // ------------------------------------------------------------------ validators
    static readonly int[,] VD = {
        {0,1,2,3,4,5,6,7,8,9},{1,2,3,4,0,6,7,8,9,5},{2,3,4,0,1,7,8,9,5,6},{3,4,0,1,2,8,9,5,6,7},
        {4,0,1,2,3,9,5,6,7,8},{5,9,8,7,6,0,4,3,2,1},{6,5,9,8,7,1,0,4,3,2},{7,6,5,9,8,2,1,0,4,3},
        {8,7,6,5,9,3,2,1,0,4},{9,8,7,6,5,4,3,2,1,0}};
    static readonly int[,] VP = {
        {0,1,2,3,4,5,6,7,8,9},{1,5,7,6,2,8,3,0,9,4},{5,8,0,3,7,9,6,1,4,2},{8,9,1,6,0,4,3,5,2,7},
        {9,4,5,3,1,2,6,8,7,0},{4,2,8,6,5,7,3,9,0,1},{2,7,9,3,8,0,6,4,1,5},{7,0,4,6,9,1,3,2,5,8}};

    static int Dig(char c) => c is >= '0' and <= '9' ? c - '0' : (int)char.GetNumericValue(c);

    public static bool VerhoeffOk(string num)
    {
        int c = 0;
        for (int i = 0; i < num.Length; i++)
            c = VD[c, VP[i % 8, Dig(num[num.Length - 1 - i])]];
        return c == 0;
    }

    public static bool LuhnOk(string num)
    {
        int total = 0; bool alt = false;
        for (int i = num.Length - 1; i >= 0; i--)
        {
            int d = Dig(num[i]);
            if (alt) { d *= 2; if (d > 9) d -= 9; }
            total += d; alt = !alt;
        }
        return total % 10 == 0;
    }

    static bool CardPrefixOk(string d) =>
        "3456".Contains(d[0]) || d.StartsWith("81") || d.StartsWith("82") || d.StartsWith("508");

    // ------------------------------------------------------------------ patterns
    // Compiled at build time by the regex source generator (no startup JIT of regexes).
    [GeneratedRegex(@"(?<!\d)(?<!\d[ -])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![ -]?\d)")] private static partial Regex ReAadhaar();
    [GeneratedRegex(@"(?<![A-Za-z0-9])[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z](?![A-Za-z0-9])")] private static partial Regex RePan();
    [GeneratedRegex(@"(?<![A-Za-z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Za-z0-9])")] private static partial Regex ReIfsc();
    [GeneratedRegex(@"(?<![\d-])(?:\d[ -]?){12,18}\d(?!\d)")] private static partial Regex ReCard();
    [GeneratedRegex(@"(?<![\d+\-])(?:(?:\+91|0091|91|0)[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")] private static partial Regex RePhone();
    [GeneratedRegex(@"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])")] private static partial Regex ReEmail();
    [GeneratedRegex(@"(?<![\w.+-])[A-Za-z0-9._-]{2,}@(?:ok(?:axis|sbi|hdfcbank|icici)|ybl|ibl|axl|paytm|upi|apl|sbi|hdfcbank|icici|axisbank|fbl|ikwik|airtel|jio|freecharge|barodampay|postbank)(?![\w.-])")] private static partial Regex ReUpi();
    [GeneratedRegex(@"(?i)\b(?:a/?c|acc(?:ount)?|bank\s*acc(?:ount)?)\.?\s*(?:no\.?|number|num|#)?\s*[:\-#]?\s*(\d{9,18})(?!\d)")] private static partial Regex ReBank();
    [GeneratedRegex(@"(?i)passport(?:\s*(?:no\.?|number|#))?\s*[:\-#]?\s*([A-PR-WY][1-9]\d{6})(?!\w)")] private static partial Regex RePassport();
    [GeneratedRegex(@"(?i)(?:epic|voter\s*id|voter)(?:\s*(?:no\.?|number|#|card))?\s*[:\-#]?\s*([A-Z]{3}\d{7})(?!\w)")] private static partial Regex ReVoter();
    [GeneratedRegex(@"(?i)(?:\bdob\b|d\.o\.b\.?|date\s+of\s+birth|birth\s*date)\s*[:\-]?\s*(\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})")] private static partial Regex ReDob();

    [GeneratedRegex(@"(?i)aadh?a+r|uidai|\buid\b")] private static partial Regex CtxAadhaar();
    [GeneratedRegex(@"(?i)\bpan\b|permanent\s+account|income\s*tax")] private static partial Regex CtxPan();
    [GeneratedRegex(@"(?i)mobile|phone|\bph\b|contact|\bmob\b|\bcell\b|\btel\b|whatsapp|\bcall\b")] private static partial Regex CtxPhone();
    [GeneratedRegex(@"(?i)e-?mail|\bmail\b")] private static partial Regex CtxEmail();
    [GeneratedRegex(@"(?i)ifsc")] private static partial Regex CtxIfsc();
    [GeneratedRegex(@"(?i)card|credit|debit|visa|master\s*card|rupay|\bcvv\b|\bpayment\b")] private static partial Regex CtxCard();
    [GeneratedRegex(@"(?i)@(gmail|yahoo|outlook|hotmail|rediffmail|icloud|proton|live)\.")] private static partial Regex FreeMail();
    [GeneratedRegex(@"\D")] private static partial Regex NonDigit();

    static string Digits(string s) => NonDigit().Replace(s, "");

    static bool HasCtx(string text, int s, int e, Regex ctx)
    {
        int a = Math.Max(0, s - 40);
        string window = text.Substring(a, s - a) + " " + text.Substring(e, Math.Min(15, text.Length - e));
        return ctx.IsMatch(window);
    }

    /// <summary>Claimed spans kept sorted by start; overlap test is a bisect over a short window.</summary>
    sealed class Claims
    {
        readonly List<int> _starts = new(), _ends = new();
        int _longest;

        public bool Overlaps(int s, int e)
        {
            int i = Lower(s - _longest), j = Lower(e);
            for (int k = i; k < j; k++)
                if (s < _ends[k]) return true;
            return false;
        }

        public void Add(int s, int e)
        {
            int k = Lower(s);
            _starts.Insert(k, s); _ends.Insert(k, e);
            if (e - s > _longest) _longest = e - s;
        }

        int Lower(int v)
        {
            int lo = 0, hi = _starts.Count;
            while (lo < hi) { int m = (lo + hi) >> 1; if (_starts[m] < v) lo = m + 1; else hi = m; }
            return lo;
        }
    }

    /// <summary>Return hits as (type, confidence, value, start, end), same order as pii_scan.scan_text.</summary>
    public static List<Hit> ScanText(string text)
    {
        var outp = new List<Hit>();
        if (string.IsNullOrEmpty(text)) return outp;
        var claimed = new Claims();
        void Add(string t, string c, string v, int s, int e) { outp.Add(new Hit(t, c, v, s, e)); claimed.Add(s, e); }

        // 1. context-required identifiers
        foreach (Match m in ReBank().Matches(text))
        {
            var g = m.Groups[1]; int s = g.Index, e = s + g.Length;
            int a = Math.Max(0, s - 80);
            string near = text.Substring(a, Math.Min(text.Length, e + 80) - a);
            string conf = ReIfsc().IsMatch(near) || CtxIfsc().IsMatch(near) ? "high" : "medium";
            Add("bank_account", conf, g.Value, s, e);
        }
        foreach (Match m in RePassport().Matches(text)) { var g = m.Groups[1]; Add("passport", "medium", g.Value, g.Index, g.Index + g.Length); }
        foreach (Match m in ReVoter().Matches(text)) { var g = m.Groups[1]; Add("voter_id", "medium", g.Value, g.Index, g.Index + g.Length); }
        foreach (Match m in ReDob().Matches(text)) { var g = m.Groups[1]; Add("dob", "medium", g.Value, g.Index, g.Index + g.Length); }

        // 2. cards
        foreach (Match m in ReCard().Matches(text))
        {
            int s = m.Index, e = s + m.Length;
            string d = Digits(m.Value);
            if (d.Length >= 13 && d.Length <= 19 && CardPrefixOk(d) && LuhnOk(d) && !claimed.Overlaps(s, e))
                Add("card", HasCtx(text, s, e, CtxCard()) ? "high" : "medium", d, s, e);
        }

        // 3. UPI, email
        foreach (Match m in ReUpi().Matches(text))
        {
            int s = m.Index, e = s + m.Length;
            if (!claimed.Overlaps(s, e)) Add("upi", "medium", m.Value, s, e);
        }
        foreach (Match m in ReEmail().Matches(text))
        {
            int s = m.Index, e = s + m.Length;
            if (claimed.Overlaps(s, e)) continue;
            string conf = HasCtx(text, s, e, CtxEmail()) ? "high" : FreeMail().IsMatch(m.Value) ? "medium" : "low";
            Add("email", conf, m.Value, s, e);
        }

        // 4. Aadhaar (Verhoeff + context for "high")
        foreach (Match m in ReAadhaar().Matches(text))
        {
            int s = m.Index, e = s + m.Length;
            string d = Digits(m.Value);
            if (claimed.Overlaps(s, e) || d.Distinct().Count() < 3 || !VerhoeffOk(d)) continue;
            Add("aadhaar", HasCtx(text, s, e, CtxAadhaar()) ? "high" : "medium", d, s, e);
        }

        // 5. PAN, IFSC
        foreach (Match m in RePan().Matches(text))
        {
            int s = m.Index, e = s + m.Length;
            if (!claimed.Overlaps(s, e)) Add("pan", HasCtx(text, s, e, CtxPan()) ? "high" : "medium", m.Value, s, e);
        }
        foreach (Match m in ReIfsc().Matches(text))
        {
            int s = m.Index, e = s + m.Length;
            if (!claimed.Overlaps(s, e)) Add("ifsc", HasCtx(text, s, e, CtxIfsc()) ? "high" : "medium", m.Value, s, e);
        }

        // 6. phone (weakest pattern)
        foreach (Match m in RePhone().Matches(text))
        {
            int s = m.Index, e = s + m.Length;
            if (claimed.Overlaps(s, e)) continue;
            string raw = m.Value, d = Digits(raw);
            bool ctx = HasCtx(text, s, e, CtxPhone());
            if (d.Length == 12 && d.StartsWith("91") && !raw.Contains('+') && !ctx) continue;
            string conf = ctx ? "high" : raw.StartsWith("+91") || raw.StartsWith("0091") ? "medium" : "low";
            Add("phone", conf, d[^10..], s, e);
        }
        return outp;
    }

    // ------------------------------------------------------------------ scoring
    static readonly Dictionary<string, double> ConfW = new() { ["high"] = 1.0, ["medium"] = 0.5, ["low"] = 0.1 };
    static readonly Dictionary<string, int> TypeW = new()
    {
        ["aadhaar"] = 10, ["card"] = 10, ["pan"] = 8, ["passport"] = 8, ["bank_account"] = 8,
        ["voter_id"] = 6, ["upi"] = 4, ["dob"] = 3, ["ifsc"] = 2, ["phone"] = 2, ["email"] = 1,
    };

    public static string Mask(string v)
    {
        int at = v.IndexOf('@');
        if (at >= 0) return (at > 0 ? v[..1] : "") + "***@" + v[(at + 1)..];
        return new string('X', Math.Max(0, v.Length - 4)) + (v.Length >= 4 ? v[^4..] : v);
    }

    public static double ScoreTypes(Dictionary<string, TypeCount> types)
    {
        double total = 0; int distinct = 0;
        foreach (var (t, c) in types)
        {
            double w = c.High * ConfW["high"] + c.Medium * ConfW["medium"] + c.Low * ConfW["low"];
            total += TypeW.GetValueOrDefault(t, 1) * Math.Min(w, 10);
            if (c.High > 0 || c.Medium > 0) distinct++;
        }
        if (distinct >= 5) total *= 2.0; else if (distinct >= 3) total *= 1.5;
        return Math.Round(total, 1, MidpointRounding.ToEven);
    }

    public static string Tier(double score) =>
        score >= 100 ? "critical" : score >= 40 ? "high" : score >= 10 ? "medium" : score > 0 ? "low" : "none";
}

public sealed class TypeCount
{
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public int Count => High + Medium + Low;
    public int Unique { get; set; }

    public void Bump(string conf)
    {
        if (conf == "high") High++; else if (conf == "medium") Medium++; else Low++;
    }
}

/// <summary>Per-file aggregation (counts, unique values, optional masked samples).</summary>
public sealed class Agg(bool wantSamples)
{
    readonly Dictionary<string, TypeCount> _counts = new();
    readonly Dictionary<string, HashSet<string>> _uniq = new();
    public Dictionary<string, List<string>> Samples { get; } = new();

    public void Add(in Hit h)
    {
        if (!_counts.TryGetValue(h.Type, out var c)) _counts[h.Type] = c = new TypeCount();
        c.Bump(h.Conf);
        if (!_uniq.TryGetValue(h.Type, out var u)) _uniq[h.Type] = u = new HashSet<string>();
        u.Add(h.Value);
        if (wantSamples)
        {
            if (!Samples.TryGetValue(h.Type, out var l)) Samples[h.Type] = l = new List<string>();
            if (l.Count < 3) l.Add(Detectors.Mask(h.Value));
        }
    }

    public void AddAll(string text)
    {
        foreach (var h in Detectors.ScanText(text)) Add(h);
    }

    public Dictionary<string, TypeCount> Result()
    {
        foreach (var (t, c) in _counts) c.Unique = _uniq[t].Count;
        return _counts;
    }
}
