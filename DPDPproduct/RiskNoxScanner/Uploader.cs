// Sends a finished report to the tenant's RiskNox workspace, authenticated by
// the scanner key issued from the Download Agent page. Key is cached locally
// so the user only has to paste it once per machine.
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;

namespace RiskNox;

public static class Uploader
{
    public sealed class UploadResult
    {
        public required bool Success { get; init; }
        public required string Message { get; init; }
    }

    public const string BackendUrl = "https://express-backend-testing.up.railway.app";

    static readonly string ConfigDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RiskNox");
    static readonly string KeyFile = Path.Combine(ConfigDir, "scanner_key.txt");

    public static string? SavedKey
    {
        get => File.Exists(KeyFile) ? File.ReadAllText(KeyFile).Trim() : null;
        set
        {
            Directory.CreateDirectory(ConfigDir);
            if (string.IsNullOrWhiteSpace(value)) { if (File.Exists(KeyFile)) File.Delete(KeyFile); }
            else
            {
                File.WriteAllText(KeyFile, value.Trim());
                // Linux/Unix: the key is a credential, keep it private to the user.
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(KeyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
    }

    public static async Task<UploadResult> UploadAsync(JsonObject report, string apiKey, CancellationToken token = default)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
            using var form = new MultipartFormDataContent();
            var content = new StringContent(report.ToJsonString(), Encoding.UTF8, "application/json");
            content.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data") { Name = "\"report\"", FileName = "\"report.json\"" };
            form.Add(content);
            http.DefaultRequestHeaders.Add("X-Scanner-Key", apiKey);

            using var res = await http.PostAsync($"{BackendUrl}/api/scanner/reports", form, token);
            string body = await res.Content.ReadAsStringAsync(token);
            if (!res.IsSuccessStatusCode)
                return new UploadResult { Success = false, Message = TryGetMessage(body) ?? $"Upload failed ({(int)res.StatusCode})" };

            return new UploadResult { Success = true, Message = "Report uploaded." };
        }
        catch (Exception ex)
        {
            return new UploadResult { Success = false, Message = "Upload failed: " + ex.Message };
        }
    }

    static string? TryGetMessage(string body)
    {
        try { return JsonNode.Parse(body)?["message"]?.ToString(); }
        catch { return null; }
    }
}
