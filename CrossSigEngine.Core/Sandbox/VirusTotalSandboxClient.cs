using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CrossSigEngine.Core.Sandbox;

public sealed class VirusTotalSandboxClient : ISandboxClient
{
    private readonly HttpClient _http;
    private readonly string _apiKey;

    public VirusTotalSandboxClient(string apiKey, HttpClient? http = null)
    {
        _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
        _http = http ?? new HttpClient();
        _http.DefaultRequestHeaders.Add("x-apikey", _apiKey);
        _http.BaseAddress = new Uri("https://www.virustotal.com/api/v3/");
    }

    public async Task<SandboxResult> AnalyzeFileAsync(string filePath, CancellationToken ct = default, int pollIntervalMs = 2000, int timeoutMs = 300000)
    {
        if (!File.Exists(filePath)) throw new FileNotFoundException(filePath);
        using var mp = new MultipartFormDataContent();
        var bytes = await File.ReadAllBytesAsync(filePath, ct);
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");
        mp.Add(fileContent, "file", Path.GetFileName(filePath));
        using var resp = await _http.PostAsync("files", mp, ct);
        var json = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
        {
            return new SandboxResult { Provider = "virustotal", Target = filePath, Status = "error", Summary = json };
        }
        using var doc = JsonDocument.Parse(json);
        var id = doc.RootElement.GetProperty("data").GetProperty("id").GetString();
        var result = await PollAnalysisAsync(id!, ct, pollIntervalMs, timeoutMs);
        return new SandboxResult
        {
            Provider = "virustotal",
            Target = filePath,
            Id = id,
            Status = result.Status,
            Score = result.Score,
            Summary = result.Summary,
            Raw = result.Raw
        };
    }

    public async Task<SandboxResult> AnalyzeUrlAsync(string url, CancellationToken ct = default, int pollIntervalMs = 2000, int timeoutMs = 300000)
    {
        var form = new FormUrlEncodedContent(new[] { new KeyValuePair<string,string>("url", url) });
        using var resp = await _http.PostAsync("urls", form, ct);
        var json = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            return new SandboxResult { Provider = "virustotal", Target = url, Status = "error", Summary = json };
        using var doc = JsonDocument.Parse(json);
        var id = doc.RootElement.GetProperty("data").GetProperty("id").GetString();
        // VT requires id transformation for url analyses: base64 of URL without padding used under analyses/{id}
        var result = await PollAnalysisAsync(id!, ct, pollIntervalMs, timeoutMs, isUrl: true);
        return new SandboxResult
        {
            Provider = "virustotal",
            Target = url,
            Id = id,
            Status = result.Status,
            Score = result.Score,
            Summary = result.Summary,
            Raw = result.Raw
        };
    }

    private async Task<SandboxResult> PollAnalysisAsync(string id, CancellationToken ct, int pollIntervalMs, int timeoutMs, bool isUrl = false)
    {
        var start = DateTimeOffset.UtcNow;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            if ((DateTimeOffset.UtcNow - start).TotalMilliseconds > timeoutMs)
                return new SandboxResult { Provider = "virustotal", Status = "error", Summary = "timeout" };

            var path = isUrl ? $"analyses/{id}" : $"analyses/{id}";
            using var r = await _http.GetAsync(path, ct);
            var t = await r.Content.ReadAsStringAsync(ct);
            if (!r.IsSuccessStatusCode)
                return new SandboxResult { Provider = "virustotal", Status = "error", Summary = t };
            using var doc = JsonDocument.Parse(t);
            var status = doc.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("status").GetString();
            if (string.Equals(status, "completed", StringComparison.OrdinalIgnoreCase))
            {
                // Extract a basic score summary from stats if present
                double? score = null; string? summary = null; object? raw = null;
                try
                {
                    var stats = doc.RootElement.GetProperty("data").GetProperty("attributes").GetProperty("stats");
                    var malicious = stats.TryGetProperty("malicious", out var m) ? m.GetInt32() : 0;
                    var suspicious = stats.TryGetProperty("suspicious", out var s) ? s.GetInt32() : 0;
                    var harmless = stats.TryGetProperty("harmless", out var h) ? h.GetInt32() : 0;
                    var undetected = stats.TryGetProperty("undetected", out var u) ? u.GetInt32() : 0;
                    var total = Math.Max(1, malicious + suspicious + harmless + undetected);
                    score = (malicious + 0.5 * suspicious) / total;
                    summary = $"malicious={malicious}, suspicious={suspicious}, harmless={harmless}, undetected={undetected}";
                }
                catch { }
                try { raw = JsonSerializer.Deserialize<object>(t); } catch { }
                return new SandboxResult { Provider = "virustotal", Status = "completed", Score = score, Summary = summary, Raw = raw };
            }
            await Task.Delay(pollIntervalMs, ct);
        }
    }
}
