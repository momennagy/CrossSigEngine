using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CrossSigEngine.Core.Sandbox;

public sealed class CuckooSandboxClient : ISandboxClient
{
    private readonly HttpClient _http;
    private readonly string _baseUrl;

    public CuckooSandboxClient(string baseUrl, string? apiKey = null, HttpClient? http = null)
    {
        if (string.IsNullOrWhiteSpace(baseUrl)) throw new ArgumentNullException(nameof(baseUrl));
        _baseUrl = baseUrl.TrimEnd('/') + "/";
        _http = http ?? new HttpClient();
        _http.BaseAddress = new Uri(_baseUrl);
        if (!string.IsNullOrWhiteSpace(apiKey))
        {
            // Best-effort common header; users can run behind a proxy that expects Bearer
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        }
    }

    public async Task<SandboxResult> AnalyzeFileAsync(string filePath, CancellationToken ct = default, int pollIntervalMs = 2000, int timeoutMs = 300000)
    {
        if (!File.Exists(filePath)) throw new FileNotFoundException(filePath);
        using var mp = new MultipartFormDataContent();
        var bytes = await File.ReadAllBytesAsync(filePath, ct);
        var fileContent = new ByteArrayContent(bytes);
        fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");
        mp.Add(fileContent, "file", Path.GetFileName(filePath));
        using var resp = await _http.PostAsync("tasks/create/file", mp, ct);
        var json = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            return new SandboxResult { Provider = "cuckoo", Target = filePath, Status = "error", Summary = json };
        using var doc = JsonDocument.Parse(json);
        var taskId = ExtractTaskId(doc);
        var polled = await PollAsync(taskId, ct, pollIntervalMs, timeoutMs);
        return new SandboxResult
        {
            Provider = "cuckoo",
            Target = filePath,
            Id = taskId,
            Status = polled.status,
            Score = polled.score,
            Summary = polled.summary,
            Raw = polled.raw
        };
    }

    public async Task<SandboxResult> AnalyzeUrlAsync(string url, CancellationToken ct = default, int pollIntervalMs = 2000, int timeoutMs = 300000)
    {
        var content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("url", url) });
        using var resp = await _http.PostAsync("tasks/create/url", content, ct);
        var json = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            return new SandboxResult { Provider = "cuckoo", Target = url, Status = "error", Summary = json };
        using var doc = JsonDocument.Parse(json);
        var taskId = ExtractTaskId(doc);
        var polled = await PollAsync(taskId, ct, pollIntervalMs, timeoutMs);
        return new SandboxResult
        {
            Provider = "cuckoo",
            Target = url,
            Id = taskId,
            Status = polled.status,
            Score = polled.score,
            Summary = polled.summary,
            Raw = polled.raw
        };
    }

    private static string ExtractTaskId(JsonDocument doc)
    {
        // Typical Cuckoo response: { "task_id": 123 } or { "task_ids": [123] }
        if (doc.RootElement.TryGetProperty("task_id", out var idEl) && idEl.ValueKind == JsonValueKind.Number)
            return idEl.GetInt32().ToString();
        if (doc.RootElement.TryGetProperty("task_ids", out var idsEl) && idsEl.ValueKind == JsonValueKind.Array && idsEl.GetArrayLength() > 0)
        {
            var first = idsEl[0];
            if (first.ValueKind == JsonValueKind.Number) return first.GetInt32().ToString();
            if (first.ValueKind == JsonValueKind.String) return first.GetString()!;
        }
        // Some wrappers return { "data": { "task_id": 123 } }
        if (doc.RootElement.TryGetProperty("data", out var data) && data.TryGetProperty("task_id", out var id2))
        {
            if (id2.ValueKind == JsonValueKind.Number) return id2.GetInt32().ToString();
            if (id2.ValueKind == JsonValueKind.String) return id2.GetString()!;
        }
        throw new InvalidOperationException("Unable to extract Cuckoo task_id from response");
    }

    private async Task<(string status, double? score, string? summary, object? raw)> PollAsync(string taskId, CancellationToken ct, int pollIntervalMs, int timeoutMs)
    {
        var start = DateTimeOffset.UtcNow;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            if ((DateTimeOffset.UtcNow - start).TotalMilliseconds > timeoutMs)
                return ("error", null, "timeout", null);

            using var r = await _http.GetAsync($"tasks/view/{taskId}", ct);
            var t = await r.Content.ReadAsStringAsync(ct);
            if (!r.IsSuccessStatusCode)
                return ("error", null, t, null);
            try
            {
                using var doc = JsonDocument.Parse(t);
                var status = ExtractStatus(doc);
                if (string.Equals(status, "reported", StringComparison.OrdinalIgnoreCase) || string.Equals(status, "completed", StringComparison.OrdinalIgnoreCase))
                {
                    // fetch report JSON
                    using var rr = await _http.GetAsync($"tasks/report/{taskId}", ct);
                    var rt = await rr.Content.ReadAsStringAsync(ct);
                    object? rawObj = null; double? score = null; string? summary = null;
                    try { rawObj = JsonSerializer.Deserialize<object>(rt); } catch { rawObj = rt; }
                    try { score = ExtractScore(rt); } catch { }
                    try { summary = ExtractSummary(rt); } catch { }
                    return ("completed", score, summary, rawObj);
                }
            }
            catch
            {
                // ignore parse errors and continue polling
            }
            await Task.Delay(pollIntervalMs, ct);
        }
    }

    private static string ExtractStatus(JsonDocument doc)
    {
        // Typical: { "task": { "status": "reported" } }
        if (doc.RootElement.TryGetProperty("task", out var task) && task.TryGetProperty("status", out var st) && st.ValueKind == JsonValueKind.String)
            return st.GetString()!;
        // Some wrappers: { "data": { "status": "reported" } }
        if (doc.RootElement.TryGetProperty("data", out var data) && data.TryGetProperty("status", out var st2) && st2.ValueKind == JsonValueKind.String)
            return st2.GetString()!;
        return "running";
    }

    private static double? ExtractScore(string reportJson)
    {
        using var doc = JsonDocument.Parse(reportJson);
        // Cuckoo classic: info.score (0-10)
        if (doc.RootElement.TryGetProperty("info", out var info) && info.TryGetProperty("score", out var sc))
        {
            if (sc.ValueKind == JsonValueKind.Number) return sc.GetDouble() / 10.0; // normalize 0-1
        }
        // Alternative: signatures count -> heuristic score
        if (doc.RootElement.TryGetProperty("signatures", out var sigs) && sigs.ValueKind == JsonValueKind.Array)
        {
            var cnt = sigs.GetArrayLength();
            return Math.Min(1.0, cnt / 20.0);
        }
        return null;
    }

    private static string? ExtractSummary(string reportJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(reportJson);
            int sigCount = 0;
            if (doc.RootElement.TryGetProperty("signatures", out var sigs) && sigs.ValueKind == JsonValueKind.Array)
                sigCount = sigs.GetArrayLength();
            double? score = null;
            if (doc.RootElement.TryGetProperty("info", out var info) && info.TryGetProperty("score", out var sc) && sc.ValueKind == JsonValueKind.Number)
                score = sc.GetDouble();
            return $"signatures={sigCount}{(score.HasValue ? ", info.score=" + score.Value : string.Empty)}";
        }
        catch { return null; }
    }
}
