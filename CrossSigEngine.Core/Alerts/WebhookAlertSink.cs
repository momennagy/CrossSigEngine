using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CrossSigEngine.Core.Alerts;

public class WebhookAlertSink : IAlertSink
{
    private static readonly HttpClient Http = new();
    private readonly string _url;
    private readonly IReadOnlyDictionary<string, string>? _headers;
    private readonly string _format; // json | slack

    public WebhookAlertSink(string url, IReadOnlyDictionary<string, string>? headers = null, string format = "json")
    {
        _url = url;
        _headers = headers;
        _format = string.IsNullOrWhiteSpace(format) ? "json" : format.ToLowerInvariant();
    }

    public async Task WriteAsync(AlertRecord record, CancellationToken cancellationToken = default)
    {
        // Build payload depending on format
        string json;
        if (_format == "slack")
        {
            var text = $"CrossSigEngine alert: {record.RuleName} ({record.Family}) - {record.Event.IndicatorType} match '{record.Event.Indicator}' at {record.Event.Offset} in {record.Event.FilePath}";
            json = JsonSerializer.Serialize(new { text });
        }
        else
        {
            json = JsonSerializer.Serialize(record);
        }

        using var req = new HttpRequestMessage(HttpMethod.Post, _url)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        if (_headers != null)
        {
            foreach (var kv in _headers)
            {
                // Try to set Authorization explicitly if header is Authorization
                if (kv.Key.Equals("authorization", StringComparison.OrdinalIgnoreCase))
                {
                    req.Headers.TryAddWithoutValidation("Authorization", kv.Value);
                }
                else
                {
                    req.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
                }
            }
        }

        using var resp = await Http.SendAsync(req, cancellationToken).ConfigureAwait(false);
        _ = resp.IsSuccessStatusCode; // swallow non-success to avoid breaking scan loops
    }
}
