using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CrossSigEngine.Core.Alerts;

public class LocalWebhookServer
{
    private readonly HttpListener _listener = new();
    private readonly string _prefix;
    private readonly string? _outputFile;

    public LocalWebhookServer(int port = 8080, string path = "/", string? outputFile = null)
    {
        if (!path.StartsWith('/')) path = "/" + path;
        if (!path.EndsWith('/')) path += "/";
        _prefix = $"http://localhost:{port}{path}";
        _outputFile = outputFile;
        _listener.Prefixes.Add(_prefix);
    }

    public async Task RunAsync(CancellationToken ct)
    {
        try { _listener.Start(); }
        catch (HttpListenerException ex)
        {
            Console.Error.WriteLine($"Failed to start LocalWebhookServer on {_prefix}: {ex.Message}");
            Console.Error.WriteLine("Tip: Run as Administrator or add a URLACL, e.g., 'netsh http add urlacl url=http://localhost:8080/ user=DOMAIN\\User'");
            return;
        }
        Console.WriteLine($"Local webhook listening on {_prefix} (press Ctrl+C to stop)...");

        StreamWriter? log = null;
        if (!string.IsNullOrWhiteSpace(_outputFile)) log = new StreamWriter(_outputFile!, append: true, Encoding.UTF8);

        try
        {
            while (!ct.IsCancellationRequested)
            {
                var ctxTask = _listener.GetContextAsync();
                var completed = await Task.WhenAny(ctxTask, Task.Delay(100, ct));
                if (completed != ctxTask) continue;
                var ctx = ctxTask.Result;
                _ = HandleContextAsync(ctx, log, ct);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            log?.Flush();
            log?.Dispose();
            try { _listener.Stop(); } catch { }
            _listener.Close();
        }
    }

    private static async Task HandleContextAsync(HttpListenerContext ctx, StreamWriter? log, CancellationToken ct)
    {
        try
        {
            string body = string.Empty;
            using (var reader = new StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding))
            {
                body = await reader.ReadToEndAsync().ConfigureAwait(false);
            }

            var entry = new
            {
                Timestamp = DateTimeOffset.UtcNow,
                Method = ctx.Request.HttpMethod,
                Url = ctx.Request.Url?.ToString(),
                Headers = ctx.Request.Headers.AllKeys.ToDictionary(k => k!, k => ctx.Request.Headers[k!]),
                Body = body
            };

            var json = JsonSerializer.Serialize(entry);
            Console.WriteLine($"[Webhook] {entry.Method} {entry.Url}\n{body}");
            if (log != null)
            {
                await log.WriteLineAsync(json).ConfigureAwait(false);
                await log.FlushAsync().ConfigureAwait(false);
            }

            var respBytes = Encoding.UTF8.GetBytes("ok");
            ctx.Response.StatusCode = 200;
            ctx.Response.ContentType = "text/plain";
            ctx.Response.ContentEncoding = Encoding.UTF8;
            ctx.Response.ContentLength64 = respBytes.Length;
            await ctx.Response.OutputStream.WriteAsync(respBytes, 0, respBytes.Length, ct).ConfigureAwait(false);
            ctx.Response.Close();
        }
        catch { }
    }
}
