namespace CrossSigEngine.Web;

public class DirScanRequest
{
    public string? Model { get; set; }
    public string? Path { get; set; }
    public bool Recursive { get; set; } = false;
    public int Parallel { get; set; } = 1;
    public List<string>? Exclude { get; set; }
    public long MaxFileSizeBytes { get; set; } = 0;
    public string? Webhook { get; set; }
    public Dictionary<string, string>? WebhookHeaders { get; set; }
    public string WebhookFormat { get; set; } = "json";
    public int WebhookDelayMs { get; set; } = 0;
    public string? EventLogSource { get; set; }
    public bool FailOnMatch { get; set; } = false;
}
