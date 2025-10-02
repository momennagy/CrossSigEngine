using System.Text.Json.Serialization;

namespace CrossSigEngine.Core.Models;

public class ThreatModel
{
    public string Name { get; set; } = string.Empty;
    public string? Family { get; set; }
    public double? Confidence { get; set; }
    public List<string> Sources { get; set; } = new();
    public List<string> Tags { get; set; } = new();

    public FileIndicators? File { get; set; }
    public NetworkIndicators? Network { get; set; }
    public LogIndicators? Log { get; set; }
    public BehavioralIndicators? Behavioral { get; set; }
}

public class FileIndicators
{
    public List<string> Hashes { get; set; } = new(); // e.g., sha256:..., md5:...
    public List<string> Strings { get; set; } = new();
    [JsonPropertyName("hex_patterns")] public List<string> HexPatterns { get; set; } = new(); // e.g., "6A 00 68 ?? ??"
    [JsonPropertyName("pe_features")] public List<string> PeFeatures { get; set; } = new(); // simple placeholders for now
}

public class NetworkIndicators
{
    public List<string> Domains { get; set; } = new();
    public List<string> Ips { get; set; } = new();
    public List<string> Uris { get; set; } = new();
    public List<string> Ja3 { get; set; } = new();
    public List<int> Ports { get; set; } = new();
}

public class LogIndicators
{
    public WindowsLogIndicators? Windows { get; set; }
}

public class WindowsLogIndicators
{
    [JsonPropertyName("event_id")] public List<int> EventId { get; set; } = new();
    [JsonPropertyName("cmdline_contains")] public List<string> CmdlineContains { get; set; } = new();
}

public class BehavioralIndicators
{
    public List<string> Mutexes { get; set; } = new();
    public List<string> RegistryKeys { get; set; } = new();
    public List<string> ProcessTrees { get; set; } = new();
}
