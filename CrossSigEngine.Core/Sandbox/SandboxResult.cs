using System.Text.Json.Serialization;

namespace CrossSigEngine.Core.Sandbox;

public sealed class SandboxResult
{
    [JsonPropertyName("provider")] public string Provider { get; init; } = string.Empty;
    [JsonPropertyName("target")] public string Target { get; init; } = string.Empty; // file path or URL
    [JsonPropertyName("id")] public string? Id { get; init; }
    [JsonPropertyName("status")] public string Status { get; init; } = string.Empty; // queued|in-progress|completed|error
    [JsonPropertyName("score")] public double? Score { get; init; }
    [JsonPropertyName("summary")] public string? Summary { get; init; }
    [JsonPropertyName("raw")] public object? Raw { get; init; }
}
