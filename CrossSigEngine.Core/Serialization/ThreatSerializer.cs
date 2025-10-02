using System.Text.Json;
using System.Text.Json.Serialization;
using CrossSigEngine.Core.Models;

namespace CrossSigEngine.Core.Serialization;

public static class ThreatSerializer
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static ThreatModel FromJson(string json)
        => JsonSerializer.Deserialize<ThreatModel>(json, Options) ?? new ThreatModel();

    public static string ToJson(ThreatModel model)
        => JsonSerializer.Serialize(model, Options);
}
