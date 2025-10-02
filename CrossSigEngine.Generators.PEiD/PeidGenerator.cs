using System.Text.Json;
using CrossSigEngine.Core.Generators;
using CrossSigEngine.Core.Models;

namespace CrossSigEngine.Generators.PEiD;

public class PeidGenerator : IRuleGenerator
{
    public string Family => "peid";

    public IReadOnlyDictionary<string, string> Generate(ThreatModel threat)
    {
        var payload = new
        {
            name = threat.Name,
            family = threat.Family,
            pe_features = threat.File?.PeFeatures ?? new List<string>(),
            hex_patterns = threat.File?.HexPatterns ?? new List<string>()
        };

        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
        return new Dictionary<string, string> { { $"{Slug(threat.Name)}.peid.json", json } };
    }

    private static string Slug(string s) => string.Join("_", s.Split(Path.GetInvalidFileNameChars().Concat(new[] { ' ' }).ToArray(), StringSplitOptions.RemoveEmptyEntries));
}
