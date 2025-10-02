using System.Text.Json;
using CrossSigEngine.Core.Generators;
using CrossSigEngine.Core.Models;

namespace CrossSigEngine.Generators.CustomPattern;

public class CustomPatternGenerator : IRuleGenerator
{
    public string Family => "custom_pattern";

    public IReadOnlyDictionary<string, string> Generate(ThreatModel threat)
    {
        var cfg = new
        {
            name = threat.Name,
            family = threat.Family,
            patterns = (threat.File?.HexPatterns ?? new List<string>()).Select((p, i) => new { id = i + 1, pattern = p, offset = (int?)null }).ToArray()
        };
        var json = JsonSerializer.Serialize(cfg, new JsonSerializerOptions { WriteIndented = true });
        return new Dictionary<string, string> { { $"{Slug(threat.Name)}.patterns.json", json } };
    }

    private static string Slug(string s) => string.Join("_", s.Split(Path.GetInvalidFileNameChars().Concat(new[] { ' ' }).ToArray(), StringSplitOptions.RemoveEmptyEntries));
}
