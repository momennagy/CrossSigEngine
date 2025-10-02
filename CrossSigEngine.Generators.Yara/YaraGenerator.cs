using System.Text;
using System.Text.RegularExpressions;
using CrossSigEngine.Core.Generators;
using CrossSigEngine.Core.Models;

namespace CrossSigEngine.Generators.Yara;

public class YaraGenerator : IRuleGenerator
{
    public string Family => "yara";

    public IReadOnlyDictionary<string, string> Generate(ThreatModel threat)
    {
        var ruleName = Slugify(threat.Name) + "_Static";
        var sb = new StringBuilder();
        sb.AppendLine($"rule {ruleName}");
        sb.AppendLine("{");
        sb.AppendLine("  meta:");
        sb.AppendLine($"    name = \"{Escape(threat.Name)}\"");
        if (!string.IsNullOrWhiteSpace(threat.Family)) sb.AppendLine($"    family = \"{Escape(threat.Family!)}\"");
    if (threat.Confidence is not null) sb.AppendLine($"    confidence = \"{threat.Confidence.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)}\"");
        if (threat.Sources.Count > 0) sb.AppendLine($"    source = \"{Escape(string.Join(';', threat.Sources))}\"");

        var stringsLines = new List<string>();
        if (threat.File?.Strings is { Count: > 0 })
        {
            int i = 1;
            foreach (var s in threat.File.Strings.Take(20))
            {
                if (IsTooGenericString(s)) continue; // policy gate for generic strings
                stringsLines.Add($"    $s{i++} = \"{Escape(s)}\" ascii nocase");
            }
        }
        if (threat.File?.HexPatterns is { Count: > 0 })
        {
            int i = 1;
            foreach (var h in threat.File.HexPatterns.Take(10))
            {
                stringsLines.Add($"    $h{i++} = {{ {NormalizeHexPattern(h)} }}");
            }
        }

        if (stringsLines.Count > 0)
        {
            sb.AppendLine("  strings:");
            foreach (var l in stringsLines) sb.AppendLine(l);
        }

        sb.AppendLine("  condition:");
        // Basic PE check + any string/hex
        var hasStrings = stringsLines.Any(l => l.Contains("$s"));
        var hasHex = stringsLines.Any(l => l.Contains("$h"));
        if (hasStrings && hasHex)
            sb.AppendLine("    (uint16(0) == 0x5A4D) and (any of ($s*) or any of ($h*))");
        else if (hasStrings)
            sb.AppendLine("    (uint16(0) == 0x5A4D) and any of ($s*)");
        else if (hasHex)
            sb.AppendLine("    (uint16(0) == 0x5A4D) and any of ($h*)");
        else
            sb.AppendLine("    uint16(0) == 0x5A4D");
        sb.AppendLine("}");

        return new Dictionary<string, string>
        {
            { $"{ruleName}.yara", sb.ToString() }
        };
    }

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");

    private static string Slugify(string s)
    {
        var slug = Regex.Replace(s, "[^A-Za-z0-9_]+", "_").Trim('_');
        if (char.IsDigit(slug.FirstOrDefault())) slug = "R_" + slug;
        return string.IsNullOrWhiteSpace(slug) ? "Rule" : slug;
    }

    private static string NormalizeHexPattern(string pattern)
    {
        // Allow users to provide either spaced hex with ?? wildcards or raw; we normalize to spaced tokens
        var cleaned = pattern.Replace("\n", " ").Replace("\r", " ").Trim();
        cleaned = Regex.Replace(cleaned, "\\s+", " ");
        return cleaned;
    }

    private static bool IsTooGenericString(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return true;
        if (s.Length < 5) return true;
        // simple entropy check: many identical chars
        var distinct = s.ToLowerInvariant().Where(char.IsLetterOrDigit).Distinct().Count();
        return distinct <= 2; // overly repetitive
    }
}
