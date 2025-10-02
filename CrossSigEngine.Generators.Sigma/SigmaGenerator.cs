using System.Text;
using CrossSigEngine.Core.Generators;
using CrossSigEngine.Core.Models;

namespace CrossSigEngine.Generators.Sigma;

public class SigmaGenerator : IRuleGenerator
{
    public string Family => "sigma";

    public IReadOnlyDictionary<string, string> Generate(ThreatModel threat)
    {
        var id = Guid.NewGuid().ToString();
        var title = string.IsNullOrWhiteSpace(threat.Family) ? threat.Name : $"{threat.Family} Process Creation";
        var sb = new StringBuilder();
        sb.AppendLine($"title: {EscapeYaml(title)}");
        sb.AppendLine($"id: {id}");
        sb.AppendLine("status: experimental");
        sb.AppendLine("logsource:");
        sb.AppendLine("  product: windows");
        sb.AppendLine("  category: process_creation");
        sb.AppendLine("detection:");
        sb.AppendLine("  selection:");

        var cmdContains = threat.Log?.Windows?.CmdlineContains ?? new List<string>();
        if (cmdContains.Count > 0)
        {
            sb.AppendLine("    CommandLine|contains:");
            foreach (var s in cmdContains.Distinct())
            {
                sb.AppendLine($"      - \"{EscapeYaml(s)}\"");
            }
            sb.AppendLine("  condition: selection");
        }
        else
        {
            var eventIds = threat.Log?.Windows?.EventId ?? new List<int>();
            if (eventIds.Count > 0)
            {
                sb.AppendLine("    EventID:");
                foreach (var e in eventIds.Distinct()) sb.AppendLine($"      - {e}");
            }
            else
            {
                sb.AppendLine("    # No specific selectors available");
            }
            sb.AppendLine("  condition: selection");
        }

        if (threat.Confidence is not null)
            sb.AppendLine($"level: {(threat.Confidence >= 0.9 ? "high" : threat.Confidence >= 0.6 ? "medium" : "low")} ");
        else sb.AppendLine("level: medium");

        var fileName = $"{Slug(threat.Name)}.yml";
        return new Dictionary<string, string> { { fileName, sb.ToString() } };
    }

    private static string EscapeYaml(string s) => s.Replace("\"", "\\\"");
    private static string Slug(string s) => string.Join("_", s.Split(Path.GetInvalidFileNameChars().Concat(new[] { ' ' }).ToArray(), StringSplitOptions.RemoveEmptyEntries));
}
