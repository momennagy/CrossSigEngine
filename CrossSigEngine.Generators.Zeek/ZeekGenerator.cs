using System.Text;
using CrossSigEngine.Core.Generators;
using CrossSigEngine.Core.Models;

namespace CrossSigEngine.Generators.Zeek;

public class ZeekGenerator : IRuleGenerator
{
    public string Family => "zeek";

    public IReadOnlyDictionary<string, string> Generate(ThreatModel threat)
    {
        var sb = new StringBuilder();
        var name = Slug(threat.Name);
        sb.AppendLine($"# Zeek policy for {threat.Name}");
        sb.AppendLine("@load base/protocols/http");
        sb.AppendLine("redef Notice::policy += { };");

        // Domains: check http host header
        if (threat.Network?.Domains is { Count: > 0 })
        {
            sb.AppendLine("event http_header(c: connection, is_orig: bool, name: string, value: string) {");
            sb.AppendLine("  if ( is_orig && name == \"HOST\" ) {");
            foreach (var d in threat.Network.Domains.Distinct())
            {
                if (string.IsNullOrWhiteSpace(d)) continue;
                sb.AppendLine($"    if ( /{EscapeRegex(d)}/ in value ) {{");
                sb.AppendLine($"      print \"{name} domain hit: \", value; ");
                sb.AppendLine("    }");
            }
            sb.AppendLine("  }");
            sb.AppendLine("}");
        }

        // URIs: check http_request
        if (threat.Network?.Uris is { Count: > 0 })
        {
            sb.AppendLine("event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {");
            foreach (var u in threat.Network.Uris.Distinct())
            {
                if (string.IsNullOrWhiteSpace(u)) continue;
                sb.AppendLine($"  if ( /{EscapeRegex(u)}/ in unescaped_URI ) {{");
                sb.AppendLine($"    print \"{name} uri hit: \", unescaped_URI; ");
                sb.AppendLine("  }");
            }
            sb.AppendLine("}");
        }

        var fileName = $"{name}.zeek";
        return new Dictionary<string, string> { { fileName, sb.ToString() } };
    }

    private static string EscapeRegex(string s) => s.Replace("/", "\\/");
    private static string Slug(string s) => string.Join("_", s.Split(Path.GetInvalidFileNameChars().Concat(new[] { ' ' }).ToArray(), StringSplitOptions.RemoveEmptyEntries));
}
