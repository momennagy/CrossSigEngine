using System.Text;
using CrossSigEngine.Core.Generators;
using CrossSigEngine.Core.Models;

namespace CrossSigEngine.Generators.SnortSuricata;

public class SnortSuricataGenerator : IRuleGenerator
{
    public string Family => "snort_suricata";

    public IReadOnlyDictionary<string, string> Generate(ThreatModel threat)
    {
        var sb = new StringBuilder();
        int sid = 1000000;
        string family = threat.Family ?? Slug(threat.Name);

        void AddRule(string rule)
        {
            sb.AppendLine(rule);
        }

        if (threat.Network is not null)
        {
            // URI matches
            foreach (var uri in threat.Network.Uris)
            {
                if (string.IsNullOrWhiteSpace(uri)) continue;
                var msg = $"{family} URI";
                AddRule($"alert http any any -> $HOME_NET any (msg:\"{Escape(msg)}\"; flow:to_server,established; content:\"{Escape(uri)}\"; http_uri; nocase; classtype:trojan-activity; sid:{sid++}; rev:1;)");
            }

            // Domain matches (host header)
            foreach (var d in threat.Network.Domains)
            {
                if (string.IsNullOrWhiteSpace(d)) continue;
                var msg = $"{family} Domain";
                AddRule($"alert http any any -> $HOME_NET any (msg:\"{Escape(msg)}\"; flow:to_server,established; content:\"{Escape(d)}\"; http_host; nocase; classtype:trojan-activity; sid:{sid++}; rev:1;)");
            }

            // JA3 (as metadata/flowbits placeholder)
            foreach (var j in threat.Network.Ja3)
            {
                if (string.IsNullOrWhiteSpace(j)) continue;
                var msg = $"{family} JA3\";"; // not natively matchable in Snort without tls fingerprints; Suricata has tls JA3 keyword in newer versions
                AddRule($"# NOTE: JA3 matching requires Suricata tls.ja3; placeholder for {Escape(j)}");
            }
        }

        var content = sb.ToString();
        if (string.IsNullOrWhiteSpace(content)) content = "# No network indicators available";

        var fileName = $"{Slug(threat.Name)}.rules";
        return new Dictionary<string, string> { { fileName, content } };
    }

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
    private static string Slug(string s) => string.Join("_", s.Split(Path.GetInvalidFileNameChars().Concat(new[] { ' ' }).ToArray(), StringSplitOptions.RemoveEmptyEntries));
}
