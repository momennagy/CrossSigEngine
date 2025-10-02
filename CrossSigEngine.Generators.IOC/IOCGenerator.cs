using System.Text;
using CrossSigEngine.Core.Generators;
using CrossSigEngine.Core.Models;

namespace CrossSigEngine.Generators.IOC;

public class IOCGenerator : IRuleGenerator
{
    public string Family => "ioc";

    public IReadOnlyDictionary<string, string> Generate(ThreatModel threat)
    {
        var rows = new List<(string Type, string Value)>();
        void AddRange(string type, IEnumerable<string> vals)
        {
            foreach (var v in vals)
            {
                if (!string.IsNullOrWhiteSpace(v)) rows.Add((type, v));
            }
        }

        if (threat.File?.Hashes is { Count: > 0 }) AddRange("hash", threat.File.Hashes);
        if (threat.Network?.Domains is { Count: > 0 }) AddRange("domain", threat.Network.Domains);
        if (threat.Network?.Ips is { Count: > 0 }) AddRange("ip", threat.Network.Ips);
        if (threat.Network?.Uris is { Count: > 0 }) AddRange("url", threat.Network.Uris);
        if (threat.Network?.Ja3 is { Count: > 0 }) AddRange("ja3", threat.Network.Ja3);

        var sbTxt = new StringBuilder();
        foreach (var r in rows) sbTxt.AppendLine(r.Value);

        var sbCsv = new StringBuilder();
        sbCsv.AppendLine("type,value");
        foreach (var r in rows) sbCsv.AppendLine($"{r.Type},{EscapeCsv(r.Value)}");

        var baseName = Slug(threat.Name);
        return new Dictionary<string, string>
        {
            { $"{baseName}.iocs.txt", sbTxt.ToString() },
            { $"{baseName}.iocs.csv", sbCsv.ToString() }
        };
    }

    private static string EscapeCsv(string s) => s.Contains(',') ? $"\"{s.Replace("\"", "\"\"")}\"" : s;
    private static string Slug(string s) => string.Join("_", s.Split(Path.GetInvalidFileNameChars().Concat(new[] { ' ' }).ToArray(), StringSplitOptions.RemoveEmptyEntries));
}
