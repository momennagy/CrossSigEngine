using System.Text;
using System.Text.RegularExpressions;
using CrossSigEngine.Core.Generators;
using CrossSigEngine.Core.Models;

namespace CrossSigEngine.Generators.ClamAV;

public class ClamAvGenerator : IRuleGenerator
{
    public string Family => "clamav";

    public IReadOnlyDictionary<string, string> Generate(ThreatModel threat)
    {
        var hdb = new StringBuilder();
        var ndb = new StringBuilder();

        // hdb: name:md5:size
        if (threat.File?.Hashes is { Count: > 0 })
        {
            foreach (var h in threat.File.Hashes)
            {
                var md5 = ExtractHash(h, "md5");
                if (md5 is null) continue;
                hdb.AppendLine($"{Slug(threat.Name)}:{md5}:0");
            }
        }

        // ndb: name:target_type:offset:hex
        if (threat.File?.HexPatterns is { Count: > 0 })
        {
            int i = 1;
            foreach (var hp in threat.File.HexPatterns)
            {
                var hex = NormalizeHex(hp);
                ndb.AppendLine($"{Slug(threat.Name)}_h{i++}:0:*:{hex}");
            }
        }

        var dict = new Dictionary<string, string>();
        if (hdb.Length > 0) dict[$"{Slug(threat.Name)}.hdb"] = hdb.ToString();
        if (ndb.Length > 0) dict[$"{Slug(threat.Name)}.ndb"] = ndb.ToString();
        if (dict.Count == 0) dict[$"{Slug(threat.Name)}.txt"] = "# No ClamAV indicators available";
        return dict;
    }

    private static string? ExtractHash(string s, string algo)
    {
        var parts = s.Split(':', 2);
        if (parts.Length != 2) return null;
        if (!parts[0].Equals(algo, StringComparison.OrdinalIgnoreCase)) return null;
        var val = parts[1];
        if (algo.Equals("md5", StringComparison.OrdinalIgnoreCase))
        {
            if (val.Length != 32) return null;
            foreach (var ch in val)
            {
                if (!Uri.IsHexDigit(ch)) return null;
            }
            return val.ToLowerInvariant();
        }
        return null;
    }

    private static string NormalizeHex(string pattern)
    {
        // Remove braces and normalize wildcards ?? to * in ClamAV hex
        var p = pattern.Trim();
        p = p.Trim('{', '}');
        p = Regex.Replace(p, "\\s+", " ");
        p = p.Replace("??", "??"); // ClamAV supports ?? wildcards in ndb
        return p;
    }

    private static string Slug(string s) => string.Join("_", s.Split(Path.GetInvalidFileNameChars().Concat(new[] { ' ' }).ToArray(), StringSplitOptions.RemoveEmptyEntries));
}
