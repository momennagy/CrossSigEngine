using System.Text.RegularExpressions;
using CrossSigEngine.Core.Models;

namespace CrossSigEngine.Core.Validation;

public enum ValidationSeverity
{
    Warning,
    Error
}

public record ValidationIssue(ValidationSeverity Severity, string Path, string Message)
{
    public override string ToString() => $"[{Severity}] {Path}: {Message}";
}

public static class ThreatValidator
{
    private static readonly Regex HexByte = new("^[0-9A-Fa-f]{2}$", RegexOptions.Compiled);
    private static readonly Regex HexString = new("^[0-9A-Fa-f]+$", RegexOptions.Compiled);
    private static readonly Regex DomainRegex = new(
        pattern: @"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}$",
        options: RegexOptions.Compiled);

    public static IReadOnlyList<ValidationIssue> Validate(ThreatModel model)
    {
        var issues = new List<ValidationIssue>();

        if (string.IsNullOrWhiteSpace(model.Name))
        {
            issues.Add(new(ValidationSeverity.Error, "$", "name is required"));
        }

        if (model.Confidence is not null)
        {
            if (model.Confidence is < 0 or > 1)
                issues.Add(new(ValidationSeverity.Error, "$.confidence", "confidence must be between 0 and 1"));
        }

        ValidateFile(model.File, issues);
        ValidateNetwork(model.Network, issues);
        ValidateLogs(model.Log, issues);

        return issues;
    }

    private static void ValidateFile(FileIndicators? file, List<ValidationIssue> issues)
    {
        if (file is null) return;

        // Hash format: algo:value with expected lengths for common algos
        for (int i = 0; i < file.Hashes.Count; i++)
        {
            var h = file.Hashes[i];
            var path = $"$.file.hashes[{i}]";
            var parts = h.Split(':', 2, StringSplitOptions.TrimEntries);
            if (parts.Length != 2)
            {
                issues.Add(new(ValidationSeverity.Error, path, "hash must be in 'algo:hex' format"));
                continue;
            }
            var algo = parts[0].ToLowerInvariant();
            var hex = parts[1];
            if (!HexString.IsMatch(hex))
            {
                issues.Add(new(ValidationSeverity.Error, path, "hash value must be hex"));
                continue;
            }

            var expectedLen = algo switch
            {
                "md5" => 32,
                "sha1" => 40,
                "sha256" => 64,
                "sha512" => 128,
                _ => (int?)null
            };
            if (expectedLen is not null && hex.Length != expectedLen)
            {
                issues.Add(new(ValidationSeverity.Warning, path, $"unexpected length for {algo} (got {hex.Length}, expected {expectedLen})"));
            }
        }

        // Strings quality
        for (int i = 0; i < file.Strings.Count; i++)
        {
            var s = file.Strings[i];
            var path = $"$.file.strings[{i}]";
            if (string.IsNullOrWhiteSpace(s))
            {
                issues.Add(new(ValidationSeverity.Error, path, "string must not be empty"));
                continue;
            }
            if (s.Trim().Length < 4)
            {
                issues.Add(new(ValidationSeverity.Warning, path, "string is very short (<4); may cause false positives"));
            }
        }

        // Hex patterns: space-separated tokens, each '??' or hex byte
        for (int i = 0; i < file.HexPatterns.Count; i++)
        {
            var pattern = file.HexPatterns[i];
            var path = $"$.file.hex_patterns[{i}]";
            if (string.IsNullOrWhiteSpace(pattern))
            {
                issues.Add(new(ValidationSeverity.Error, path, "hex pattern must not be empty"));
                continue;
            }
            var tokens = pattern.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (tokens.Length == 0)
            {
                issues.Add(new(ValidationSeverity.Error, path, "hex pattern contains no tokens"));
                continue;
            }
            int concreteCount = 0;
            for (int t = 0; t < tokens.Length; t++)
            {
                var tok = tokens[t];
                if (tok == "??") continue;
                if (!HexByte.IsMatch(tok))
                {
                    issues.Add(new(ValidationSeverity.Error, path, $"invalid token '{tok}' at position {t}"));
                }
                else
                {
                    concreteCount++;
                }
            }
            if (concreteCount == 0)
            {
                issues.Add(new(ValidationSeverity.Warning, path, "pattern contains only wildcards"));
            }
        }
    }

    private static void ValidateNetwork(NetworkIndicators? net, List<ValidationIssue> issues)
    {
        if (net is null) return;

        for (int i = 0; i < net.Domains.Count; i++)
        {
            var d = net.Domains[i];
            var path = $"$.network.domains[{i}]";
            if (string.IsNullOrWhiteSpace(d))
            {
                issues.Add(new(ValidationSeverity.Error, path, "domain must not be empty"));
                continue;
            }
            if (!DomainRegex.IsMatch(d))
            {
                issues.Add(new(ValidationSeverity.Warning, path, "domain format looks invalid"));
            }
        }

        for (int i = 0; i < net.Uris.Count; i++)
        {
            var u = net.Uris[i];
            var path = $"$.network.uris[{i}]";
            if (string.IsNullOrWhiteSpace(u))
            {
                issues.Add(new(ValidationSeverity.Error, path, "uri must not be empty"));
                continue;
            }
            var ok = Uri.TryCreate(u, UriKind.RelativeOrAbsolute, out var uri);
            if (!ok)
            {
                issues.Add(new(ValidationSeverity.Warning, path, "uri could not be parsed"));
            }
            else if (uri != null && uri.IsAbsoluteUri && string.IsNullOrWhiteSpace(uri.Scheme))
            {
                issues.Add(new(ValidationSeverity.Warning, path, "uri missing scheme"));
            }
        }

        for (int i = 0; i < net.Ports.Count; i++)
        {
            var p = net.Ports[i];
            var path = $"$.network.ports[{i}]";
            if (p is < 1 or > 65535)
            {
                issues.Add(new(ValidationSeverity.Error, path, "port must be between 1 and 65535"));
            }
        }
    }

    private static void ValidateLogs(LogIndicators? logs, List<ValidationIssue> issues)
    {
        if (logs == null || logs.Windows == null) return;
        var w = logs.Windows;

        for (int i = 0; i < w.EventId.Count; i++)
        {
            var id = w.EventId[i];
            if (id <= 0)
                issues.Add(new(ValidationSeverity.Error, $"$.log.windows.event_id[{i}]", "event_id must be positive"));
        }
        for (int i = 0; i < w.CmdlineContains.Count; i++)
        {
            var s = w.CmdlineContains[i];
            var path = $"$.log.windows.cmdline_contains[{i}]";
            if (string.IsNullOrWhiteSpace(s))
            {
                issues.Add(new(ValidationSeverity.Error, path, "cmdline_contains entry must not be empty"));
                continue;
            }
            if (s.Trim().Length < 4)
            {
                issues.Add(new(ValidationSeverity.Warning, path, "cmdline substring is very short (<4); may be noisy"));
            }
        }
    }
}
