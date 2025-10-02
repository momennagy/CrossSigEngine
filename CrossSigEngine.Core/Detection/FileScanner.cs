using System.Buffers;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using CrossSigEngine.Core.Models;

namespace CrossSigEngine.Core.Detection;

public record DetectionEvent(
    string FilePath,
    string IndicatorType, // string | hex | hash
    string Indicator,
    long Offset // -1 for non-positional (hash)
);

public static class FileScanner
{
    public static IEnumerable<DetectionEvent> ScanPath(ThreatModel model, string path, bool recursive = false, int degreeOfParallelism = 1, IEnumerable<string>? excludeGlobs = null, long maxFileSizeBytes = 0)
    {
        if (File.Exists(path))
            return ScanFile(model, path, maxFileSizeBytes);

        if (Directory.Exists(path))
        {
            var results = new ConcurrentBag<DetectionEvent>();
            var option = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            var files = Directory.EnumerateFiles(path, "*", option);
            var excludes = (excludeGlobs ?? Array.Empty<string>()).ToArray();
            if (degreeOfParallelism <= 1)
            {
                foreach (var file in files)
                {
                    try
                    {
                        if (IsExcluded(file, excludes)) continue;
                        foreach (var ev in ScanFile(model, file, maxFileSizeBytes)) results.Add(ev);
                    }
                    catch { }
                }
            }
            else
            {
                Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = degreeOfParallelism }, file =>
                {
                    try
                    {
                        if (IsExcluded(file, excludes)) return;
                        foreach (var ev in ScanFile(model, file, maxFileSizeBytes)) results.Add(ev);
                    }
                    catch { }
                });
            }
            return results.ToArray();
        }

        return Array.Empty<DetectionEvent>();
    }

    public static IEnumerable<DetectionEvent> ScanFile(ThreatModel model, string filePath, long maxFileSizeBytes = 0)
    {
        var evts = new List<DetectionEvent>();
        if (model.File is null) return evts;

        byte[] bytes;
        try
        {
            if (maxFileSizeBytes > 0)
            {
                var fi = new FileInfo(filePath);
                if (fi.Exists && fi.Length > maxFileSizeBytes) return evts;
            }
            bytes = File.ReadAllBytes(filePath);
        }
        catch { return evts; }

        // Strings → UTF8 search in bytes
        foreach (var s in model.File.Strings)
        {
            if (string.IsNullOrEmpty(s)) continue;
            var needle = Encoding.UTF8.GetBytes(s);
            foreach (var idx in FindAll(bytes, needle))
            {
                evts.Add(new DetectionEvent(filePath, "string", s, idx));
            }
        }

        // Hex patterns → tokens '??' or two-hex bytes
        foreach (var pattern in model.File.HexPatterns)
        {
            if (string.IsNullOrWhiteSpace(pattern)) continue;
            if (!TryParseHexPattern(pattern, out var pat)) continue;
            foreach (var idx in FindAll(bytes, pat))
            {
                evts.Add(new DetectionEvent(filePath, "hex", pattern, idx));
            }
        }

        // Hashes → compute only the algorithms present in model
        if (model.File.Hashes.Count > 0)
        {
            var wantMd5 = model.File.Hashes.Any(h => h.StartsWith("md5:", StringComparison.OrdinalIgnoreCase));
            var wantSha1 = model.File.Hashes.Any(h => h.StartsWith("sha1:", StringComparison.OrdinalIgnoreCase));
            var wantSha256 = model.File.Hashes.Any(h => h.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase));

            string? md5 = null, sha1 = null, sha256 = null;
            if (wantMd5) md5 = ComputeHash(MD5.Create(), bytes);
            if (wantSha1) sha1 = ComputeHash(SHA1.Create(), bytes);
            if (wantSha256) sha256 = ComputeHash(SHA256.Create(), bytes);

            foreach (var h in model.File.Hashes)
            {
                var parts = h.Split(':', 2, StringSplitOptions.TrimEntries);
                if (parts.Length != 2) continue;
                var algo = parts[0].ToLowerInvariant();
                var hex = parts[1];
                var matched = algo switch
                {
                    "md5" => md5 != null && md5.Equals(hex, StringComparison.OrdinalIgnoreCase),
                    "sha1" => sha1 != null && sha1.Equals(hex, StringComparison.OrdinalIgnoreCase),
                    "sha256" => sha256 != null && sha256.Equals(hex, StringComparison.OrdinalIgnoreCase),
                    _ => false
                };
                if (matched)
                {
                    evts.Add(new DetectionEvent(filePath, "hash", $"{algo}:{hex}", -1));
                }
            }
        }

        // Optional: PE feature matches using PeFeatures list via PeNet (if referenced)
        try
        {
            if (model.File.PeFeatures.Count > 0)
            {
                // Late-bound load to avoid hard dependency if package is not present
                var asm = AppDomain.CurrentDomain.GetAssemblies().FirstOrDefault(a => a.GetName().Name?.Equals("PeNet", StringComparison.OrdinalIgnoreCase) == true);
                if (asm != null)
                {
                    var peFileType = asm.GetType("PeNet.PeFile");
                    if (peFileType != null)
                    {
                        var ctor = peFileType.GetConstructor(new[] { typeof(byte[]) });
                        var pe = ctor?.Invoke(new object[] { bytes });
                        if (pe != null)
                        {
                            var isPeProp = peFileType.GetProperty("IsValidPeFile");
                            var isPe = isPeProp != null && (bool)(isPeProp.GetValue(pe) ?? false);
                            if (isPe)
                            {
                                foreach (var feat in model.File.PeFeatures)
                                {
                                    if (string.IsNullOrWhiteSpace(feat)) continue;
                                    // Simple checks: sections, imports, architecture
                                    if (feat.Equals("pe32", StringComparison.OrdinalIgnoreCase) || feat.Equals("pe32+", StringComparison.OrdinalIgnoreCase))
                                    {
                                        var is64Prop = peFileType.GetProperty("Is64Bit");
                                        var is64 = is64Prop != null && (bool)(is64Prop.GetValue(pe) ?? false);
                                        if (feat.Equals("pe32", StringComparison.OrdinalIgnoreCase) && !is64)
                                            evts.Add(new DetectionEvent(filePath, "pe_feature", feat, -1));
                                        if (feat.Equals("pe32+", StringComparison.OrdinalIgnoreCase) && is64)
                                            evts.Add(new DetectionEvent(filePath, "pe_feature", feat, -1));
                                    }
                                    else if (feat.StartsWith("import:", StringComparison.OrdinalIgnoreCase))
                                    {
                                        var want = feat.Substring(7).Trim();
                                        var importsProp = peFileType.GetProperty("ImportedFunctions");
                                        var imports = importsProp?.GetValue(pe) as System.Collections.IEnumerable;
                                        if (imports != null)
                                        {
                                            foreach (var fn in imports)
                                            {
                                                var fnType = fn.GetType();
                                                var nameProp = fnType.GetProperty("Name");
                                                var dllProp = fnType.GetProperty("DLL");
                                                var name = nameProp?.GetValue(fn)?.ToString();
                                                var dll = dllProp?.GetValue(fn)?.ToString();
                                                if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(dll))
                                                {
                                                    var id = $"{dll}!{name}";
                                                    if (id.Contains(want, StringComparison.OrdinalIgnoreCase))
                                                    {
                                                        evts.Add(new DetectionEvent(filePath, "pe_feature", $"import:{id}", -1));
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    else if (feat.StartsWith("section:", StringComparison.OrdinalIgnoreCase))
                                    {
                                        var want = feat.Substring(8).Trim();
                                        var sectsProp = peFileType.GetProperty("ImageSectionHeaders");
                                        var sects = sectsProp?.GetValue(pe) as System.Collections.IEnumerable;
                                        if (sects != null)
                                        {
                                            foreach (var s in sects)
                                            {
                                                var st = s.GetType();
                                                var nameProp = st.GetProperty("NameString");
                                                var name = nameProp?.GetValue(s)?.ToString();
                                                if (!string.IsNullOrEmpty(name) && name.Contains(want, StringComparison.OrdinalIgnoreCase))
                                                {
                                                    evts.Add(new DetectionEvent(filePath, "pe_feature", $"section:{name}", -1));
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        catch { }

        return evts;
    }

    private static string ComputeHash(HashAlgorithm algo, byte[] data)
    {
        using (algo)
        {
            var hash = algo.ComputeHash(data);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
    }

    private static bool IsExcluded(string file, string[] excludes)
    {
        if (excludes.Length == 0) return false;
        var name = Path.GetFileName(file);
        foreach (var g in excludes)
        {
            if (string.IsNullOrWhiteSpace(g)) continue;
            if (GlobMatch(name, g) || GlobMatch(file, g)) return true;
        }
        return false;
    }

    // Simple glob matcher supporting * and ?
    private static bool GlobMatch(string text, string pattern)
    {
        int ti = 0, pi = 0, star = -1, mark = -1;
        while (ti < text.Length)
        {
            if (pi < pattern.Length && (pattern[pi] == '?' || char.ToLowerInvariant(pattern[pi]) == char.ToLowerInvariant(text[ti])))
            { ti++; pi++; continue; }
            if (pi < pattern.Length && pattern[pi] == '*')
            { star = pi++; mark = ti; continue; }
            if (star != -1)
            { pi = star + 1; ti = ++mark; continue; }
            return false;
        }
        while (pi < pattern.Length && pattern[pi] == '*') pi++;
        return pi == pattern.Length;
    }
    // Find all occurrences of a byte pattern within haystack; supports nulls in pattern as wildcards
    private static IEnumerable<int> FindAll(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0) yield break;
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { ok = false; break; }
            }
            if (ok) yield return i;
        }
    }

    private static IEnumerable<int> FindAll(byte[] haystack, byte?[] pattern)
    {
        if (pattern.Length == 0) yield break;
        for (int i = 0; i <= haystack.Length - pattern.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                var p = pattern[j];
                if (p.HasValue && haystack[i + j] != p.Value) { ok = false; break; }
            }
            if (ok) yield return i;
        }
    }

    private static bool TryParseHexPattern(string pattern, out byte?[] parsed)
    {
        var tokens = pattern.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        parsed = new byte?[tokens.Length];
        for (int i = 0; i < tokens.Length; i++)
        {
            var tok = tokens[i];
            if (tok == "??") { parsed[i] = null; continue; }
            if (tok.Length == 2 && int.TryParse(tok, System.Globalization.NumberStyles.HexNumber, null, out var b))
            {
                parsed[i] = (byte)b;
            }
            else
            {
                parsed = Array.Empty<byte?>();
                return false;
            }
        }
        return true;
    }
}
