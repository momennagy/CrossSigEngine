using CrossSigEngine.Core.Models;
using CrossSigEngine.Generators.Yara;
using CrossSigEngine.Core.Detection;
using Xunit;

namespace CrossSigEngine.Tests;

public class YaraGeneratorTests
{
    [Fact]
    public void Generates_Rule_With_Strings_And_Hex()
    {
        var model = new ThreatModel
        {
            Name = "CobaltStrike Beacon",
            Family = "CobaltStrike",
            Confidence = 0.92,
            Sources = { "CTI:VendorX", "Internal:RedTeam" },
            File = new FileIndicators
            {
                Strings = { "reflective loader", "beacon_start" },
                HexPatterns = { "6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 08" }
            }
        };

        var gen = new YaraGenerator();
        var artifacts = gen.Generate(model);
        Assert.Single(artifacts);
        var kv = artifacts.First();

        Assert.EndsWith(".yara", kv.Key);
        var rule = kv.Value;
        Assert.Contains("rule CobaltStrike_Beacon_Static", rule);
        Assert.Contains("$s1 = \"reflective loader\" ascii nocase", rule);
        Assert.Contains("$s2 = \"beacon_start\" ascii", rule);
        Assert.Contains("$h1 = { 6A 00 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 08 }", rule);
        Assert.Contains("uint16(0) == 0x5A4D", rule);
    }
}

public class FileScannerTests
{
    [Fact]
    public void Scanner_Detects_String_And_Hex()
    {
        var tm = new ThreatModel
        {
            Name = "Test",
            File = new FileIndicators
            {
                Strings = new() { "hello_world" },
                HexPatterns = new() { "68 65 6C 6C 6F" } // "hello"
            }
        };

        var tmp = Path.GetTempFileName();
        try
        {
            // file content: "xxxhello_worldyyy"
            File.WriteAllBytes(tmp, System.Text.Encoding.ASCII.GetBytes("xxxhello_worldyyy"));
            var events = FileScanner.ScanFile(tm, tmp).ToList();
            Assert.Contains(events, e => e.IndicatorType == "string" && e.Indicator == "hello_world");
            Assert.Contains(events, e => e.IndicatorType == "hex" && e.Indicator == "68 65 6C 6C 6F");
        }
        finally
        {
            try { File.Delete(tmp); } catch { }
        }
    }
}
