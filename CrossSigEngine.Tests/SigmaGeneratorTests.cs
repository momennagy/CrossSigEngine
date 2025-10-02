using CrossSigEngine.Core.Models;
using CrossSigEngine.Generators.Sigma;
using Xunit;

namespace CrossSigEngine.Tests;

public class SigmaGeneratorTests
{
    [Fact]
    public void Generates_Yaml_With_CommandLine_Contains()
    {
        var model = new ThreatModel
        {
            Name = "Sigma Test",
            Family = "SigFam",
            Log = new LogIndicators
            {
                Windows = new WindowsLogIndicators
                {
                    CmdlineContains = { "powershell -enc" },
                    EventId = { 4688 }
                }
            }
        };

        var gen = new SigmaGenerator();
        var artifacts = gen.Generate(model);
        Assert.Single(artifacts);
        var file = artifacts.First();
        Assert.EndsWith(".yml", file.Key);
        var yaml = file.Value;
        Assert.Contains("title:", yaml);
        Assert.Contains("logsource:", yaml);
        Assert.Contains("detection:", yaml);
        Assert.Contains("CommandLine|contains:", yaml);
        Assert.Contains("- \"powershell -enc\"", yaml);
        Assert.Contains("condition: selection", yaml);
    }
}
