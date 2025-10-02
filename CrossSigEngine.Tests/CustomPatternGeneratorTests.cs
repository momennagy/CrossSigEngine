using CrossSigEngine.Core.Models;
using CrossSigEngine.Generators.CustomPattern;
using Xunit;

namespace CrossSigEngine.Tests;

public class CustomPatternGeneratorTests
{
    [Fact]
    public void Generates_Patterns_Json()
    {
        var model = new ThreatModel
        {
            Name = "PatTest",
            File = new FileIndicators { HexPatterns = { "11 22 33 ??" } }
        };

        var gen = new CustomPatternGenerator();
        var artifacts = gen.Generate(model);
        Assert.Single(artifacts);
        var file = artifacts.First();
        Assert.EndsWith(".patterns.json", file.Key);
        Assert.Contains("\"patterns\"", file.Value);
        Assert.Contains("11 22 33 ??", file.Value);
    }
}
