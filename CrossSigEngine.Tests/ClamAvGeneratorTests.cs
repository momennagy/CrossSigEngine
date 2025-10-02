using CrossSigEngine.Core.Models;
using CrossSigEngine.Generators.ClamAV;
using Xunit;

namespace CrossSigEngine.Tests;

public class ClamAvGeneratorTests
{
    [Fact]
    public void Generates_Ndb_From_HexPatterns()
    {
        var model = new ThreatModel
        {
            Name = "ClamTest",
            File = new FileIndicators { HexPatterns = { "AA BB CC ?? DD" } }
        };

        var gen = new ClamAvGenerator();
        var artifacts = gen.Generate(model);
        Assert.Single(artifacts);
        var file = artifacts.First();
        Assert.EndsWith(".ndb", file.Key);
        Assert.Contains("AA BB CC ?? DD", file.Value);
    }
}
