using CrossSigEngine.Core.Models;
using CrossSigEngine.Generators.Zeek;
using Xunit;

namespace CrossSigEngine.Tests;

public class ZeekGeneratorTests
{
    [Fact]
    public void Generates_Zeek_Policy()
    {
        var model = new ThreatModel
        {
            Name = "ZeekTest",
            Network = new NetworkIndicators { Domains = { "evil.test" }, Uris = { "/x" } }
        };

        var gen = new ZeekGenerator();
        var artifacts = gen.Generate(model);
        Assert.Single(artifacts);
        var file = artifacts.First();
        Assert.EndsWith(".zeek", file.Key);
        Assert.Contains("HOST", file.Value);
        Assert.Contains("/evil.test/", file.Value);
        Assert.Contains("/\\/x/", file.Value.Replace("/x", "/\\/x"));
    }
}
