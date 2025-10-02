using CrossSigEngine.Core.Models;
using CrossSigEngine.Generators.SnortSuricata;
using Xunit;

namespace CrossSigEngine.Tests;

public class SnortSuricataGeneratorTests
{
    [Fact]
    public void Generates_Rules_For_Domain_And_Uri()
    {
        var model = new ThreatModel
        {
            Name = "Test Threat",
            Family = "TestFam",
            Network = new NetworkIndicators
            {
                Domains = { "bad.example" },
                Uris = { "/evil.js" }
            }
        };

        var gen = new SnortSuricataGenerator();
        var artifacts = gen.Generate(model);
        Assert.Single(artifacts);
        var file = artifacts.First();

        Assert.EndsWith(".rules", file.Key);
        var rules = file.Value;
        Assert.Contains("content:\"/evil.js\"; http_uri;", rules);
        Assert.Contains("content:\"bad.example\"; http_host;", rules);
        Assert.Contains("sid:1000000;", rules);
    }
}
