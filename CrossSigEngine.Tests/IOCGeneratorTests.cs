using CrossSigEngine.Core.Models;
using CrossSigEngine.Generators.IOC;
using Xunit;

namespace CrossSigEngine.Tests;

public class IOCGeneratorTests
{
    [Fact]
    public void Generates_Txt_And_Csv()
    {
        var model = new ThreatModel
        {
            Name = "IOCTest",
            File = new FileIndicators { Hashes = { "sha256:deadbeef" } },
            Network = new NetworkIndicators { Domains = { "ex.test" }, Uris = { "/a" } }
        };

        var gen = new IOCGenerator();
        var artifacts = gen.Generate(model);
        Assert.Equal(2, artifacts.Count);
        Assert.Contains(artifacts.Keys, k => k.EndsWith(".iocs.txt"));
        Assert.Contains(artifacts.Keys, k => k.EndsWith(".iocs.csv"));
        Assert.Contains("deadbeef", string.Join("\n", artifacts.Values));
        Assert.Contains("ex.test", string.Join("\n", artifacts.Values));
    }
}
