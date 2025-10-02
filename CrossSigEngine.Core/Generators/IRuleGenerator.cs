using CrossSigEngine.Core.Models;

namespace CrossSigEngine.Core.Generators;

public interface IRuleGenerator
{
    string Family { get; }
    /// <summary>
    /// Generate one or more signatures from a ThreatModel.
    /// </summary>
    /// <param name="threat">Unified threat model</param>
    /// <returns>Mapping of artifact file name to content</returns>
    IReadOnlyDictionary<string, string> Generate(ThreatModel threat);
}
