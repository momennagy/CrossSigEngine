using System.Threading;
using System.Threading.Tasks;

namespace CrossSigEngine.Core.Sandbox;

public interface ISandboxClient
{
    Task<SandboxResult> AnalyzeFileAsync(string filePath, CancellationToken ct = default, int pollIntervalMs = 2000, int timeoutMs = 300000);
    Task<SandboxResult> AnalyzeUrlAsync(string url, CancellationToken ct = default, int pollIntervalMs = 2000, int timeoutMs = 300000);
}
