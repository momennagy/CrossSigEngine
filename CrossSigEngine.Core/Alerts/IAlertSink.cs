using System.Threading;
using System.Threading.Tasks;
using CrossSigEngine.Core.Detection;

namespace CrossSigEngine.Core.Alerts;

public interface IAlertSink
{
    Task WriteAsync(AlertRecord record, CancellationToken cancellationToken = default);
}

public record AlertRecord(
    string RuleName,
    string? Family,
    string Source, // e.g., "scan"
    DateTimeOffset Timestamp,
    DetectionEvent Event
);
