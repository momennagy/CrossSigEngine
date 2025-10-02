using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CrossSigEngine.Core.Alerts;

public class WindowsEventLogAlertSink : IAlertSink
{
    private readonly string _source;
    private readonly string _logName;

    public WindowsEventLogAlertSink(string source, string logName = "Application")
    {
        _source = source;
        _logName = logName;
    }

    public Task WriteAsync(AlertRecord record, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows()) return Task.CompletedTask;

        try
        {
            // Ensure source exists; may require admin privileges
            if (!EventLog.SourceExists(_source))
            {
                try { EventLog.CreateEventSource(_source, _logName); }
                catch { /* ignore if lacks permission */ }
            }

            var json = JsonSerializer.Serialize(record);
            EventLog.WriteEntry(_source, json, EventLogEntryType.Information, 1000);
        }
        catch
        {
            // ignore write failures (permissions, etc.)
        }

        return Task.CompletedTask;
    }
}
