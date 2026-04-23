using System.Diagnostics;

namespace SecureVol.Service;

public sealed class WindowsEventLogger
{
    private const string SourceName = "SecureVol";
    private const string LogName = "Application";

    public WindowsEventLogger()
    {
        if (!EventLog.SourceExists(SourceName))
        {
            EventLog.CreateEventSource(SourceName, LogName);
        }
    }

    public void Info(string message) => EventLog.WriteEntry(SourceName, message, EventLogEntryType.Information, 1000);
    public void Warning(string message) => EventLog.WriteEntry(SourceName, message, EventLogEntryType.Warning, 1001);
    public void Error(string message) => EventLog.WriteEntry(SourceName, message, EventLogEntryType.Error, 1002);
}
