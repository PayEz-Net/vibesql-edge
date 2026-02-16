using System.Text.Json;

namespace Vibe.Edge.Security;

public class ConsoleSecurityEventSink : ISecurityEventSink
{
    private readonly ILogger<ConsoleSecurityEventSink> _logger;

    public ConsoleSecurityEventSink(ILogger<ConsoleSecurityEventSink> logger)
    {
        _logger = logger;
    }

    public Task EmitAsync(EdgeSecurityEvent e)
    {
        _logger.LogInformation(
            "EDGE_SECURITY_EVENT: {EventType} {Result} provider={Provider} user={VibeUserId} client={ClientId} ip={IpAddress} path={RequestPath}",
            e.EventType, e.Result, e.Provider, e.VibeUserId, e.ClientId, e.IpAddress, e.RequestPath);
        return Task.CompletedTask;
    }

    public async Task EmitBatchAsync(IEnumerable<EdgeSecurityEvent> events)
    {
        foreach (var e in events)
            await EmitAsync(e);
    }
}
