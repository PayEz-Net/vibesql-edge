namespace Vibe.Edge.Security;

public interface ISecurityEventSink
{
    Task EmitAsync(EdgeSecurityEvent securityEvent);
    Task EmitBatchAsync(IEnumerable<EdgeSecurityEvent> events);
}

public static class SecurityEventSinkExtensions
{
    public static async Task EmitSafeAsync(this ISecurityEventSink sink, EdgeSecurityEvent securityEvent, ILogger? logger = null)
    {
        try
        {
            await sink.EmitAsync(securityEvent);
        }
        catch (Exception ex)
        {
            logger?.LogWarning(ex, "EDGE_SECURITY: Failed to emit {EventType} event", securityEvent.EventType);
        }
    }
}
