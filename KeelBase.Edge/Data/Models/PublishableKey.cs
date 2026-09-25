namespace KeelBase.Edge.Data.Models;

public class PublishableKey
{
    public int Id { get; set; }
    public string KeyPrefix { get; set; } = string.Empty;
    public string KeyHash { get; set; } = string.Empty;
    public string TenantClientId { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public bool IsRevoked => RevokedAt.HasValue;
}
