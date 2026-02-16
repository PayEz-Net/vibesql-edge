namespace Vibe.Edge.Data.Models;

public class FederatedIdentity
{
    public int Id { get; set; }
    public string ProviderKey { get; set; } = string.Empty;
    public string ExternalSubject { get; set; } = string.Empty;
    public int VibeUserId { get; set; }
    public string? Email { get; set; }
    public string? DisplayName { get; set; }
    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public bool IsActive { get; set; } = true;
    public string? Metadata { get; set; }
}
