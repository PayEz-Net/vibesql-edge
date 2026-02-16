namespace Vibe.Edge.Data.Models;

public class OidcProviderClientMapping
{
    public int Id { get; set; }
    public string ProviderKey { get; set; } = string.Empty;
    public string VibeClientId { get; set; } = string.Empty;
    public bool IsActive { get; set; } = true;
    public string MaxPermission { get; set; } = "write";
    public DateTimeOffset CreatedAt { get; set; }
}
