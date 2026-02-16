namespace Vibe.Edge.Data.Models;

public class OidcProviderRoleMapping
{
    public int Id { get; set; }
    public string ProviderKey { get; set; } = string.Empty;
    public string ExternalRole { get; set; } = string.Empty;
    public string VibePermission { get; set; } = string.Empty;
    public string[]? DeniedStatements { get; set; }
    public string[]? AllowedCollections { get; set; }
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
