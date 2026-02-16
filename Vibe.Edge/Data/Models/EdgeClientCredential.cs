namespace Vibe.Edge.Data.Models;

public class EdgeClientCredential
{
    public int Id { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string SigningKey { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
