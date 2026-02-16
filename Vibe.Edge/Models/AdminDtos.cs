using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Vibe.Edge.Models;

public class CreateOidcProviderRequest
{
    [Required]
    [JsonPropertyName("provider_key")]
    public string ProviderKey { get; set; } = string.Empty;

    [Required]
    [JsonPropertyName("display_name")]
    public string DisplayName { get; set; } = string.Empty;

    [Required]
    [JsonPropertyName("issuer")]
    public string Issuer { get; set; } = string.Empty;

    [Required]
    [JsonPropertyName("discovery_url")]
    public string DiscoveryUrl { get; set; } = string.Empty;

    [Required]
    [JsonPropertyName("audience")]
    public string Audience { get; set; } = string.Empty;

    [JsonPropertyName("auto_provision")]
    public bool AutoProvision { get; set; }

    [JsonPropertyName("provision_default_role")]
    public string? ProvisionDefaultRole { get; set; }

    [JsonPropertyName("subject_claim_path")]
    public string SubjectClaimPath { get; set; } = "sub";

    [JsonPropertyName("role_claim_path")]
    public string RoleClaimPath { get; set; } = "roles";

    [JsonPropertyName("email_claim_path")]
    public string EmailClaimPath { get; set; } = "email";

    [JsonPropertyName("clock_skew_seconds")]
    public int ClockSkewSeconds { get; set; } = 60;
}

public class UpdateOidcProviderRequest
{
    [JsonPropertyName("display_name")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("discovery_url")]
    public string? DiscoveryUrl { get; set; }

    [JsonPropertyName("audience")]
    public string? Audience { get; set; }

    [JsonPropertyName("auto_provision")]
    public bool? AutoProvision { get; set; }

    [JsonPropertyName("provision_default_role")]
    public string? ProvisionDefaultRole { get; set; }

    [JsonPropertyName("subject_claim_path")]
    public string? SubjectClaimPath { get; set; }

    [JsonPropertyName("role_claim_path")]
    public string? RoleClaimPath { get; set; }

    [JsonPropertyName("email_claim_path")]
    public string? EmailClaimPath { get; set; }

    [JsonPropertyName("clock_skew_seconds")]
    public int? ClockSkewSeconds { get; set; }
}

public class CreateRoleMappingRequest
{
    [Required]
    [JsonPropertyName("external_role")]
    public string ExternalRole { get; set; } = string.Empty;

    [Required]
    [JsonPropertyName("vibe_permission")]
    public string VibePermission { get; set; } = string.Empty;

    [JsonPropertyName("denied_statements")]
    public string[]? DeniedStatements { get; set; }

    [JsonPropertyName("allowed_collections")]
    public string[]? AllowedCollections { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }
}

public class UpdateRoleMappingRequest
{
    [JsonPropertyName("vibe_permission")]
    public string? VibePermission { get; set; }

    [JsonPropertyName("denied_statements")]
    public string[]? DeniedStatements { get; set; }

    [JsonPropertyName("allowed_collections")]
    public string[]? AllowedCollections { get; set; }

    [JsonPropertyName("description")]
    public string? Description { get; set; }
}

public class CreateClientMappingRequest
{
    [Required]
    [JsonPropertyName("vibe_client_id")]
    public string VibeClientId { get; set; } = string.Empty;

    [JsonPropertyName("max_permission")]
    public string MaxPermission { get; set; } = "write";
}

public class UpdateClientMappingRequest
{
    [JsonPropertyName("vibe_client_id")]
    public string? VibeClientId { get; set; }

    [JsonPropertyName("is_active")]
    public bool? IsActive { get; set; }

    [JsonPropertyName("max_permission")]
    public string? MaxPermission { get; set; }
}

public class CreateCredentialRequest
{
    [Required]
    [JsonPropertyName("client_id")]
    public string ClientId { get; set; } = string.Empty;

    [Required]
    [JsonPropertyName("signing_key")]
    public string SigningKey { get; set; } = string.Empty;

    [JsonPropertyName("display_name")]
    public string? DisplayName { get; set; }
}

public class UpdateCredentialRequest
{
    [JsonPropertyName("display_name")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("is_active")]
    public bool? IsActive { get; set; }
}

public class CredentialResponse
{
    [JsonPropertyName("id")]
    public int Id { get; set; }

    [JsonPropertyName("client_id")]
    public string ClientId { get; set; } = string.Empty;

    [JsonPropertyName("display_name")]
    public string? DisplayName { get; set; }

    [JsonPropertyName("is_active")]
    public bool IsActive { get; set; }

    [JsonPropertyName("created_at")]
    public DateTimeOffset CreatedAt { get; set; }

    [JsonPropertyName("updated_at")]
    public DateTimeOffset UpdatedAt { get; set; }

    public static CredentialResponse From(Data.Models.EdgeClientCredential c)
    {
        return new CredentialResponse
        {
            Id = c.Id,
            ClientId = c.ClientId,
            DisplayName = c.DisplayName,
            IsActive = c.IsActive,
            CreatedAt = c.CreatedAt,
            UpdatedAt = c.UpdatedAt
        };
    }
}

public class ProviderHealthStatus
{
    [JsonPropertyName("provider_key")]
    public string ProviderKey { get; set; } = string.Empty;

    [JsonPropertyName("display_name")]
    public string DisplayName { get; set; } = string.Empty;

    [JsonPropertyName("is_active")]
    public bool IsActive { get; set; }

    [JsonPropertyName("discovery_reachable")]
    public bool DiscoveryReachable { get; set; }

    [JsonPropertyName("jwks_reachable")]
    public bool JwksReachable { get; set; }

    [JsonPropertyName("error")]
    public string? Error { get; set; }
}

public class BootstrapProviderConfig
{
    public string ProviderKey { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string DiscoveryUrl { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public bool IsBootstrap { get; set; } = true;
    public int ClockSkewSeconds { get; set; } = 60;
}
