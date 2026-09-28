namespace KeelBase.Edge.Authentication;

/// <summary>
/// TS-09: KeelAuth is the built-in identity provider. Config section: "KeelEdge:KeelAuth".
/// Claim names are configuration only — nothing about agent recognition is hard-coded.
/// </summary>
public class KeelAuthOptions
{
    public const string SectionName = "KeelEdge:KeelAuth";

    /// <summary>Provider key KeelAuth is seeded and registered under (JWT scheme "Edge_KeelAuth").</summary>
    public const string ProviderKey = "KeelAuth";

    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public string DiscoveryUrl { get; set; } = string.Empty;

    /// <summary>Claim name that marks a token as an agent. Empty or null = agent recognition off.</summary>
    public string? AgentClaim { get; set; }

    /// <summary>
    /// R15 (NightHawk 65081): the VALUE <see cref="AgentClaim"/> must carry to mean "agent". Recognition is
    /// value-based, not presence-based, because a service token also carries user_type (=service).
    /// </summary>
    public string AgentClaimValue { get; set; } = "agent";

    /// <summary>Claim name carrying the agent's own id (agent_profile_id). Optional: an agent token without it is still an agent.</summary>
    public string? AgentIdClaim { get; set; }

    /// <summary>Claim name carrying the agent's owning user id.</summary>
    public string? AgentOwnerClaim { get; set; }

    /// <summary>True when the section is filled in enough to be seeded as a bootstrap provider.</summary>
    public bool IsConfigured => !string.IsNullOrWhiteSpace(Issuer) || !string.IsNullOrWhiteSpace(DiscoveryUrl);
}
