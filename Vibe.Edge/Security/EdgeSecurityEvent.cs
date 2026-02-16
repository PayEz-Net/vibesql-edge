namespace Vibe.Edge.Security;

public record EdgeSecurityEvent
{
    public string EventId { get; init; } = Guid.NewGuid().ToString();
    public string EventType { get; init; } = string.Empty;
    public string? Provider { get; init; }
    public string? ExternalSubject { get; init; }
    public int? VibeUserId { get; init; }
    public string? ClientId { get; init; }
    public string? PermissionLevel { get; init; }
    public string? Operation { get; init; }
    public string Result { get; init; } = string.Empty;
    public string? DenyReason { get; init; }
    public string? IpAddress { get; init; }
    public string? UserAgent { get; init; }
    public string? RequestPath { get; init; }
    public string? RequestMethod { get; init; }
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;
    public Dictionary<string, object>? Metadata { get; init; }
}

public static class EdgeEventTypes
{
    public const string AuthSuccess = "auth_success";
    public const string AuthFailure = "auth_failure";
    public const string PermissionGranted = "permission_granted";
    public const string PermissionDenied = "permission_denied";
    public const string IdentityProvisioned = "identity_provisioned";
    public const string ProviderDisabled = "provider_disabled";
    public const string ProviderEnabled = "provider_enabled";
    public const string ProviderRegistered = "provider_registered";
    public const string UnknownIssuer = "unknown_issuer";
    public const string SigningKeyMiss = "signing_key_miss";
}

public static class EdgeDenyReasons
{
    public const string InvalidToken = "invalid_token";
    public const string UnknownIssuer = "unknown_issuer";
    public const string InactiveProvider = "inactive_provider";
    public const string IdentityNotFound = "identity_not_found";
    public const string PermissionInsufficient = "permission_insufficient";
    public const string DeniedStatement = "denied_statement";
    public const string ClientMappingMissing = "client_mapping_missing";
    public const string ClientInactive = "client_inactive";
    public const string PermissionCapExceeded = "permission_cap_exceeded";
    public const string SigningKeyNotFound = "signing_key_not_found";
    public const string MultiStatementRejected = "multi_statement_rejected";
    public const string UnrecognizedStatement = "unrecognized_statement";
}
