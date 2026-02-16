using System.Data;
using Dapper;
using Devart.Data.PostgreSql;
using Vibe.Edge.Data.Models;

namespace Vibe.Edge.Data;

public class VibeDataService
{
    private readonly string _connectionString;
    private readonly ILogger<VibeDataService> _logger;

    public VibeDataService(IConfiguration configuration, ILogger<VibeDataService> logger)
    {
        _connectionString = configuration.GetConnectionString("EdgeDb")
            ?? throw new InvalidOperationException("ConnectionStrings:EdgeDb is not configured");
        _logger = logger;
    }

    private PgSqlConnection CreateConnection() => new(_connectionString);

    #region Schema Initialization

    public async Task InitializeSchemaAsync()
    {
        _logger.LogInformation("EDGE_SCHEMA: Initializing vibe_system schema...");

        const string ddl = """
            CREATE SCHEMA IF NOT EXISTS vibe_system;

            CREATE TABLE IF NOT EXISTS vibe_system.oidc_providers (
                provider_key            VARCHAR(50) PRIMARY KEY,
                display_name            VARCHAR(200) NOT NULL,
                issuer                  VARCHAR(500) NOT NULL UNIQUE,
                discovery_url           VARCHAR(500) NOT NULL,
                audience                VARCHAR(500) NOT NULL,
                is_active               BOOLEAN DEFAULT TRUE,
                is_bootstrap            BOOLEAN DEFAULT FALSE,
                auto_provision          BOOLEAN DEFAULT FALSE,
                provision_default_role  VARCHAR(100),
                subject_claim_path      VARCHAR(100) DEFAULT 'sub',
                role_claim_path         VARCHAR(100) DEFAULT 'roles',
                email_claim_path        VARCHAR(100) DEFAULT 'email',
                clock_skew_seconds      INTEGER DEFAULT 60,
                disable_grace_minutes   INTEGER DEFAULT 0,
                disabled_at             TIMESTAMPTZ,
                created_at              TIMESTAMPTZ DEFAULT NOW(),
                updated_at              TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS vibe_system.oidc_provider_role_mappings (
                id                  SERIAL PRIMARY KEY,
                provider_key        VARCHAR(50) NOT NULL,
                external_role       VARCHAR(200) NOT NULL,
                vibe_permission     VARCHAR(20) NOT NULL CHECK (vibe_permission IN ('none','read','write','schema','admin')),
                denied_statements   TEXT[],
                allowed_collections TEXT[],
                description         VARCHAR(500),
                created_at          TIMESTAMPTZ DEFAULT NOW(),
                CONSTRAINT uq_provider_role UNIQUE (provider_key, external_role),
                CONSTRAINT fk_role_provider FOREIGN KEY (provider_key)
                    REFERENCES vibe_system.oidc_providers(provider_key) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS vibe_system.oidc_provider_client_mappings (
                id              SERIAL PRIMARY KEY,
                provider_key    VARCHAR(50) NOT NULL,
                vibe_client_id  VARCHAR(100) NOT NULL,
                is_active       BOOLEAN DEFAULT TRUE,
                max_permission  VARCHAR(20) DEFAULT 'write' CHECK (max_permission IN ('none','read','write','schema','admin')),
                created_at      TIMESTAMPTZ DEFAULT NOW(),
                CONSTRAINT uq_provider_client UNIQUE (provider_key, vibe_client_id),
                CONSTRAINT fk_client_provider FOREIGN KEY (provider_key)
                    REFERENCES vibe_system.oidc_providers(provider_key) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS vibe_system.federated_identities (
                id                  SERIAL PRIMARY KEY,
                provider_key        VARCHAR(50) NOT NULL,
                external_subject    VARCHAR(255) NOT NULL,
                vibe_user_id        INTEGER NOT NULL,
                email               VARCHAR(255),
                display_name        VARCHAR(255),
                first_seen_at       TIMESTAMPTZ DEFAULT NOW(),
                last_seen_at        TIMESTAMPTZ DEFAULT NOW(),
                is_active           BOOLEAN DEFAULT TRUE,
                metadata            JSONB,
                CONSTRAINT uq_federated_identity UNIQUE (provider_key, external_subject),
                CONSTRAINT fk_federated_provider FOREIGN KEY (provider_key)
                    REFERENCES vibe_system.oidc_providers(provider_key) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_federated_lookup ON vibe_system.federated_identities (provider_key, external_subject);
            CREATE INDEX IF NOT EXISTS idx_federated_vibe_user ON vibe_system.federated_identities (vibe_user_id);

            CREATE TABLE IF NOT EXISTS vibe_system.edge_client_credentials (
                id              SERIAL PRIMARY KEY,
                client_id       VARCHAR(100) NOT NULL UNIQUE,
                signing_key     VARCHAR(500) NOT NULL,
                display_name    VARCHAR(200),
                is_active       BOOLEAN DEFAULT TRUE,
                created_at      TIMESTAMPTZ DEFAULT NOW(),
                updated_at      TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE SEQUENCE IF NOT EXISTS vibe_system.federated_user_id_seq START WITH 10000;
            """;

        using var conn = CreateConnection();
        await conn.OpenAsync();
        await conn.ExecuteAsync(ddl);

        _logger.LogInformation("EDGE_SCHEMA: Schema initialization complete");
    }

    #endregion

    #region OidcProviders

    public async Task<IEnumerable<OidcProvider>> GetAllProvidersAsync()
    {
        using var conn = CreateConnection();
        return await conn.QueryAsync<OidcProvider>(
            "SELECT * FROM vibe_system.oidc_providers ORDER BY provider_key");
    }

    public async Task<IEnumerable<OidcProvider>> GetActiveProvidersAsync()
    {
        using var conn = CreateConnection();
        return await conn.QueryAsync<OidcProvider>(
            "SELECT * FROM vibe_system.oidc_providers WHERE is_active = TRUE ORDER BY provider_key");
    }

    public async Task<OidcProvider?> GetProviderByKeyAsync(string providerKey)
    {
        using var conn = CreateConnection();
        return await conn.QuerySingleOrDefaultAsync<OidcProvider>(
            "SELECT * FROM vibe_system.oidc_providers WHERE provider_key = @ProviderKey",
            new { ProviderKey = providerKey });
    }

    public async Task<OidcProvider?> GetProviderByIssuerAsync(string issuer)
    {
        using var conn = CreateConnection();
        return await conn.QuerySingleOrDefaultAsync<OidcProvider>(
            "SELECT * FROM vibe_system.oidc_providers WHERE issuer = @Issuer AND is_active = TRUE",
            new { Issuer = issuer });
    }

    public async Task<OidcProvider> InsertProviderAsync(OidcProvider provider)
    {
        using var conn = CreateConnection();
        await conn.ExecuteAsync("""
            INSERT INTO vibe_system.oidc_providers
                (provider_key, display_name, issuer, discovery_url, audience, is_active, is_bootstrap,
                 auto_provision, provision_default_role, subject_claim_path, role_claim_path,
                 email_claim_path, clock_skew_seconds)
            VALUES
                (@ProviderKey, @DisplayName, @Issuer, @DiscoveryUrl, @Audience, @IsActive, @IsBootstrap,
                 @AutoProvision, @ProvisionDefaultRole, @SubjectClaimPath, @RoleClaimPath,
                 @EmailClaimPath, @ClockSkewSeconds)
            """, provider);

        return (await GetProviderByKeyAsync(provider.ProviderKey))!;
    }

    public async Task<OidcProvider?> UpdateProviderAsync(string providerKey, Action<OidcProvider> applyUpdates)
    {
        using var conn = CreateConnection();
        await conn.OpenAsync();
        using var tx = conn.BeginTransaction();

        var existing = await conn.QuerySingleOrDefaultAsync<OidcProvider>(
            "SELECT * FROM vibe_system.oidc_providers WHERE provider_key = @ProviderKey FOR UPDATE",
            new { ProviderKey = providerKey }, tx);
        if (existing == null) return null;

        applyUpdates(existing);

        await conn.ExecuteAsync("""
            UPDATE vibe_system.oidc_providers SET
                display_name = @DisplayName,
                discovery_url = @DiscoveryUrl,
                audience = @Audience,
                auto_provision = @AutoProvision,
                provision_default_role = @ProvisionDefaultRole,
                subject_claim_path = @SubjectClaimPath,
                role_claim_path = @RoleClaimPath,
                email_claim_path = @EmailClaimPath,
                clock_skew_seconds = @ClockSkewSeconds,
                updated_at = NOW()
            WHERE provider_key = @ProviderKey
            """, existing, tx);

        tx.Commit();

        return await conn.QuerySingleOrDefaultAsync<OidcProvider>(
            "SELECT * FROM vibe_system.oidc_providers WHERE provider_key = @ProviderKey",
            new { ProviderKey = providerKey });
    }

    public async Task<bool> DisableProviderAsync(string providerKey)
    {
        using var conn = CreateConnection();
        var rows = await conn.ExecuteAsync("""
            UPDATE vibe_system.oidc_providers
            SET is_active = FALSE, disabled_at = NOW(), updated_at = NOW()
            WHERE provider_key = @ProviderKey AND is_bootstrap = FALSE
            """, new { ProviderKey = providerKey });
        return rows > 0;
    }

    public async Task<bool> ProviderExistsAsync(string providerKey)
    {
        using var conn = CreateConnection();
        return await conn.ExecuteScalarAsync<bool>(
            "SELECT EXISTS(SELECT 1 FROM vibe_system.oidc_providers WHERE provider_key = @ProviderKey)",
            new { ProviderKey = providerKey });
    }

    #endregion

    #region RoleMappings

    public async Task<IEnumerable<OidcProviderRoleMapping>> GetRoleMappingsAsync(string providerKey)
    {
        using var conn = CreateConnection();
        return await conn.QueryAsync<OidcProviderRoleMapping>(
            "SELECT * FROM vibe_system.oidc_provider_role_mappings WHERE provider_key = @ProviderKey ORDER BY id",
            new { ProviderKey = providerKey });
    }

    public async Task<OidcProviderRoleMapping?> GetRoleMappingByIdAsync(int id)
    {
        using var conn = CreateConnection();
        return await conn.QuerySingleOrDefaultAsync<OidcProviderRoleMapping>(
            "SELECT * FROM vibe_system.oidc_provider_role_mappings WHERE id = @Id",
            new { Id = id });
    }

    public async Task<IEnumerable<OidcProviderRoleMapping>> GetRoleMappingsByRolesAsync(string providerKey, IEnumerable<string> roles)
    {
        using var conn = CreateConnection();
        return await conn.QueryAsync<OidcProviderRoleMapping>(
            "SELECT * FROM vibe_system.oidc_provider_role_mappings WHERE provider_key = @ProviderKey AND external_role = ANY(@Roles)",
            new { ProviderKey = providerKey, Roles = roles.ToArray() });
    }

    public async Task<OidcProviderRoleMapping> InsertRoleMappingAsync(OidcProviderRoleMapping mapping)
    {
        using var conn = CreateConnection();
        var id = await conn.ExecuteScalarAsync<int>("""
            INSERT INTO vibe_system.oidc_provider_role_mappings
                (provider_key, external_role, vibe_permission, denied_statements, allowed_collections, description)
            VALUES
                (@ProviderKey, @ExternalRole, @VibePermission, @DeniedStatements, @AllowedCollections, @Description)
            RETURNING id
            """, mapping);

        return (await GetRoleMappingByIdAsync(id))!;
    }

    public async Task<OidcProviderRoleMapping?> UpdateRoleMappingAsync(int id, Action<OidcProviderRoleMapping> applyUpdates)
    {
        using var conn = CreateConnection();
        await conn.OpenAsync();
        using var tx = conn.BeginTransaction();

        var existing = await conn.QuerySingleOrDefaultAsync<OidcProviderRoleMapping>(
            "SELECT * FROM vibe_system.oidc_provider_role_mappings WHERE id = @Id FOR UPDATE",
            new { Id = id }, tx);
        if (existing == null) return null;

        applyUpdates(existing);

        await conn.ExecuteAsync("""
            UPDATE vibe_system.oidc_provider_role_mappings SET
                vibe_permission = @VibePermission,
                denied_statements = @DeniedStatements,
                allowed_collections = @AllowedCollections,
                description = @Description
            WHERE id = @Id
            """, existing, tx);

        tx.Commit();

        return await conn.QuerySingleOrDefaultAsync<OidcProviderRoleMapping>(
            "SELECT * FROM vibe_system.oidc_provider_role_mappings WHERE id = @Id",
            new { Id = id });
    }

    public async Task<bool> DeleteRoleMappingAsync(int id)
    {
        using var conn = CreateConnection();
        var rows = await conn.ExecuteAsync(
            "DELETE FROM vibe_system.oidc_provider_role_mappings WHERE id = @Id",
            new { Id = id });
        return rows > 0;
    }

    #endregion

    #region ClientMappings

    public async Task<IEnumerable<OidcProviderClientMapping>> GetClientMappingsAsync(string providerKey)
    {
        using var conn = CreateConnection();
        return await conn.QueryAsync<OidcProviderClientMapping>(
            "SELECT * FROM vibe_system.oidc_provider_client_mappings WHERE provider_key = @ProviderKey ORDER BY id",
            new { ProviderKey = providerKey });
    }

    public async Task<OidcProviderClientMapping?> GetClientMappingByIdAsync(int id)
    {
        using var conn = CreateConnection();
        return await conn.QuerySingleOrDefaultAsync<OidcProviderClientMapping>(
            "SELECT * FROM vibe_system.oidc_provider_client_mappings WHERE id = @Id",
            new { Id = id });
    }

    public async Task<OidcProviderClientMapping?> GetActiveClientMappingAsync(string providerKey)
    {
        using var conn = CreateConnection();
        return await conn.QueryFirstOrDefaultAsync<OidcProviderClientMapping>(
            "SELECT * FROM vibe_system.oidc_provider_client_mappings WHERE provider_key = @ProviderKey AND is_active = TRUE LIMIT 1",
            new { ProviderKey = providerKey });
    }

    public async Task<OidcProviderClientMapping> InsertClientMappingAsync(OidcProviderClientMapping mapping)
    {
        using var conn = CreateConnection();
        var id = await conn.ExecuteScalarAsync<int>("""
            INSERT INTO vibe_system.oidc_provider_client_mappings
                (provider_key, vibe_client_id, is_active, max_permission)
            VALUES
                (@ProviderKey, @VibeClientId, @IsActive, @MaxPermission)
            RETURNING id
            """, mapping);

        return (await GetClientMappingByIdAsync(id))!;
    }

    public async Task<OidcProviderClientMapping?> UpdateClientMappingAsync(int id, Action<OidcProviderClientMapping> applyUpdates)
    {
        using var conn = CreateConnection();
        await conn.OpenAsync();
        using var tx = conn.BeginTransaction();

        var existing = await conn.QuerySingleOrDefaultAsync<OidcProviderClientMapping>(
            "SELECT * FROM vibe_system.oidc_provider_client_mappings WHERE id = @Id FOR UPDATE",
            new { Id = id }, tx);
        if (existing == null) return null;

        applyUpdates(existing);

        await conn.ExecuteAsync("""
            UPDATE vibe_system.oidc_provider_client_mappings SET
                vibe_client_id = @VibeClientId,
                is_active = @IsActive,
                max_permission = @MaxPermission
            WHERE id = @Id
            """, existing, tx);

        tx.Commit();

        return await conn.QuerySingleOrDefaultAsync<OidcProviderClientMapping>(
            "SELECT * FROM vibe_system.oidc_provider_client_mappings WHERE id = @Id",
            new { Id = id });
    }

    public async Task<bool> DeleteClientMappingAsync(int id)
    {
        using var conn = CreateConnection();
        var rows = await conn.ExecuteAsync(
            "DELETE FROM vibe_system.oidc_provider_client_mappings WHERE id = @Id",
            new { Id = id });
        return rows > 0;
    }

    #endregion

    #region FederatedIdentities

    public async Task<IEnumerable<FederatedIdentity>> GetFederatedIdentitiesAsync(int limit = 100, int offset = 0, string? providerKey = null)
    {
        using var conn = CreateConnection();
        if (!string.IsNullOrEmpty(providerKey))
        {
            return await conn.QueryAsync<FederatedIdentity>(
                "SELECT * FROM vibe_system.federated_identities WHERE provider_key = @ProviderKey ORDER BY id LIMIT @Limit OFFSET @Offset",
                new { ProviderKey = providerKey, Limit = limit, Offset = offset });
        }
        return await conn.QueryAsync<FederatedIdentity>(
            "SELECT * FROM vibe_system.federated_identities ORDER BY id LIMIT @Limit OFFSET @Offset",
            new { Limit = limit, Offset = offset });
    }

    public async Task<FederatedIdentity?> GetFederatedIdentityByIdAsync(int id)
    {
        using var conn = CreateConnection();
        return await conn.QuerySingleOrDefaultAsync<FederatedIdentity>(
            "SELECT * FROM vibe_system.federated_identities WHERE id = @Id",
            new { Id = id });
    }

    public async Task<FederatedIdentity?> GetFederatedIdentityAsync(string providerKey, string externalSubject)
    {
        using var conn = CreateConnection();
        return await conn.QuerySingleOrDefaultAsync<FederatedIdentity>(
            "SELECT * FROM vibe_system.federated_identities WHERE provider_key = @ProviderKey AND external_subject = @ExternalSubject",
            new { ProviderKey = providerKey, ExternalSubject = externalSubject });
    }

    public async Task<FederatedIdentity> InsertFederatedIdentityAsync(FederatedIdentity identity)
    {
        using var conn = CreateConnection();
        var id = await conn.ExecuteScalarAsync<int>("""
            INSERT INTO vibe_system.federated_identities
                (provider_key, external_subject, vibe_user_id, email, display_name, metadata)
            VALUES
                (@ProviderKey, @ExternalSubject, @VibeUserId, @Email, @DisplayName, CASE WHEN @Metadata IS NULL THEN NULL ELSE @Metadata::jsonb END)
            RETURNING id
            """, identity);

        return (await GetFederatedIdentityByIdAsync(id))!;
    }

    public async Task UpdateLastSeenAsync(int id)
    {
        using var conn = CreateConnection();
        await conn.ExecuteAsync(
            "UPDATE vibe_system.federated_identities SET last_seen_at = NOW() WHERE id = @Id",
            new { Id = id });
    }

    public async Task<int> NextVibeUserIdAsync()
    {
        using var conn = CreateConnection();
        return await conn.ExecuteScalarAsync<int>(
            "SELECT nextval('vibe_system.federated_user_id_seq')");
    }

    #endregion

    #region EdgeClientCredentials

    public async Task<IEnumerable<EdgeClientCredential>> GetAllCredentialsAsync()
    {
        using var conn = CreateConnection();
        return await conn.QueryAsync<EdgeClientCredential>(
            "SELECT * FROM vibe_system.edge_client_credentials ORDER BY id");
    }

    public async Task<EdgeClientCredential?> GetCredentialByIdAsync(int id)
    {
        using var conn = CreateConnection();
        return await conn.QuerySingleOrDefaultAsync<EdgeClientCredential>(
            "SELECT * FROM vibe_system.edge_client_credentials WHERE id = @Id",
            new { Id = id });
    }

    public async Task<EdgeClientCredential?> GetCredentialByClientIdAsync(string clientId)
    {
        using var conn = CreateConnection();
        return await conn.QuerySingleOrDefaultAsync<EdgeClientCredential>(
            "SELECT * FROM vibe_system.edge_client_credentials WHERE client_id = @ClientId AND is_active = TRUE",
            new { ClientId = clientId });
    }

    public async Task<EdgeClientCredential> InsertCredentialAsync(EdgeClientCredential credential)
    {
        using var conn = CreateConnection();
        var id = await conn.ExecuteScalarAsync<int>("""
            INSERT INTO vibe_system.edge_client_credentials
                (client_id, signing_key, display_name, is_active)
            VALUES
                (@ClientId, @SigningKey, @DisplayName, @IsActive)
            RETURNING id
            """, credential);

        return (await GetCredentialByIdAsync(id))!;
    }

    public async Task<EdgeClientCredential?> UpdateCredentialAsync(int id, Action<EdgeClientCredential> applyUpdates)
    {
        using var conn = CreateConnection();
        await conn.OpenAsync();
        using var tx = conn.BeginTransaction();

        var existing = await conn.QuerySingleOrDefaultAsync<EdgeClientCredential>(
            "SELECT * FROM vibe_system.edge_client_credentials WHERE id = @Id FOR UPDATE",
            new { Id = id }, tx);
        if (existing == null) return null;

        applyUpdates(existing);

        await conn.ExecuteAsync("""
            UPDATE vibe_system.edge_client_credentials SET
                display_name = @DisplayName,
                is_active = @IsActive,
                updated_at = NOW()
            WHERE id = @Id
            """, existing, tx);

        tx.Commit();

        return await conn.QuerySingleOrDefaultAsync<EdgeClientCredential>(
            "SELECT * FROM vibe_system.edge_client_credentials WHERE id = @Id",
            new { Id = id });
    }

    public async Task<bool> DeleteCredentialAsync(int id)
    {
        using var conn = CreateConnection();
        var rows = await conn.ExecuteAsync(
            "DELETE FROM vibe_system.edge_client_credentials WHERE id = @Id",
            new { Id = id });
        return rows > 0;
    }

    #endregion
}
