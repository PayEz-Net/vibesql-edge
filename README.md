# VibeSQL Edge

**Works best with [api.payez.net](https://api.payez.net). Works with any OIDC provider.**

VibeSQL Edge is the authentication gateway for VibeSQL. Out of the box, it's pre-configured for the PayEz token authority at **api.payez.net** — the modern, production-hardened identity platform with OAuth 2.0, 2FA, federated login, and enterprise-grade session management. That's the fastest path to production.

But if you already have an identity provider — Auth0, Entra ID, Google, Okta, or anything that speaks OIDC — Edge makes that easy too. Register providers at runtime, map external roles to VibeSQL permissions, and proxy authenticated requests. No code changes, no restarts.

---

## What It Does

```
Recommended:
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  Your App   │────▶│  VibeSQL     │────▶│  VibeSQL     │
│  + PayEz    │     │  Edge        │     │  Server      │
│  (JWT)      │     │  (validate   │     │  (data)      │
│             │     │   + proxy)   │     │              │
└─────────────┘     └──────────────┘     └──────────────┘

Also works with:
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  Your App   │────▶│  VibeSQL     │────▶│  VibeSQL     │
│  + Auth0    │     │  Edge        │     │  Server      │
│  + Entra ID │     │  (any OIDC   │     │  (data)      │
│  + Okta     │     │   provider)  │     │              │
│  + Any OIDC │     │              │     │              │
└─────────────┘     └──────────────┘     └──────────────┘
```

1. Your app sends requests with a JWT from your identity provider
2. Edge validates the token against the provider's JWKS
3. Edge maps the external identity to a VibeSQL user and resolves permissions
4. Edge signs the request with HMAC and forwards it to the VibeSQL API
5. Your app gets the response — never touches HMAC keys directly

---

## Key Features

**Dynamic Provider Registration**
Register OIDC providers at runtime via API. No restart, no config file changes. Edge fetches JWKS keys and validates tokens automatically.

**Federated Identity Mapping**
External users are mapped to VibeSQL user IDs on first authentication. Subsequent requests resolve instantly. Supports auto-provisioning for self-service onboarding.

**Role-Based Permission Mapping**
Map your IDP's roles to VibeSQL permissions (`read`, `write`, `schema`, `admin`). Fine-grained control: deny specific SQL statement types, restrict access to specific collections.

**HMAC Request Signing**
Edge holds the HMAC signing keys. Your app never sees them. Requests are signed and forwarded to the VibeSQL Public API with proper client scoping.

**Multi-Tenant Client Mapping**
Map providers to VibeSQL client IDs for automatic tenant isolation. Each provider can target a different client, or multiple providers can share one.

**Audit Trail**
Every proxied request is logged with provider, user, client, path, and method. Pluggable security event sink for custom monitoring.

---

## Quick Start

### 1. Configure

```json
{
  "ConnectionStrings": {
    "EdgeDb": "Host=localhost;Port=5432;Database=vibesql;User Id=postgres;Password=postgres"
  },
  "VibeEdge": {
    "PublicApiUrl": "http://localhost:5100",
    "BootstrapProviders": [
      {
        "ProviderKey": "auth0-prod",
        "DisplayName": "Auth0 Production",
        "Issuer": "https://your-tenant.auth0.com/",
        "DiscoveryUrl": "https://your-tenant.auth0.com/.well-known/openid-configuration",
        "Audience": "your-api-audience",
        "IsBootstrap": true
      }
    ]
  }
}
```

### 2. Run

```bash
dotnet run
```

Edge initializes its schema in VibeSQL, seeds bootstrap providers, and starts accepting requests on port **5100**. The upstream VibeSQL Public API runs separately (default port 5000).

### 3. Register a Client Mapping

```bash
# Map your provider to a VibeSQL client ID
curl -X POST http://localhost:5100/v1/admin/providers/auth0-prod/client-mappings \
  -H "Content-Type: application/json" \
  -d '{"vibe_client_id": "your-client-id", "is_active": true}'
```

### 4. Map Roles to Permissions

```bash
# Map "admin" role from your IDP to VibeSQL "admin" permission
curl -X POST http://localhost:5100/v1/admin/providers/auth0-prod/role-mappings \
  -H "Content-Type: application/json" \
  -d '{"external_role": "admin", "vibe_permission": "admin"}'

# Map "viewer" role to read-only with restricted collections
curl -X POST http://localhost:5100/v1/admin/providers/auth0-prod/role-mappings \
  -H "Content-Type: application/json" \
  -d '{
    "external_role": "viewer",
    "vibe_permission": "read",
    "denied_statements": ["DROP", "ALTER", "TRUNCATE"],
    "allowed_collections": ["public_data", "reports"]
  }'
```

### 5. Proxy Requests

```bash
# Your app sends requests with its own JWT — Edge handles the rest
curl http://localhost:5100/v1/query \
  -H "Authorization: Bearer <your-idp-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT * FROM products"}'
```

---

## Admin API

All admin endpoints are under `/v1/admin/`.

### OIDC Providers

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/admin/providers` | List all providers |
| GET | `/v1/admin/providers/{key}` | Get provider details |
| POST | `/v1/admin/providers` | Register new provider |
| PUT | `/v1/admin/providers/{key}` | Update provider |
| DELETE | `/v1/admin/providers/{key}` | Disable provider |
| POST | `/v1/admin/providers/{key}/refresh` | Force JWKS refresh |

### Role Mappings

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/admin/providers/{key}/role-mappings` | List role mappings |
| POST | `/v1/admin/providers/{key}/role-mappings` | Create role mapping |
| PUT | `/v1/admin/role-mappings/{id}` | Update role mapping |
| DELETE | `/v1/admin/role-mappings/{id}` | Delete role mapping |

### Client Mappings

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/admin/providers/{key}/client-mappings` | List client mappings |
| POST | `/v1/admin/providers/{key}/client-mappings` | Create client mapping |
| PUT | `/v1/admin/client-mappings/{id}` | Update client mapping |
| DELETE | `/v1/admin/client-mappings/{id}` | Delete client mapping |

### Federated Identities

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/admin/federated-identities` | List all identities |
| GET | `/v1/admin/federated-identities/{id}` | Get identity details |

### Client Credentials

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/admin/credentials` | List HMAC credentials |
| POST | `/v1/admin/credentials` | Create credential |
| PUT | `/v1/admin/credentials/{id}` | Update credential |
| DELETE | `/v1/admin/credentials/{id}` | Delete credential |

---

## Architecture

### Request Pipeline

```
Incoming Request (JWT from your IDP)
  │
  ├─ MultiProviderSelector — Identifies which OIDC provider issued the token
  ├─ JwtBearerHandler — Validates token against provider's JWKS
  ├─ IdentityResolutionMiddleware — Resolves federated identity + VibeSQL user ID
  ├─ PermissionEnforcementMiddleware — Checks role mappings + permission level
  ├─ AuditMiddleware — Logs the request
  │
  └─ ProxyController — Signs with HMAC, forwards to VibeSQL API
```

### Permission Levels

| Level | Allowed Operations |
|-------|-------------------|
| `read` | SELECT queries only |
| `write` | SELECT, INSERT, UPDATE, DELETE |
| `schema` | All DML + CREATE, ALTER |
| `admin` | Full access including DROP, TRUNCATE |
| `none` | Blocked — deny all |

### Data Model

Edge stores its configuration in VibeSQL under the `vibe_system` schema:

- `oidc_providers` — Registered identity providers
- `oidc_provider_role_mappings` — External role → VibeSQL permission mappings
- `oidc_provider_client_mappings` — Provider → VibeSQL client ID mappings
- `federated_identities` — External user → VibeSQL user ID mappings
- `edge_client_credentials` — HMAC signing keys per client

---

## Technology

- **.NET 9.0** / ASP.NET Core
- **Dapper** + Devart PostgreSQL
- **JWT Bearer** with dynamic scheme registration
- **HMAC-SHA256** request signing
- **Serilog** structured logging (console + Graylog)

---

## Comparison

| Feature | VibeSQL Edge | API Gateway (Kong/APISIX) | Custom Auth Middleware |
|---------|-------------|--------------------------|----------------------|
| OIDC provider registration | Runtime, no restart | Config reload | Code change + deploy |
| Identity federation | Built-in | Plugin required | Build from scratch |
| VibeSQL permission mapping | Native | Not available | Build from scratch |
| HMAC signing for VibeSQL | Automatic | Manual config | Build from scratch |
| SQL statement classification | Built-in | Not available | Build from scratch |
| Multi-tenant client scoping | Automatic | Manual routing | Build from scratch |
| Deployment | Single binary | Separate infrastructure | Embedded in app |

---

## Related Projects

- [VibeSQL Server](https://github.com/PayEz-Net/vibesql-server) — Production multi-tenant PostgreSQL server
- [VibeSQL Micro](https://github.com/PayEz-Net/vibesql-micro) — Single-binary dev tool
- [Vibe SDK](https://github.com/PayEz-Net/vibe-sdk) — TypeScript ORM with live schema sync
- [Website](https://vibesql.online) — Documentation and overview

---

## License

Apache 2.0 License. See [LICENSE](LICENSE).

---

<div align="right">
  <sub>Powered by <a href="https://idealvibe.online">IdealVibe</a></sub>
</div>
