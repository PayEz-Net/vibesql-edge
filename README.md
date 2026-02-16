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
│  (JWT)      │     │  (:5100)     │     │  (:5000)     │
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

1. Your app sends requests with a JWT from your identity provider to **Edge** (:5100)
2. Edge validates the token against the registered provider's JWKS
3. Edge maps the external identity to a VibeSQL user and resolves permissions
4. Edge signs the request with HMAC and forwards it to VibeSQL **Server** (:5000)
5. Your app gets the response — never touches HMAC keys directly

---

## Key Features

**Dynamic Provider Registration**
Register OIDC providers at runtime via API. No restart, no config file changes. Edge fetches JWKS keys and validates tokens automatically. Refreshes every 30 minutes.

**Federated Identity Mapping**
External users are mapped to VibeSQL user IDs on first authentication. Subsequent requests resolve instantly. Supports auto-provisioning for self-service onboarding.

**Role-Based Permission Mapping**
Map your IDP's roles to VibeSQL permissions (`read`, `write`, `schema`, `admin`). Fine-grained control: deny specific SQL statement types, restrict access to specific collections.

**HMAC Request Signing**
Edge holds the HMAC signing keys. Your app never sees them. Requests are signed and forwarded to the VibeSQL Public API with proper client scoping.

**Multi-Tenant Client Mapping**
Map providers to VibeSQL client IDs for automatic tenant isolation. Each provider can target a different client, or multiple providers can share one.

**Rate Limiting**
Built-in rate limiting at three levels: 500 req/min global, 200 req/min per provider (proxy), 30 req/min per IP (admin).

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
    "PublicApiUrl": "http://localhost:5000",
    "AdminApiKey": "your-admin-secret-here",
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

> **Note:** `PublicApiUrl` is the **upstream** VibeSQL Server (default :5000). Edge itself listens on :5100. Do not point Edge at its own port.

### 2. Run

```bash
dotnet run
```

Edge initializes its schema in VibeSQL, seeds bootstrap providers, and starts accepting requests on port **5100**. The upstream VibeSQL Public API runs separately on port **5000**.

### 3. Register HMAC Credentials

Before Edge can proxy requests, it needs an HMAC signing key for the target VibeSQL client:

```bash
curl -X POST http://localhost:5100/v1/admin/credentials \
  -H "Content-Type: application/json" \
  -H "X-Edge-Admin-Key: your-admin-secret-here" \
  -d '{"client_id": "your-client-id", "signing_key": "your-hmac-secret", "display_name": "Production"}'
```

### 4. Register a Client Mapping

```bash
# Map your OIDC provider to a VibeSQL client ID
curl -X POST http://localhost:5100/v1/admin/oidc-providers/auth0-prod/clients \
  -H "Content-Type: application/json" \
  -H "X-Edge-Admin-Key: your-admin-secret-here" \
  -d '{"vibe_client_id": "your-client-id", "is_active": true}'
```

### 5. Map Roles to Permissions

```bash
# Map "admin" role from your IDP to VibeSQL "admin" permission
curl -X POST http://localhost:5100/v1/admin/oidc-providers/auth0-prod/roles \
  -H "Content-Type: application/json" \
  -H "X-Edge-Admin-Key: your-admin-secret-here" \
  -d '{"external_role": "admin", "vibe_permission": "admin"}'

# Map "viewer" role to read-only with restricted collections
curl -X POST http://localhost:5100/v1/admin/oidc-providers/auth0-prod/roles \
  -H "Content-Type: application/json" \
  -H "X-Edge-Admin-Key: your-admin-secret-here" \
  -d '{
    "external_role": "viewer",
    "vibe_permission": "read",
    "denied_statements": ["DROP", "ALTER", "TRUNCATE"],
    "allowed_collections": ["public_data", "reports"]
  }'
```

### 6. Proxy Requests

```bash
# Your app sends requests with its own JWT — Edge handles the rest
curl http://localhost:5100/v1/query \
  -H "Authorization: Bearer <your-idp-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"sql": "SELECT * FROM products"}'
```

---

## Admin API

All admin endpoints require authentication via `X-Edge-Admin-Key` header or a JWT with admin-level permissions. Rate limited to 30 requests/minute per IP.

### OIDC Providers

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/admin/oidc-providers` | List all providers |
| POST | `/v1/admin/oidc-providers` | Register new provider |
| GET | `/v1/admin/oidc-providers/{key}` | Get provider details |
| PUT | `/v1/admin/oidc-providers/{key}` | Update provider |
| DELETE | `/v1/admin/oidc-providers/{key}` | Disable provider (soft delete) |
| POST | `/v1/admin/oidc-providers/{key}/test` | Test provider connectivity (JWKS fetch) |
| POST | `/v1/admin/oidc-providers/{key}/refresh` | Force JWKS refresh |

### Role Mappings

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/admin/oidc-providers/{key}/roles` | List role mappings |
| POST | `/v1/admin/oidc-providers/{key}/roles` | Create role mapping |
| PUT | `/v1/admin/oidc-providers/{key}/roles/{id}` | Update role mapping |
| DELETE | `/v1/admin/oidc-providers/{key}/roles/{id}` | Delete role mapping |

### Client Mappings

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/admin/oidc-providers/{key}/clients` | List client mappings |
| POST | `/v1/admin/oidc-providers/{key}/clients` | Create client mapping |
| PUT | `/v1/admin/oidc-providers/{key}/clients/{id}` | Update client mapping |
| DELETE | `/v1/admin/oidc-providers/{key}/clients/{id}` | Delete client mapping |

### Federated Identities

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/admin/federated-identities` | List identities (supports `limit`, `offset`, `provider_key`) |
| GET | `/v1/admin/federated-identities/{id}` | Get identity details |

### Client Credentials

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/admin/credentials` | List HMAC credentials (keys masked) |
| POST | `/v1/admin/credentials` | Create credential |
| PUT | `/v1/admin/credentials/{id}` | Update credential |
| DELETE | `/v1/admin/credentials/{id}` | Delete credential |

### Health

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health/providers` | None | Check all provider JWKS reachability |

---

## Architecture

### Request Pipeline

```
Incoming Request (JWT from your IDP)
  │
  ├─ RateLimiter — 500/min global, 200/min per provider
  ├─ MultiProviderSelector — Identifies which OIDC provider issued the token
  ├─ JwtBearerHandler — Validates token against provider's JWKS
  ├─ IdentityResolutionMiddleware — Resolves federated identity + VibeSQL user ID
  ├─ PermissionEnforcementMiddleware — Checks role mappings + SQL statement classification
  ├─ AuditMiddleware — Logs the request with security event details
  │
  └─ ProxyController — Signs with HMAC, forwards to VibeSQL Server (:5000)
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
| Rate limiting | Built-in (3 tiers) | Built-in | Build from scratch |
| Deployment | Single binary | Separate infrastructure | Embedded in app |

---

## Related Projects

- [VibeSQL Server](https://github.com/PayEz-Net/vibesql-server) — Production multi-tenant PostgreSQL server
- [VibeSQL Micro](https://github.com/PayEz-Net/vibesql-micro) — Single-binary dev tool
- [VibeSQL Audit](https://github.com/PayEz-Net/vibesql-audit) — PCI DSS compliant audit logging
- [Vibe SDK](https://github.com/PayEz-Net/vibe-sdk) — TypeScript ORM with live schema sync
- [Website](https://vibesql.online) — Documentation and overview

---

## License

Apache 2.0 License. See [LICENSE](LICENSE).

---

<div align="right">
  <sub>Powered by <a href="https://idealvibe.online">IdealVibe</a></sub>
</div>
