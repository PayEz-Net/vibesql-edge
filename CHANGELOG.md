# Changelog

## 2026-03-13

### Added
- **Upstream auth: container secret support** — Edge can now authenticate to upstream VibeSQL Server using `Authorization: Secret {key}` instead of HMAC signing
- Config-driven upstream auth mode: `VibeSQL:UpstreamAuthMode` = "hmac" (default) or "secret"
- `BuildWithSecret()` method on `ProxyRequestBuilder` for secret-mode upstream calls

### Unchanged
- HMAC signing for external client authentication (Edge's own inbound auth) — no changes
- Default upstream auth mode remains HMAC for backwards compatibility

## 2026-02-12

### Fixed
- README: corrected API paths, added missing setup steps, documented auth + rate limiting
- DI lifetime, thread safety, auto-provision role, admin attribute, operator precedence, AllowAnonymous (Review Round 12)
- Removed `signing_key` from `UpdateCredentialAsync` SQL

## 2026-01-20

### Added
- Initial Vibe.Edge release
- HMAC-signed proxy to upstream VibeSQL Server
- Client credential auto-provisioning
- JWT validation via external IDP
- Rate limiting per client tier
- PostgreSQL-backed credential store
