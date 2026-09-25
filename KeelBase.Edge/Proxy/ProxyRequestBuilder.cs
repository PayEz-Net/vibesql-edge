namespace KeelBase.Edge.Proxy;

using KeelBase.Edge.Identity;

public static class ProxyRequestBuilder
{
    /// <summary>
    /// Build a proxy request using HMAC authentication headers.
    /// This is the default mode for edge/DMZ deployments.
    /// </summary>
    public static HttpRequestMessage Build(
        HttpRequest originalRequest,
        string targetUrl,
        string vibeClientId,
        string timestamp,
        string signature,
        int vibeUserId,
        string viaHeader,
        byte[]? bodyBytes = null,
        ResolvedCaller? caller = null)
    {
        var method = new HttpMethod(originalRequest.Method);
        var request = new HttpRequestMessage(method, targetUrl);

        // TS-10: authoritative identity headers. The data server must ignore X-Keel-* on any request
        // that is not authenticated as Edge (HMAC signature below); they are only trustworthy because
        // this request carries that proof.
        ApplyCallerIdentity(originalRequest, request, caller);

        request.Headers.Add("X-Vibe-Client-Id", vibeClientId);
        request.Headers.Add("X-Vibe-Timestamp", timestamp);
        request.Headers.Add("X-Vibe-Signature", signature);
        request.Headers.Add("X-Vibe-User-Id", vibeUserId.ToString());
        request.Headers.Add("X-Vibe-Via", viaHeader);

        if (originalRequest.Headers.TryGetValue("Authorization", out var authHeader))
        {
            var authValue = authHeader.FirstOrDefault();
            if (!string.IsNullOrEmpty(authValue))
            {
                request.Headers.TryAddWithoutValidation("Authorization", authValue);
            }
        }

        if (bodyBytes != null && bodyBytes.Length > 0)
        {
            request.Content = new ByteArrayContent(bodyBytes);
            if (originalRequest.ContentType != null)
            {
                request.Content.Headers.ContentType =
                    System.Net.Http.Headers.MediaTypeHeaderValue.Parse(originalRequest.ContentType);
            }
        }

        return request;
    }

    /// <summary>
    /// Build a proxy request using container secret authentication.
    /// Used for internal/k8s deployments where the upstream KeelBase Server
    /// is configured with KeelBaseSQL:AuthMode=secret.
    /// </summary>
    public static HttpRequestMessage BuildWithSecret(
        HttpRequest originalRequest,
        string targetUrl,
        string containerSecret,
        string vibeClientId,
        int vibeUserId,
        string viaHeader,
        byte[]? bodyBytes = null,
        ResolvedCaller? caller = null)
    {
        var method = new HttpMethod(originalRequest.Method);
        var request = new HttpRequestMessage(method, targetUrl);

        // TS-10: authoritative identity headers (see Build for why the data server may trust them).
        ApplyCallerIdentity(originalRequest, request, caller);

        request.Headers.Add("X-Vibe-Client-Id", vibeClientId);
        request.Headers.Add("X-Vibe-User-Id", vibeUserId.ToString());
        request.Headers.Add("X-Vibe-Via", viaHeader);

        request.Headers.TryAddWithoutValidation("Authorization", $"Secret {containerSecret}");

        if (bodyBytes != null && bodyBytes.Length > 0)
        {
            request.Content = new ByteArrayContent(bodyBytes);
            if (originalRequest.ContentType != null)
            {
                request.Content.Headers.ContentType =
                    System.Net.Http.Headers.MediaTypeHeaderValue.Parse(originalRequest.ContentType);
            }
        }

        return request;
    }

    /// <summary>
    /// TS-10: strip every client-supplied X-Keel-* header so a caller can never forge identity to the
    /// data server, then set the authoritative values from the resolved caller. Null values are omitted.
    /// </summary>
    private static void ApplyCallerIdentity(HttpRequest originalRequest, HttpRequestMessage request, ResolvedCaller? caller)
    {
        foreach (var headerName in originalRequest.Headers.Keys
                     .Where(k => k.StartsWith("X-Keel-", StringComparison.OrdinalIgnoreCase))
                     .ToList())
        {
            originalRequest.Headers.Remove(headerName);
        }

        if (caller == null)
        {
            return;
        }

        // The tenant router resolves tenants by provider key, so for user and customer-IdP callers the
        // provider key IS the tenant client id; anonymous publishable-key callers set TenantClientId.
        var tenant = caller.TenantClientId ?? caller.ProviderKey;

        var role = caller.CallerType switch
        {
            CallerType.Anonymous => "anon",
            CallerType.Service => "service",
            _ => "authenticated"
        };

        AddIfPresent(request, "X-Keel-Tenant", tenant);
        AddIfPresent(request, "X-Keel-User", caller.UserId);
        AddIfPresent(request, "X-Keel-Agent", caller.AgentId);
        AddIfPresent(request, "X-Keel-Role", role);
        AddIfPresent(request, "X-Keel-Caller-Type", caller.CallerType.ToString().ToLowerInvariant());
    }

    private static void AddIfPresent(HttpRequestMessage request, string name, string? value)
    {
        if (!string.IsNullOrEmpty(value))
        {
            request.Headers.Add(name, value);
        }
    }
}
