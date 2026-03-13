namespace Vibe.Edge.Proxy;

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
        byte[]? bodyBytes = null)
    {
        var method = new HttpMethod(originalRequest.Method);
        var request = new HttpRequestMessage(method, targetUrl);

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
    /// Used for internal/k8s deployments where the upstream VibeSQL Server
    /// is configured with VibeSQL:AuthMode=secret.
    /// </summary>
    public static HttpRequestMessage BuildWithSecret(
        HttpRequest originalRequest,
        string targetUrl,
        string containerSecret,
        string vibeClientId,
        int vibeUserId,
        string viaHeader,
        byte[]? bodyBytes = null)
    {
        var method = new HttpMethod(originalRequest.Method);
        var request = new HttpRequestMessage(method, targetUrl);

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
}
