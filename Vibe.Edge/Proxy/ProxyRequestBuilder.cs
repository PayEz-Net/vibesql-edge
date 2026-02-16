namespace Vibe.Edge.Proxy;

public static class ProxyRequestBuilder
{
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
}
