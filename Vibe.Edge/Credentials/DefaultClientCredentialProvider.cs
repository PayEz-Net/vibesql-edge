using System.Collections.Concurrent;
using Vibe.Edge.Data;

namespace Vibe.Edge.Credentials;

public class DefaultClientCredentialProvider : IClientCredentialProvider
{
    private readonly VibeDataService _dataService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<DefaultClientCredentialProvider> _logger;
    private readonly ConcurrentDictionary<string, (string Key, DateTime Expires)> _cache = new();

    public DefaultClientCredentialProvider(
        VibeDataService dataService,
        IConfiguration configuration,
        ILogger<DefaultClientCredentialProvider> logger)
    {
        _dataService = dataService;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<string?> GetSigningKeyAsync(string clientId)
    {
        if (_cache.TryGetValue(clientId, out var cached) && cached.Expires > DateTime.UtcNow)
        {
            return cached.Key;
        }

        var credential = await _dataService.GetCredentialByClientIdAsync(clientId);
        if (credential == null)
        {
            _logger.LogWarning("EDGE_CREDENTIAL: No active credential found for client {ClientId}", clientId);
            _cache.TryRemove(clientId, out _);
            return null;
        }

        var ttlMinutes = _configuration.GetValue("VibeEdge:SigningKeyCacheTtlMinutes", 5);
        _cache[clientId] = (credential.SigningKey, DateTime.UtcNow.AddMinutes(ttlMinutes));

        return credential.SigningKey;
    }

    public void InvalidateCache(string clientId)
    {
        _cache.TryRemove(clientId, out _);
    }
}
