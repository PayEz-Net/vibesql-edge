using Vibe.Edge.Data;
using Vibe.Edge.Models;

namespace Vibe.Edge.Authorization;

public class PermissionResolver
{
    private readonly VibeDataService _dataService;
    private readonly ILogger<PermissionResolver> _logger;

    public PermissionResolver(VibeDataService dataService, ILogger<PermissionResolver> logger)
    {
        _dataService = dataService;
        _logger = logger;
    }

    public async Task<PermissionResult> ResolveAsync(string providerKey, IEnumerable<string> roles)
    {
        var roleMappings = (await _dataService.GetRoleMappingsByRolesAsync(providerKey, roles)).ToList();

        if (roleMappings.Count == 0)
        {
            return new PermissionResult
            {
                EffectiveLevel = PermissionLevel.None,
                DeniedStatements = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            };
        }

        var highestLevel = PermissionLevel.None;
        var allDenied = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var mapping in roleMappings)
        {
            var level = PermissionLevelExtensions.Parse(mapping.VibePermission);
            if (level > highestLevel)
                highestLevel = level;

            if (mapping.DeniedStatements != null)
            {
                foreach (var denied in mapping.DeniedStatements)
                    allDenied.Add(denied);
            }
        }

        return new PermissionResult
        {
            EffectiveLevel = highestLevel,
            DeniedStatements = allDenied
        };
    }

    public async Task<PermissionResult> ResolveWithCapAsync(string providerKey, IEnumerable<string> roles)
    {
        var result = await ResolveAsync(providerKey, roles);

        var clientMapping = await _dataService.GetActiveClientMappingAsync(providerKey);
        if (clientMapping != null)
        {
            var cap = PermissionLevelExtensions.Parse(clientMapping.MaxPermission);
            if (result.EffectiveLevel > cap)
            {
                _logger.LogInformation(
                    "EDGE_PERMISSION: Capped permission from {Actual} to {Cap} for provider {Provider}",
                    result.EffectiveLevel, cap, providerKey);
                result.EffectiveLevel = cap;
            }
        }

        return result;
    }
}

public class PermissionResult
{
    public PermissionLevel EffectiveLevel { get; set; }
    public ISet<string> DeniedStatements { get; set; } = new HashSet<string>();
}
