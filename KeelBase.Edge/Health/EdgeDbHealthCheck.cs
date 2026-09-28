using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;

namespace KeelBase.Edge.Health;

/// <summary>
/// TS-10: readiness check - SELECT 1 against the EdgeDb connection string.
/// Written locally because AddNpgsql(...) would require a new NuGet package.
/// </summary>
public class EdgeDbHealthCheck : IHealthCheck
{
    private readonly string _connectionString;

    public EdgeDbHealthCheck(string connectionString) => _connectionString = connectionString;

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var conn = new NpgsqlConnection(_connectionString);
            await conn.OpenAsync(cancellationToken);
            await using var cmd = new NpgsqlCommand("SELECT 1", conn);
            await cmd.ExecuteScalarAsync(cancellationToken);
            return HealthCheckResult.Healthy("ready");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("db", ex);
        }
    }
}
