namespace Vibe.Edge.Models;

public enum PermissionLevel
{
    None = 0,
    Read = 1,
    Write = 2,
    Schema = 3,
    Admin = 4
}

public static class PermissionLevelExtensions
{
    public static PermissionLevel Parse(string? value)
    {
        return value?.ToLowerInvariant() switch
        {
            "none" => PermissionLevel.None,
            "read" => PermissionLevel.Read,
            "write" => PermissionLevel.Write,
            "schema" => PermissionLevel.Schema,
            "admin" => PermissionLevel.Admin,
            _ => PermissionLevel.None
        };
    }

    public static string ToDbValue(this PermissionLevel level)
    {
        return level switch
        {
            PermissionLevel.None => "none",
            PermissionLevel.Read => "read",
            PermissionLevel.Write => "write",
            PermissionLevel.Schema => "schema",
            PermissionLevel.Admin => "admin",
            _ => "none"
        };
    }
}
