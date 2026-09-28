namespace KeelBase.Edge.Meta;

public static class PgToTsTypeMapper
{
    public static string Map(string pgType, bool isNullable)
    {
        var tsType = MapBase(pgType);
        return isNullable ? $"{tsType} | null" : tsType;
    }

    private static string MapBase(string pgType)
    {
        var t = pgType.ToLowerInvariant().TrimEnd('[', ']');
        bool isArray = pgType.TrimEnd().EndsWith("[]");
        var mapped = t switch
        {
            "text" or "varchar" or "character varying" or "char" or "bpchar" or "uuid" or "name" or "citext" => "string",
            "smallint" or "int2" or "integer" or "int" or "int4" or "bigint" or "int8"
                or "numeric" or "decimal" or "real" or "float4" or "double precision" or "float8" => "number",
            "boolean" or "bool" => "boolean",
            "json" or "jsonb" => "unknown",
            "timestamp" or "timestamp without time zone" or "timestamp with time zone" or "timestamptz"
                or "date" or "time" or "time without time zone" or "time with time zone" or "timetz" => "string",
            _ => $"unknown /* {pgType} */"
        };
        return isArray ? $"{mapped}[]" : mapped;
    }
}
