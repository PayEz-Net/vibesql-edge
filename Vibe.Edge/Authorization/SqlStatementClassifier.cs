using Vibe.Edge.Models;

namespace Vibe.Edge.Authorization;

public static class SqlStatementClassifier
{
    private static readonly Dictionary<string, PermissionLevel> KeywordMap = new(StringComparer.OrdinalIgnoreCase)
    {
        ["SELECT"] = PermissionLevel.Read,
        ["SHOW"] = PermissionLevel.Read,
        ["INSERT"] = PermissionLevel.Write,
        ["UPDATE"] = PermissionLevel.Write,
        ["DELETE"] = PermissionLevel.Write,
        ["UPSERT"] = PermissionLevel.Write,
        ["MERGE"] = PermissionLevel.Write,
        ["COPY"] = PermissionLevel.Write,
        ["CREATE"] = PermissionLevel.Schema,
        ["ALTER"] = PermissionLevel.Schema,
        ["DROP"] = PermissionLevel.Schema,
        ["TRUNCATE"] = PermissionLevel.Admin,
        ["GRANT"] = PermissionLevel.Admin,
        ["REVOKE"] = PermissionLevel.Admin,
        ["VACUUM"] = PermissionLevel.Admin,
        ["REINDEX"] = PermissionLevel.Admin,
    };

    public enum ClassifyResult
    {
        Ok,
        MultiStatement,
        Unrecognized
    }

    public static (ClassifyResult Result, PermissionLevel Level, string? Keyword) Classify(string sql)
    {
        var stripped = StripLeadingComments(sql).TrimStart();

        if (ContainsMultiStatement(stripped))
            return (ClassifyResult.MultiStatement, PermissionLevel.None, null);

        var firstKeyword = GetFirstKeyword(stripped);
        if (string.IsNullOrEmpty(firstKeyword))
            return (ClassifyResult.Unrecognized, PermissionLevel.None, null);

        if (firstKeyword.Equals("EXPLAIN", StringComparison.OrdinalIgnoreCase))
        {
            var rest = stripped[firstKeyword.Length..].TrimStart();
            if (rest.StartsWith("ANALYZE", StringComparison.OrdinalIgnoreCase) ||
                rest.StartsWith("(", StringComparison.OrdinalIgnoreCase))
            {
                var afterOptions = SkipExplainOptions(rest);
                var innerKeyword = GetFirstKeyword(afterOptions);
                if (innerKeyword != null && KeywordMap.TryGetValue(innerKeyword, out var innerLevel))
                    return (ClassifyResult.Ok, innerLevel, innerKeyword);
            }
            else
            {
                var innerKeyword = GetFirstKeyword(rest);
                if (innerKeyword != null && KeywordMap.TryGetValue(innerKeyword, out var innerLevel))
                    return (ClassifyResult.Ok, innerLevel, innerKeyword);
            }
            return (ClassifyResult.Unrecognized, PermissionLevel.None, "EXPLAIN");
        }

        if (firstKeyword.Equals("WITH", StringComparison.OrdinalIgnoreCase))
        {
            var terminalKeyword = FindCteTerminalKeyword(stripped);
            if (terminalKeyword != null && KeywordMap.TryGetValue(terminalKeyword, out var cteLevel))
                return (ClassifyResult.Ok, cteLevel, terminalKeyword);
            return (ClassifyResult.Unrecognized, PermissionLevel.None, "WITH");
        }

        if (firstKeyword.Equals("DROP", StringComparison.OrdinalIgnoreCase))
        {
            var rest = stripped[firstKeyword.Length..].TrimStart();
            var secondKeyword = GetFirstKeyword(rest);
            if (secondKeyword != null &&
                (secondKeyword.Equals("SCHEMA", StringComparison.OrdinalIgnoreCase) ||
                 secondKeyword.Equals("DATABASE", StringComparison.OrdinalIgnoreCase)))
            {
                return (ClassifyResult.Ok, PermissionLevel.Admin, "DROP SCHEMA");
            }
            return (ClassifyResult.Ok, PermissionLevel.Schema, "DROP");
        }

        if (firstKeyword.Equals("CREATE", StringComparison.OrdinalIgnoreCase))
        {
            var rest = stripped[firstKeyword.Length..].TrimStart();
            var secondKeyword = GetFirstKeyword(rest);
            if (secondKeyword != null &&
                secondKeyword.Equals("SCHEMA", StringComparison.OrdinalIgnoreCase))
            {
                return (ClassifyResult.Ok, PermissionLevel.Admin, "CREATE SCHEMA");
            }
        }

        if (KeywordMap.TryGetValue(firstKeyword, out var level))
            return (ClassifyResult.Ok, level, firstKeyword);

        return (ClassifyResult.Unrecognized, PermissionLevel.None, firstKeyword);
    }

    private static string StripLeadingComments(string sql)
    {
        var i = 0;
        while (i < sql.Length)
        {
            while (i < sql.Length && char.IsWhiteSpace(sql[i])) i++;

            if (i + 1 < sql.Length && sql[i] == '-' && sql[i + 1] == '-')
            {
                while (i < sql.Length && sql[i] != '\n') i++;
                continue;
            }

            if (i + 1 < sql.Length && sql[i] == '/' && sql[i + 1] == '*')
            {
                i += 2;
                while (i + 1 < sql.Length && !(sql[i] == '*' && sql[i + 1] == '/')) i++;
                if (i + 1 < sql.Length) i += 2;
                continue;
            }

            break;
        }

        return i < sql.Length ? sql[i..] : string.Empty;
    }

    private static bool ContainsMultiStatement(string sql)
    {
        var inSingleQuote = false;
        var inDoubleQuote = false;

        for (var i = 0; i < sql.Length; i++)
        {
            var c = sql[i];

            if (c == '\'' && !inDoubleQuote)
            {
                if (i + 1 < sql.Length && sql[i + 1] == '\'')
                    { i++; continue; }
                inSingleQuote = !inSingleQuote;
                continue;
            }

            if (c == '"' && !inSingleQuote)
            {
                inDoubleQuote = !inDoubleQuote;
                continue;
            }

            if (c == ';' && !inSingleQuote && !inDoubleQuote)
            {
                var rest = sql[(i + 1)..].TrimEnd();
                if (rest.Length > 0)
                    return true;
            }
        }

        return false;
    }

    private static string? GetFirstKeyword(string sql)
    {
        var i = 0;
        while (i < sql.Length && char.IsWhiteSpace(sql[i])) i++;
        var start = i;
        while (i < sql.Length && char.IsLetterOrDigit(sql[i]) || (i < sql.Length && sql[i] == '_')) i++;
        if (i == start) return null;
        return sql[start..i];
    }

    private static string SkipExplainOptions(string rest)
    {
        var trimmed = rest.TrimStart();
        if (trimmed.StartsWith('('))
        {
            var depth = 1;
            var i = 1;
            while (i < trimmed.Length && depth > 0)
            {
                if (trimmed[i] == '(') depth++;
                else if (trimmed[i] == ')') depth--;
                i++;
            }
            return trimmed[i..].TrimStart();
        }

        if (trimmed.StartsWith("ANALYZE", StringComparison.OrdinalIgnoreCase))
        {
            return trimmed[7..].TrimStart();
        }

        return trimmed;
    }

    private static string? FindCteTerminalKeyword(string sql)
    {
        var depth = 0;
        var i = 0;
        var foundWith = false;

        while (i < sql.Length)
        {
            while (i < sql.Length && char.IsWhiteSpace(sql[i])) i++;

            if (!foundWith)
            {
                var kw = ReadKeywordAt(sql, i);
                if (kw != null && kw.Equals("WITH", StringComparison.OrdinalIgnoreCase))
                {
                    foundWith = true;
                    i += kw.Length;
                    continue;
                }
                return null;
            }

            if (i < sql.Length && sql[i] == '(')
            {
                depth++;
                i++;
                continue;
            }

            if (i < sql.Length && sql[i] == ')')
            {
                depth--;
                i++;
                continue;
            }

            if (depth == 0)
            {
                var kw = ReadKeywordAt(sql, i);
                if (kw != null && KeywordMap.ContainsKey(kw))
                    return kw;
                if (kw != null)
                {
                    i += kw.Length;
                    continue;
                }
            }

            i++;
        }

        return null;
    }

    private static string? ReadKeywordAt(string sql, int pos)
    {
        if (pos >= sql.Length || !char.IsLetter(sql[pos])) return null;
        var start = pos;
        while (pos < sql.Length && (char.IsLetterOrDigit(sql[pos]) || sql[pos] == '_')) pos++;
        return sql[start..pos];
    }
}
