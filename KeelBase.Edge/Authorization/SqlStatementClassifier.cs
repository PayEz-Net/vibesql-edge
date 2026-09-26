using KeelBase.Edge.Models;

namespace KeelBase.Edge.Authorization;

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

        // R16 (QAPert 65084): `SELECT ... INTO t2 FROM t` creates a table but the leading keyword is
        // SELECT, so it used to classify Read. Treat a top-level INTO in a SELECT as Schema (DDL).
        if (IsSelectInto(stripped))
            return (ClassifyResult.Ok, PermissionLevel.Schema, "SELECT INTO");

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
            // skip whitespace
            while (i < sql.Length && char.IsWhiteSpace(sql[i])) i++;
            if (i >= sql.Length) break;

            // line comment: -- to end of line
            if (i + 1 < sql.Length && sql[i] == '-' && sql[i + 1] == '-')
            {
                while (i < sql.Length && sql[i] != '\n') i++;
                continue;
            }

            // block comment: /* ... */, NESTED per Postgres (R13, QAPert 65084)
            if (i + 1 < sql.Length && sql[i] == '/' && sql[i + 1] == '*')
            {
                i = SkipBlockComment(sql, i);
                continue;
            }

            break;
        }

        return i < sql.Length ? sql[i..] : string.Empty;
    }

    /// <summary>Skip a (possibly nested) block comment starting at <paramref name="i"/> (which points at "/*").
    /// Returns the index just past the matching "*/", or sql.Length if unterminated.</summary>
    private static int SkipBlockComment(string sql, int i)
    {
        var depth = 0;
        while (i < sql.Length)
        {
            if (i + 1 < sql.Length && sql[i] == '/' && sql[i + 1] == '*')
            {
                depth++;
                i += 2;
                continue;
            }
            if (i + 1 < sql.Length && sql[i] == '*' && sql[i + 1] == '/')
            {
                depth--;
                i += 2;
                if (depth == 0) return i;
                continue;
            }
            i++;
        }
        return i;
    }

    private static bool ContainsMultiStatement(string sql)
    {
        var i = 0;
        while (i < sql.Length)
        {
            var c = sql[i];

            // line comment
            if (c == '-' && i + 1 < sql.Length && sql[i + 1] == '-')
            {
                while (i < sql.Length && sql[i] != '\n') i++;
                continue;
            }

            // block comment (nested)
            if (c == '/' && i + 1 < sql.Length && sql[i + 1] == '*')
            {
                i = SkipBlockComment(sql, i);
                continue;
            }

            // double-quoted identifier: "" is an escaped quote inside
            if (c == '"')
            {
                i++;
                while (i < sql.Length)
                {
                    if (sql[i] == '"' && i + 1 < sql.Length && sql[i + 1] == '"') { i += 2; continue; }
                    if (sql[i] == '"') { i++; break; }
                    i++;
                }
                continue;
            }

            // dollar-quoted string: $tag$ ... $tag$ (tag may be empty)
            if (c == '$')
            {
                var tagEnd = i + 1;
                while (tagEnd < sql.Length && (char.IsLetterOrDigit(sql[tagEnd]) || sql[tagEnd] == '_')) tagEnd++;
                if (tagEnd < sql.Length && sql[tagEnd] == '$')
                {
                    var tag = sql[i..(tagEnd + 1)]; // includes both $...$
                    var close = sql.IndexOf(tag, tagEnd + 1, StringComparison.Ordinal);
                    i = close < 0 ? sql.Length : close + tag.Length;
                    continue;
                }
            }

            // single-quoted string, with E'\'' backslash escapes when preceded by E/e
            if (c == '\'')
            {
                var isEString = i > 0 && (sql[i - 1] == 'E' || sql[i - 1] == 'e');
                i++;
                while (i < sql.Length)
                {
                    if (isEString && sql[i] == '\\' && i + 1 < sql.Length) { i += 2; continue; }
                    if (sql[i] == '\'' && i + 1 < sql.Length && sql[i + 1] == '\'') { i += 2; continue; }
                    if (sql[i] == '\'') { i++; break; }
                    i++;
                }
                continue;
            }

            // multi-statement separator
            if (c == ';')
            {
                var rest = sql[(i + 1)..].TrimEnd();
                if (rest.Length > 0)
                    return true;
            }

            i++;
        }

        return false;
    }

    /// <summary>R16: a top-level INTO in a SELECT (SELECT ... INTO new_table ...). Scans outside strings/comments
    /// and only at bracket depth 0, so `SELECT * FROM t WHERE x IN (SELECT ...)` is untouched.</summary>
    private static bool IsSelectInto(string sql)
    {
        var firstKeyword = GetFirstKeyword(sql);
        if (firstKeyword == null || !firstKeyword.Equals("SELECT", StringComparison.OrdinalIgnoreCase))
            return false;

        var i = 0;
        var depth = 0;
        while (i < sql.Length)
        {
            var c = sql[i];

            if (c == '-' && i + 1 < sql.Length && sql[i + 1] == '-')
            {
                while (i < sql.Length && sql[i] != '\n') i++;
                continue;
            }
            if (c == '/' && i + 1 < sql.Length && sql[i + 1] == '*')
            {
                i = SkipBlockComment(sql, i);
                continue;
            }
            if (c == '"' || c == '\'')
            {
                i = SkipQuoted(sql, i, c);
                continue;
            }
            if (c == '(') { depth++; i++; continue; }
            if (c == ')') { depth--; i++; continue; }

            if (depth == 0 && (c == 'I' || c == 'i'))
            {
                var kw = ReadKeywordAt(sql, i);
                if (kw != null && kw.Equals("INTO", StringComparison.OrdinalIgnoreCase))
                    return true;
                if (kw != null) { i += kw.Length; continue; }
            }

            i++;
        }

        return false;
    }

    private static int SkipQuoted(string sql, int i, char quote)
    {
        var isEString = quote == '\'' && i > 0 && (sql[i - 1] == 'E' || sql[i - 1] == 'e');
        i++;
        while (i < sql.Length)
        {
            if (isEString && sql[i] == '\\' && i + 1 < sql.Length) { i += 2; continue; }
            if (sql[i] == quote && i + 1 < sql.Length && sql[i + 1] == quote) { i += 2; continue; }
            if (sql[i] == quote) { i++; break; }
            i++;
        }
        return i;
    }

    private static string? GetFirstKeyword(string sql)
    {
        var i = 0;
        while (i < sql.Length && char.IsWhiteSpace(sql[i])) i++;
        var start = i;
        while (i < sql.Length && (char.IsLetterOrDigit(sql[i]) || sql[i] == '_')) i++;
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
