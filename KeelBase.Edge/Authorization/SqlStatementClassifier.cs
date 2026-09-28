using KeelBase.Edge.Models;

namespace KeelBase.Edge.Authorization;

/// <summary>
/// The front gate that decides the permission level of a SQL statement.
///
/// PAY-1854 round 2 (NightHawk 65130, QAPert 65122, BAPert 65125/65133): three review rounds each
/// found a fresh bypass in the hand-rolled lexer, so this is a rewrite around ONE tokenizer and ONE
/// token-boundary rule. The three scanners (the multi-statement check, the E-string rule and the
/// dollar-quote rule) previously each decided for themselves whether a character was a token
/// boundary, and drifted apart; they now all read the same <see cref="Tokenize"/> output.
///
/// The token-boundary rule, stated once (Postgres 4.1.1: identifiers may contain letters, digits,
/// underscores and dollar signs after the first character):
///   - a '$' opens a dollar quote ONLY at a token boundary (previous char is not [A-Za-z0-9_$], or
///     it is the start of input), and the tag may not start with a digit (so $1$ is not a tag);
///   - a quote is an E-string ONLY when the E is its own token (the char before it is not
///     [A-Za-z0-9_$], or it is the start of input). Otherwise a keyword ENDING in E (LIKE, WHERE,
///     ELSE, CASE, ILIKE) would switch on backslash escapes and swallow a following batch.
/// </summary>
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
        var toks = Tokenize(sql);

        // A ';' with any token after it is a second statement, whatever hid it (comments, strings,
        // dollar quotes, E-strings) - the tokenizer has already removed all of those.
        if (ContainsMultiStatement(toks))
            return (ClassifyResult.MultiStatement, PermissionLevel.None, null);

        if (toks.Count == 0)
            return (ClassifyResult.Unrecognized, PermissionLevel.None, null);

        // EXPLAIN [ANALYZE] [VERBOSE] [( options )] <statement>. Unwrap to the inner statement so an
        // INTO hidden behind a wrapper (R16) is still seen.
        if (IsIdent(toks[0], "EXPLAIN"))
        {
            var i = 1;
            while (i < toks.Count)
            {
                if (IsIdent(toks[i], "ANALYZE") || IsIdent(toks[i], "VERBOSE")) { i++; continue; }
                if (IsPunct(toks[i], "(")) { i = SkipParens(toks, i); continue; }
                break;
            }
            return ClassifyFrom(toks, i, "EXPLAIN");
        }

        return ClassifyFrom(toks, 0, null);
    }

    private static (ClassifyResult Result, PermissionLevel Level, string? Keyword) ClassifyFrom(List<Tok> toks, int start, string? fallback)
    {
        if (start >= toks.Count || toks[start].Kind != TokKind.Ident)
            return (ClassifyResult.Unrecognized, PermissionLevel.None, fallback);

        // WITH: a CTE list. The statement's class is the MAX level of any keyword in the whole thing
        // (R10: a DELETE/UPDATE/INSERT inside a CTE body is a write), and a top-level INTO whose
        // terminal statement is a SELECT is Schema (R16: WITH x AS (...) SELECT ... INTO t2).
        if (IsIdent(toks[start], "WITH"))
            return ClassifyWith(toks, start);

        var kw = toks[start].Text;
        if (!KeywordMap.TryGetValue(kw, out var level))
            return (ClassifyResult.Unrecognized, PermissionLevel.None, kw);

        // R16: SELECT ... INTO new_table creates a table. INSERT INTO is NOT this (its verb is INSERT
        // and it is already Write); only a SELECT whose top-level body carries an INTO is DDL.
        if (kw.Equals("SELECT", StringComparison.OrdinalIgnoreCase) && HasTopLevelInto(toks, start + 1))
            return (ClassifyResult.Ok, PermissionLevel.Schema, "SELECT INTO");

        if (kw.Equals("DROP", StringComparison.OrdinalIgnoreCase))
        {
            // MUST-5: the second keyword is read from TOKENS, so a comment between DROP and SCHEMA
            // (DROP/**/SCHEMA) no longer hides the Admin classification.
            var second = NextIdentText(toks, start + 1);
            if (second != null && (second.Equals("SCHEMA", StringComparison.OrdinalIgnoreCase)
                                || second.Equals("DATABASE", StringComparison.OrdinalIgnoreCase)))
                return (ClassifyResult.Ok, PermissionLevel.Admin, "DROP SCHEMA");
            return (ClassifyResult.Ok, PermissionLevel.Schema, "DROP");
        }

        if (kw.Equals("CREATE", StringComparison.OrdinalIgnoreCase))
        {
            var second = NextIdentText(toks, start + 1);
            if (second != null && second.Equals("SCHEMA", StringComparison.OrdinalIgnoreCase))
                return (ClassifyResult.Ok, PermissionLevel.Admin, "CREATE SCHEMA");
            return (ClassifyResult.Ok, level, kw);
        }

        return (ClassifyResult.Ok, level, kw);
    }

    private static (ClassifyResult Result, PermissionLevel Level, string? Keyword) ClassifyWith(List<Tok> toks, int start)
    {
        var highest = PermissionLevel.None;
        string? highestKeyword = null;
        var hasSelect = false;

        foreach (var t in toks)
        {
            if (t.Kind != TokKind.Ident) continue;
            if (t.Text.Equals("SELECT", StringComparison.OrdinalIgnoreCase)) hasSelect = true;
            if (KeywordMap.TryGetValue(t.Text, out var lvl) && lvl > highest)
            {
                highest = lvl;
                highestKeyword = t.Text;
            }
        }

        // A top-level INTO reachable by a SELECT (WITH ... SELECT ... INTO t2) is DDL.
        if (hasSelect && highest <= PermissionLevel.Read && HasTopLevelInto(toks, start))
            return (ClassifyResult.Ok, PermissionLevel.Schema, "SELECT INTO");

        if (highest == PermissionLevel.None)
            return (ClassifyResult.Unrecognized, PermissionLevel.None, "WITH");

        // R10: a data-modifying CTE body makes the whole statement a Write even though the terminal
        // keyword is SELECT. The DML keywords are in KeywordMap, so the max already reflects them.
        return (ClassifyResult.Ok, highest, highestKeyword ?? "WITH");
    }

    private static bool ContainsMultiStatement(List<Tok> toks)
    {
        for (var i = 0; i < toks.Count; i++)
        {
            if (toks[i].Kind == TokKind.Punct && toks[i].Text == ";" && i + 1 < toks.Count)
                return true;
        }
        return false;
    }

    /// <summary>True when an INTO keyword sits at bracket depth 0 from <paramref name="from"/> (R16).
    /// Nested subqueries are skipped, so `x IN (SELECT ...)` is untouched.</summary>
    private static bool HasTopLevelInto(List<Tok> toks, int from)
    {
        var depth = 0;
        for (var i = from; i < toks.Count; i++)
        {
            var t = toks[i];
            if (t.Kind == TokKind.Punct && t.Text == "(") { depth++; continue; }
            if (t.Kind == TokKind.Punct && t.Text == ")") { depth--; continue; }
            if (depth == 0 && t.Kind == TokKind.Ident && t.Text.Equals("INTO", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    // -------------------------------------------------------------------------------------------
    // The tokenizer. Comments and string literals (single, E-string, dollar-quoted, double-quoted)
    // each become AT MOST ONE token, so a ';' inside any of them cannot be seen as a separator.
    // -------------------------------------------------------------------------------------------

    private enum TokKind { Ident, Literal, Punct }

    private readonly struct Tok
    {
        public readonly TokKind Kind;
        public readonly string Text;
        public Tok(TokKind kind, string text) { Kind = kind; Text = text; }
    }

    private static List<Tok> Tokenize(string sql)
    {
        var toks = new List<Tok>();
        var i = 0;
        while (i < sql.Length)
        {
            var c = sql[i];

            // MUST-7: whitespace must be exactly [ \t\n\r\f\v], not char.IsWhiteSpace which includes NBSP
            if (IsAsciiWhiteSpace(c)) { i++; continue; }

            // Check for non-ASCII or extended whitespace outside string literals (MUST-7 fail-closed)
            if (c >= '\x80' || (char.IsWhiteSpace(c) && !IsAsciiWhiteSpace(c)))
                return new List<Tok> { }; // Return empty to signal Unrecognized

            // line comment - MUST-7: ends at \r OR \n
            if (c == '-' && i + 1 < sql.Length && sql[i + 1] == '-')
            {
                while (i < sql.Length && sql[i] != '\n' && sql[i] != '\r') i++;
                if (i < sql.Length) i++; // Skip the line terminator
                continue;
            }

            // block comment (nested per Postgres)
            if (c == '/' && i + 1 < sql.Length && sql[i + 1] == '*')
            {
                i = SkipBlockComment(sql, i);
                continue;
            }

            // double-quoted identifier
            if (c == '"')
            {
                var start = i;
                i = SkipDoubleQuoted(sql, i);
                toks.Add(new Tok(TokKind.Ident, sql[start..i]));
                continue;
            }

            // single-quoted string; E-string ONLY when the E is its own token (MUST-1)
            if (c == '\'')
            {
                var isE = IsEStringPrefix(sql, i);
                var start = i;
                i = SkipSingleQuoted(sql, i, isE);
                toks.Add(new Tok(TokKind.Literal, sql[start..i]));
                continue;
            }

            // dollar quote ONLY at a token boundary and with a non-digit tag (MUST-3)
            if (c == '$' && IsDollarBoundary(sql, i) && TryDollarQuote(sql, i, out var afterClose))
            {
                var start = i;
                i = afterClose;
                toks.Add(new Tok(TokKind.Literal, sql[start..i]));
                continue;
            }

            // identifier (ASCII letters, digits, underscore, and '$' after the first char)
            // MUST-7: only ASCII letters allowed to start an identifier
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_')
            {
                var start = i;
                i++;
                while (i < sql.Length && IsIdentChar(sql[i])) i++;
                toks.Add(new Tok(TokKind.Ident, sql[start..i]));
                continue;
            }

            toks.Add(new Tok(TokKind.Punct, c.ToString()));
            i++;
        }
        return toks;
    }

    /// <summary>MUST-7: only ASCII whitespace - specifically [ \t\n\r\f\v]. Not char.IsWhiteSpace,
    /// which includes NBSP (U+00A0) and other Unicode spaces.</summary>
    private static bool IsAsciiWhiteSpace(char c) => c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';

    /// <summary>MUST-7: identifier characters are ASCII only outside of quoted identifiers.
    /// Letters means [A-Za-z], and digits means [0-9]. Non-ASCII chars are rejected (fail-closed).</summary>
    private static bool IsIdentChar(char c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '$';

    /// <summary>MUST-1: the quote at <paramref name="quoteIdx"/> is an E-string only when the
    /// immediately preceding E/e is its OWN token - i.e. the char before the E is not an identifier
    /// char (or the E is at the start of input). A keyword ending in E (LIKE, WHERE, ELSE, CASE,
    /// ILIKE) is therefore NOT an E-string prefix.</summary>
    private static bool IsEStringPrefix(string sql, int quoteIdx)
    {
        var e = quoteIdx - 1;
        if (e < 0 || (sql[e] != 'E' && sql[e] != 'e')) return false;
        return e - 1 < 0 || !IsIdentChar(sql[e - 1]);
    }

    /// <summary>MUST-3: a '$' is a dollar-quote opener only when the previous char is not an
    /// identifier char (or it is the start of input).</summary>
    private static bool IsDollarBoundary(string sql, int i) => i == 0 || !IsIdentChar(sql[i - 1]);

    /// <summary>MUST-3: read a $tag$ ... $tag$ dollar quote. The tag may be empty ($$) but may not
    /// start with a digit ($1$ is a positional parameter, not a quote). Returns the index just past
    /// the closing tag, or false when this '$' is not a dollar quote. MUST-7: tag chars must be
    /// ASCII only.</summary>
    private static bool TryDollarQuote(string sql, int i, out int afterClose)
    {
        afterClose = i;
        var j = i + 1;
        var tagStart = j;
        // MUST-7: only ASCII letters, digits, underscore in tags
        while (j < sql.Length && (((sql[j] >= 'A' && sql[j] <= 'Z') || (sql[j] >= 'a' && sql[j] <= 'z') || (sql[j] >= '0' && sql[j] <= '9')) || sql[j] == '_')) j++;
        if (j > tagStart && sql[tagStart] >= '0' && sql[tagStart] <= '9') return false;
        if (j >= sql.Length || sql[j] != '$') return false;

        var tag = sql[i..(j + 1)];
        var close = sql.IndexOf(tag, j + 1, StringComparison.Ordinal);
        // No closing tag: PG would treat the rest as an open quote; consume to the end so a ';'
        // hidden inside it is not counted as a separator.
        afterClose = close < 0 ? sql.Length : close + tag.Length;
        return true;
    }

    private static int SkipSingleQuoted(string sql, int i, bool isE)
    {
        i++;
        while (i < sql.Length)
        {
            if (isE && sql[i] == '\\' && i + 1 < sql.Length) { i += 2; continue; }
            if (sql[i] == '\'' && i + 1 < sql.Length && sql[i + 1] == '\'') { i += 2; continue; }
            if (sql[i] == '\'') { i++; break; }
            i++;
        }
        return i;
    }

    private static int SkipDoubleQuoted(string sql, int i)
    {
        i++;
        while (i < sql.Length)
        {
            if (sql[i] == '"' && i + 1 < sql.Length && sql[i + 1] == '"') { i += 2; continue; }
            if (sql[i] == '"') { i++; break; }
            i++;
        }
        return i;
    }

    /// <summary>Skip a (possibly nested) block comment starting at <paramref name="i"/> (which points at "/*").
    /// Returns the index just past the matching "*/", or sql.Length if unterminated.</summary>
    private static int SkipBlockComment(string sql, int i)
    {
        var depth = 0;
        while (i < sql.Length)
        {
            if (i + 1 < sql.Length && sql[i] == '/' && sql[i + 1] == '*') { depth++; i += 2; continue; }
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

    private static int SkipParens(List<Tok> toks, int i)
    {
        var depth = 0;
        for (; i < toks.Count; i++)
        {
            if (IsPunct(toks[i], "(")) depth++;
            else if (IsPunct(toks[i], ")"))
            {
                depth--;
                if (depth == 0) return i + 1;
            }
        }
        return toks.Count;
    }

    private static bool IsIdent(Tok t, string value) =>
        t.Kind == TokKind.Ident && t.Text.Equals(value, StringComparison.OrdinalIgnoreCase);

    private static bool IsPunct(Tok t, string value) =>
        t.Kind == TokKind.Punct && t.Text == value;

    private static string? NextIdentText(List<Tok> toks, int from)
    {
        for (var i = from; i < toks.Count; i++)
            if (toks[i].Kind == TokKind.Ident) return toks[i].Text;
        return null;
    }
}
