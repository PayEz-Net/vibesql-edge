using FluentAssertions;
using KeelBase.Edge.Authorization;
using KeelBase.Edge.Models;

namespace KeelBase.Edge.Tests;

/// <summary>
/// PAY-1853 F2 (classification table), R13 (nested block comments) and R16 (SELECT ... INTO).
///
/// Test-first: R13 and R16 are EXPECTED RED at keelbase-edge/dev 88d5a41. They are written against the
/// correct behaviour, which the current classifier does not deliver. R13/R16 are DotNetPert's targets;
/// F2 pins the table so a fix cannot over-block.
///
/// API note: KeelBase.Edge's classifier returns a TUPLE (Result, Level, Keyword), unlike the
/// VibeSQL.Edge original's result object. Rows ported from vibesql-server/tests/VibeSQL.Edge.Tests
/// are adapted to this signature - not copied verbatim.
/// </summary>
public class SqlStatementClassifierTests
{
    private static (SqlStatementClassifier.ClassifyResult Result, PermissionLevel Level, string? Keyword) C(string sql)
        => SqlStatementClassifier.Classify(sql);

    // ── F2: the classification table (positive controls for the DDL gate) ──────────────────────────

    [Theory]
    [InlineData("SELECT * FROM users", PermissionLevel.Read, "SELECT")]
    [InlineData("select id from orders", PermissionLevel.Read, "SELECT")]
    [InlineData("SHOW tables", PermissionLevel.Read, "SHOW")]
    public void Read_statements_classify_as_Read(string sql, PermissionLevel level, string keyword)
    {
        var (result, gotLevel, gotKeyword) = C(sql);
        result.Should().Be(SqlStatementClassifier.ClassifyResult.Ok);
        gotLevel.Should().Be(level);
        // The classifier returns the keyword as TYPED, so compare case-insensitively.
        gotKeyword.Should().BeEquivalentTo(keyword);
    }

    [Theory]
    [InlineData("INSERT INTO users VALUES (1)", "INSERT")]
    [InlineData("UPDATE users SET name='x' WHERE id=1", "UPDATE")]
    [InlineData("DELETE FROM users WHERE id=1", "DELETE")]
    [InlineData("MERGE INTO users USING staging ON users.id = staging.id", "MERGE")]
    [InlineData("COPY users FROM STDIN", "COPY")]
    public void Write_statements_classify_as_Write(string sql, string keyword)
    {
        var (result, level, gotKeyword) = C(sql);
        result.Should().Be(SqlStatementClassifier.ClassifyResult.Ok);
        level.Should().Be(PermissionLevel.Write);
        gotKeyword.Should().Be(keyword);
    }

    [Theory]
    [InlineData("CREATE TABLE t (id int)", "CREATE")]
    [InlineData("ALTER TABLE t ADD COLUMN x int", "ALTER")]
    [InlineData("DROP TABLE t", "DROP")]
    public void Schema_statements_classify_as_Schema(string sql, string keyword)
    {
        var (result, level, gotKeyword) = C(sql);
        result.Should().Be(SqlStatementClassifier.ClassifyResult.Ok);
        level.Should().Be(PermissionLevel.Schema);
        gotKeyword.Should().Be(keyword);
    }

    [Theory]
    [InlineData("TRUNCATE TABLE t", "TRUNCATE")]
    [InlineData("GRANT SELECT ON t TO r", "GRANT")]
    [InlineData("REVOKE SELECT ON t FROM r", "REVOKE")]
    [InlineData("DROP SCHEMA s", "DROP SCHEMA")]
    [InlineData("CREATE SCHEMA s", "CREATE SCHEMA")]
    public void Admin_statements_classify_as_Admin(string sql, string keyword)
    {
        var (result, level, gotKeyword) = C(sql);
        result.Should().Be(SqlStatementClassifier.ClassifyResult.Ok);
        level.Should().Be(PermissionLevel.Admin);
        gotKeyword.Should().Be(keyword);
    }

    // ── PAY-1853 MUST-5 (QAPert 65122, BAPert 65125 promoted it): the SECOND keyword read does not skip
    // comments, so `DROP/**/SCHEMA s` classifies Schema, not Admin. Agents are still refused (>= Schema),
    // but a Schema-role USER could drop a schema. The second-keyword read must skip comments.

    [Theory]
    [InlineData("DROP/**/SCHEMA s", "DROP SCHEMA")]
    [InlineData("CREATE /* x */ SCHEMA s", "CREATE SCHEMA")]
    public void MUST5_second_keyword_skips_comments(string sql, string keyword)
    {
        var (result, level, gotKeyword) = C(sql);
        result.Should().Be(SqlStatementClassifier.ClassifyResult.Ok);
        level.Should().Be(PermissionLevel.Admin,
            "the effective second keyword is SCHEMA, so this is an Admin statement. SQL: " + sql);
        gotKeyword.Should().Be(keyword);
    }

    [Fact]
    public void ExplainAnalyzeDelete_classifies_as_Write()
    {
        var (result, level, keyword) = C("EXPLAIN ANALYZE DELETE FROM users");
        result.Should().Be(SqlStatementClassifier.ClassifyResult.Ok);
        level.Should().Be(PermissionLevel.Write);
        keyword.Should().Be("DELETE");
    }

    [Fact]
    public void ExplainSelect_classifies_as_Read()
    {
        var (result, level, keyword) = C("EXPLAIN SELECT * FROM users");
        result.Should().Be(SqlStatementClassifier.ClassifyResult.Ok);
        level.Should().Be(PermissionLevel.Read);
        keyword.Should().Be("SELECT");
    }

    [Theory]
    [InlineData("DO $$ BEGIN END $$")]
    [InlineData("CALL some_proc()")]
    [InlineData("SET search_path = public")]
    public void Unrecognized_statements_are_refused(string sql)
    {
        var (result, level, _) = C(sql);
        result.Should().Be(SqlStatementClassifier.ClassifyResult.Unrecognized);
        level.Should().Be(PermissionLevel.None);
    }

    // ── PAY-1853 F2 support: multi-statement is its own refusal, never a leading-keyword pass ───────

    [Fact]
    public void Multi_statement_is_MultiStatement()
    {
        var (result, _, _) = C("SELECT 1; DROP TABLE t");
        result.Should().Be(SqlStatementClassifier.ClassifyResult.MultiStatement);
    }

    // ── PAY-1853 R5 (NightHawk 65081 M3): a QUOTE inside a COMMENT used to fool the multi-statement
    // scanner. The old ContainsMultiStatement tracked '...' and "..." but ignored -- and /* */ comments,
    // $$ dollar-quotes and E'\'' escapes. So an odd quote in a comment flipped the in-string state and
    // swallowed the ';', and `SELECT 1 -- '  ; DROP TABLE t -- '` classified a single SELECT (Read) while
    // Npgsql ran BOTH statements. DotNetPert's M3 real lexer should make every shape below MultiStatement.

    [Theory]
    [InlineData("SELECT 1 -- '\n; DROP TABLE t -- '")]
    [InlineData("SELECT 1 /* ' */ ; DROP TABLE t /* ' */")]
    [InlineData("SELECT $$;$$ AS s; DROP TABLE t")]
    [InlineData("SELECT E'\\';' AS s; DROP TABLE t")]
    public void R5_quote_in_comment_or_quote_form_cannot_hide_a_second_statement(string sql)
    {
        var (result, _, _) = C(sql);
        result.Should().Be(SqlStatementClassifier.ClassifyResult.MultiStatement,
            "the ';' separates two statements once comments/quoting are lexed correctly. SQL: " + sql);
    }

    // Over-block control for R5: a ';' INSIDE a string literal or comment is not a statement separator.
    [Theory]
    [InlineData("SELECT 'a;b' AS s")]
    [InlineData("SELECT 1 -- ; not a statement")]
    [InlineData("SELECT $$a;b$$ AS s")]
    public void R5_control_semicolon_inside_quoting_is_not_multi_statement(string sql)
    {
        var (result, _, _) = C(sql);
        result.Should().Be(SqlStatementClassifier.ClassifyResult.Ok,
            "a ';' inside a string/comment/dollar-quote must not read as a second statement. SQL: " + sql);
    }

    // ── PAY-1853 MUST-1 (QAPert 65122, BAPert 65125): the M3 lexer treats a quote as an E-string whenever
    // the PREVIOUS CHAR is E/e. A keyword ENDING in E right before a quote (LIKE, WHERE, ELSE, CASE, ILIKE)
    // switches on backslash escapes, so \' swallows the closing quote and the rest of the batch hides
    // inside a fake string. All three measured Ok (not MultiStatement) at f0373d4, and PROVEN against the
    // dev-93 Postgres with standard_conforming_strings=on: it ran BOTH statements. The fix: treat it as an
    // E-string ONLY when the E is its own token (char before E is not [A-Za-z0-9_$], or E at start).

    [Theory]
    [InlineData("SELECT * FROM t WHERE a LIKE'\\'; DROP TABLE t; --'")]
    [InlineData("SELECT 1 WHERE'\\'='\\'; DROP TABLE t; --'")]
    [InlineData("SELECT CASE WHEN true THEN 1 ELSE'\\' END; DROP TABLE t; --'")]
    public void MUST1_keyword_ending_in_E_does_not_open_an_E_string(string sql)
    {
        var (result, _, _) = C(sql);
        result.Should().Be(SqlStatementClassifier.ClassifyResult.MultiStatement,
            "the quote here follows a keyword ending in E, not a real E-string prefix, so the ';' " +
            "separates two statements. SQL: " + sql);
    }

    // MUST-1 control: a GENUINE E-string (E is its own token) still hides its ';' and must stay Ok.
    // Verbatim from QAPert 65122's list (BAPert 65127: the backslash must survive transit; the C# @-string
    // below carries it). This row is the MUST-1 over-block control.
    [Fact]
    public void MUST1_control_real_E_string_stays_Ok()
    {
        var (result, _, _) = C("SELECT E'\\';DROP' AS s");
        result.Should().Be(SqlStatementClassifier.ClassifyResult.Ok,
            "E'...' here IS a real E-string, so the ';' is inside the literal and must not split the batch");
    }

    // ── PAY-1853 MUST-3 (NightHawk 65130, BAPert 65133): the multi-statement lexer opens a DOLLAR QUOTE
    // at a '$' INSIDE AN IDENTIFIER. Postgres identifiers may contain '$' after the first char, so `a$b$`
    // is ONE identifier token and the following ';' is a real separator. The lexer treats any '$' as a
    // possible `$tag$` opener, so it swallows the rest of the batch: both strings below measured NOT multi
    // at f0373d4, so Edge saw a single SELECT (Read) while Postgres runs every statement.
    // Fix: a '$' opens a dollar quote ONLY at a token boundary (prev char not [A-Za-z0-9_$], or start),
    // and a tag may not start with a digit. Same shared boundary helper as MUST-1.

    [Theory]
    [InlineData("SELECT 1 AS a$b$; DROP TABLE t; SELECT 1 AS c$b$")]
    [InlineData("SELECT 1 AS a$z$; DROP TABLE t")]
    public void MUST3_dollar_inside_identifier_does_not_open_a_dollar_quote(string sql)
    {
        var (result, _, _) = C(sql);
        result.Should().Be(SqlStatementClassifier.ClassifyResult.MultiStatement,
            "a '$' inside an identifier is not a dollar-quote opener, so the ';' separates statements. SQL: " + sql);
    }

    // MUST-3 control: a REAL dollar quote (opener at a token boundary) still hides its ';' and stays Ok.
    [Fact]
    public void MUST3_control_real_dollar_quote_stays_Ok()
    {
        var (result, _, _) = C("SELECT $x$;$x$ AS s");
        result.Should().Be(SqlStatementClassifier.ClassifyResult.Ok,
            "$x$ here IS a real dollar quote, so the ';' is inside the literal and must not split the batch");
    }

    // MUST-3 control: in PG a tag may not start with a digit, so $1$ is not a dollar-quote opener.
    [Fact]
    public void MUST3_control_digit_tag_is_not_a_dollar_quote()
    {
        var (result, _, _) = C("SELECT 1 AS a$1$; DROP TABLE t");
        result.Should().Be(SqlStatementClassifier.ClassifyResult.MultiStatement,
            "a tag may not start with a digit, so $1$ opens no quote and the ';' separates statements");
    }

    // ── PAY-1853 R13: PG NESTS block comments. Expected RED at 88d5a41. ─────────────────────────────
    //
    // `/* /* */ SELECT 1 */ DROP TABLE t` is, in PostgreSQL, ONE nested block comment
    // (`/* /* */ SELECT 1 */`) followed by `DROP TABLE t`. StripLeadingComments (SqlStatementClassifier.cs)
    // ends at the FIRST `*/`, so it stops inside the outer comment and reads the remainder as
    // `SELECT 1 */ DROP TABLE t` -> first keyword SELECT -> classified Read. That is the fail-open:
    // a caller needing only Read is handed a statement whose EFFECTIVE command is DROP TABLE.
    //
    // The assertion is deliberately the falsifiable core - it must NOT come back Ok+Read. A correct
    // nested-comment lexer lands on DROP (Schema); a conservative fix that refuses also satisfies this.

    [Fact]
    public void R13_nested_block_comment_does_not_classify_as_Read()
    {
        var (result, level, keyword) = C("/* /* */ SELECT 1 */ DROP TABLE t");

        (result == SqlStatementClassifier.ClassifyResult.Ok && level == PermissionLevel.Read)
            .Should().BeFalse(
                "PostgreSQL nests block comments: the outer comment is `/* /* */ SELECT 1 */`, so the " +
                "effective statement is DROP TABLE t (Schema), never Ok+Read/SELECT");

        // If a nested lexer is in place, the effective keyword is DROP and it needs Schema.
        if (result == SqlStatementClassifier.ClassifyResult.Ok)
        {
            keyword.Should().Be("DROP");
            level.Should().Be(PermissionLevel.Schema);
        }
    }

    // ── PAY-1853 R16: SELECT ... INTO creates a table but classifies Read. Expected RED at 88d5a41. ─
    //
    // PostgreSQL's SELECT ... INTO creates a NEW table. The classifier keys only on the leading keyword,
    // so it returns Read, and a Read-only role is allowed to create a table. The upstream QueryValidator
    // checks only the leading keyword too, so the DB grants are the sole backstop. A read-only role must
    // be refused: classify SELECT ... INTO as Schema.
    //
    // QAPert 65111: a SINGLE shape lets a string-match fix go green while real bypasses stay open, so this
    // is a Theory over SIX shapes. Every row must be NOT Ok+Read. The mutant reverts ONLY the SELECT...INTO
    // branch and all six must go RED - not just row 1.

    [Theory]
    [InlineData("SELECT * INTO t2 FROM t")]
    [InlineData("select a, b into temp t2 from t")]
    [InlineData("SELECT *\nINTO UNLOGGED t2 FROM t")]
    [InlineData("SELECT * /* c */ INTO t2 FROM t")]
    [InlineData("WITH x AS (SELECT 1) SELECT * INTO t2 FROM x")]
    [InlineData("EXPLAIN ANALYZE SELECT * INTO t2 FROM t")]
    // QAPert 65122: SkipQuoted does not skip $$...$$, so the ' opens a fake string that swallows the INTO.
    [InlineData("SELECT $$'$$ INTO t2 FROM t")]
    public void R16_select_into_is_never_Ok_Read(string sql)
    {
        var (result, level, _) = C(sql);

        (result == SqlStatementClassifier.ClassifyResult.Ok && level == PermissionLevel.Read)
            .Should().BeFalse(
                "SELECT ... INTO creates a table; a Read-only role must not be able to run it. Offending SQL: " + sql);

        // If the fix classifies it rather than refusing, it must demand Schema.
        if (result == SqlStatementClassifier.ClassifyResult.Ok)
        {
            level.Should().Be(PermissionLevel.Schema, "the effective statement is CREATE TABLE (Schema). Offending SQL: " + sql);
        }
    }

    // QAPert 65111 OPTIONAL over-block control, NOT a gate: a literal containing the word INTO is not a
    // SELECT...INTO. Correct behaviour is Read; if a conservative fix refuses it instead, that is
    // acceptable only if the PR says so. This row pins the DESIRABLE behaviour, so it is allowed to be RED.
    [Fact]
    public void R16_control_literal_containing_INTO_stays_Read()
    {
        var (result, level, _) = C("SELECT 'put INTO box' AS s");

        result.Should().Be(SqlStatementClassifier.ClassifyResult.Ok);
        level.Should().Be(PermissionLevel.Read,
            "the INTO here is inside a string literal, not a SELECT...INTO table creation");
    }

    // BAPert 65119: sweep the OTHER wrappers the same effective-statement resolution feeds.
    // (a) A parenthesised SELECT...INTO. Must not be Ok+Read (Unrecognized is acceptable - it is refused).
    // (b) CREATE TABLE ... AS SELECT: a table-creating statement; must already be Schema (positive control).
    [Theory]
    [InlineData("(SELECT * INTO t2 FROM t)")]
    [InlineData("EXPLAIN (FORMAT JSON) SELECT * INTO t2 FROM t")]
    public void R16_other_wrappers_never_yield_Ok_Read(string sql)
    {
        var (result, level, _) = C(sql);
        (result == SqlStatementClassifier.ClassifyResult.Ok && level == PermissionLevel.Read)
            .Should().BeFalse("a wrapped SELECT...INTO still creates a table. SQL: " + sql);
    }

    [Theory]
    [InlineData("CREATE TABLE t2 AS SELECT * FROM t", "CREATE")]
    [InlineData("CREATE UNLOGGED TABLE t2 AS SELECT * FROM t", "CREATE")]
    public void R16_control_create_table_as_is_already_Schema(string sql, string keyword)
    {
        var (result, level, gotKeyword) = C(sql);
        result.Should().Be(SqlStatementClassifier.ClassifyResult.Ok);
        level.Should().Be(PermissionLevel.Schema, "CREATE ... AS SELECT creates a table. SQL: " + sql);
        gotKeyword.Should().Be(keyword);
    }

    // ── PAY-1853 R10 (NightHawk 65081, re-measured RED by QAPert 65122): a DATA-MODIFYING CTE. The CTE
    // body contains DELETE, so the statement writes, but FindCteTerminalKeyword looks only at depth 0 and
    // ignores strings, so the terminal keyword is the outer SELECT = Read. Upstream blocks a leading WITH
    // today, so this is defence in depth - but it is on the list and it is RED.

    [Theory]
    [InlineData("WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x")]
    [InlineData("WITH x AS (UPDATE t SET a = 1 RETURNING *) SELECT * FROM x")]
    [InlineData("WITH x AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM x")]
    public void R10_data_modifying_cte_is_not_Read(string sql)
    {
        var (result, level, _) = C(sql);

        (result == SqlStatementClassifier.ClassifyResult.Ok && level == PermissionLevel.Read)
            .Should().BeFalse(
                "a data-modifying CTE writes; it must not be Ok+Read. SQL: " + sql);
    }
}
