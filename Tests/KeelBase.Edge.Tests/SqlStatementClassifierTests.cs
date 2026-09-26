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

    [Fact]
    public void R16_select_into_classifies_as_Schema_not_Read()
    {
        var (result, level, _) = C("SELECT * INTO t2 FROM t");

        level.Should().NotBe(PermissionLevel.Read,
            "SELECT ... INTO creates a table; a Read-only role must not be allowed to run it");
        if (result == SqlStatementClassifier.ClassifyResult.Ok)
        {
            level.Should().Be(PermissionLevel.Schema);
        }
    }
}
