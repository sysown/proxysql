// Patched ParserSQL capability fixtures for the MySQL analytical SELECT contract.
//
// This target is deliberately parser-only. It records what the vendored
// Parser<Dialect::MySQL> actually produces, including incomplete ASTs and
// silent normalisations that the later admission layer must not mistake for
// successful translation. It does not implement recognition, translation or
// any DuckDB execution.
//
// A successful parse is not a semantic admission decision: status==OK alone is
// never sufficient. The parser gate below requires a complete input, no
// remaining text, a known SELECT statement and the expected single-SELECT AST
// root. Semantic type/collation/session admission belongs to Task 2 and is
// documented in doc/duckdb/mysql-query-compatibility.md.

#include "tap.h"

#include "sql_parser/ast_transform.h"
#include "sql_parser/ast_walk.h"
#include "sql_parser/emitter.h"
#include "sql_parser/parser.h"
#include "sql_parser/user_variable.h"

#include <cstring>
#include <string>

using namespace sql_parser;

namespace {

std::string ref_string(StringRef ref) {
	return ref.ptr && ref.len != 0 ? std::string(ref.ptr, ref.len) : std::string();
}

// Necessary parser-side gate only. It intentionally does not claim that the
// statement is semantically admissible. In particular a root NODE_SELECT_STMT
// may still contain session-dependent or unsupported expressions.
bool parser_complete_select(const ParseResult& result) {
	return result.status == ParseResult::OK &&
	       result.full_input &&
	       !result.has_remaining() &&
	       result.ast != nullptr &&
	       result.stmt_type == StmtType::SELECT &&
	       result.ast->type == NodeType::NODE_SELECT_STMT;
}

std::string emit_sql(Parser<Dialect::MySQL>& parser, const AstNode* ast) {
	if (ast == nullptr) {
		return {};
	}
	Emitter<Dialect::MySQL> emitter(parser.arena());
	emitter.emit(ast);
	return ref_string(emitter.result());
}

const AstNode* find_node(const AstNode* root, NodeType type, size_t& count) {
	const AstNode* first = nullptr;
	count = 0;
	if (root == nullptr) {
		return nullptr;
	}
	AstWalkResult walked = walk_ast(root, [&](const AstNode& node, const AstVisitContext&) {
		if (node.type == type) {
			++count;
			if (first == nullptr) {
				first = &node;
			}
		}
		return AstVisitAction::Continue;
	});
	ok(walked.status == AstWalkStatus::Completed, "AST walk completes while looking for node %d",
	   static_cast<int>(type));
	return first;
}

const AstNode* direct_child(const AstNode* node, NodeType type) {
	for (const AstNode* child = node != nullptr ? node->first_child : nullptr;
	     child != nullptr; child = child->next_sibling) {
		if (child->type == type) {
			return child;
		}
	}
	return nullptr;
}

size_t direct_child_count(const AstNode* node) {
	size_t count = 0;
	for (const AstNode* child = node != nullptr ? node->first_child : nullptr;
	     child != nullptr; child = child->next_sibling) {
		++count;
	}
	return count;
}

// The disposition records the proposed Task 2 treatment, not an implementation.
enum class Disposition {
	CANDIDATE,     // within the proposed first analytical subset (subject to Task 2)
	DEFERRED,      // complete AST, semantics intentionally not admitted yet
	REFUSED,       // must be refused before execution by contract
	PARSER_GAP,    // vendored grammar cannot produce a trustworthy complete AST
	OUT_OF_SCOPE,  // non-SELECT / mutation / endpoint policy boundary
};

struct ParseFixture {
	const char* name;
	const char* sql;
	ParseResult::Status status;
	StmtType stmt_type;
	bool full_input;
	bool has_ast;
	NodeType root;                 // NODE_UNKNOWN disables the root check
	const char* remaining_prefix;  // nullptr disables the check
	const char* emitted;           // nullptr disables the exact emission check
	bool parser_gate;
	Disposition disposition;
};

void run_fixture(const ParseFixture& fixture) {
	Parser<Dialect::MySQL> parser;
	ParseResult result = parser.parse(fixture.sql, std::strlen(fixture.sql));
	const std::string emitted = emit_sql(parser, result.ast);

	ok(result.status == fixture.status, "%s: parse status", fixture.name);
	ok(result.stmt_type == fixture.stmt_type, "%s: statement type", fixture.name);
	ok(result.full_input == fixture.full_input, "%s: full_input", fixture.name);
	ok((result.ast != nullptr) == fixture.has_ast, "%s: AST presence", fixture.name);

	if (fixture.remaining_prefix != nullptr) {
		const std::string remaining = ref_string(result.remaining);
		ok(remaining.rfind(fixture.remaining_prefix, 0) == 0,
		   "%s: remaining starts with '%s' (actual '%s')",
		   fixture.name, fixture.remaining_prefix, remaining.c_str());
	}
	if (result.ast != nullptr && fixture.root != NodeType::NODE_UNKNOWN) {
		ok(result.ast->type == fixture.root, "%s: AST root", fixture.name);
	}
	if (fixture.emitted != nullptr) {
		ok(emitted == fixture.emitted, "%s: emitted SQL", fixture.name);
	}
	ok(parser_complete_select(result) == fixture.parser_gate,
	   "%s: parser-complete-select gate", fixture.name);
	if (fixture.disposition == Disposition::CANDIDATE && !parser_complete_select(result)) {
		ok(false, "%s: candidate fixture must pass the parser gate", fixture.name);
	}
}

struct NodeFixture {
	const char* name;
	const char* sql;
	NodeType type;
	size_t min_count;
	const char* first_value;  // nullptr disables the value check
};

void run_node_fixture(const NodeFixture& fixture) {
	Parser<Dialect::MySQL> parser;
	ParseResult result = parser.parse(fixture.sql, std::strlen(fixture.sql));
	size_t count = 0;
	const AstNode* node = find_node(result.ast, fixture.type, count);
	ok(node != nullptr && count >= fixture.min_count,
	   "%s: at least %zu node(s) of type %d (found %zu)",
	   fixture.name, fixture.min_count, static_cast<int>(fixture.type), count);
	if (fixture.first_value != nullptr && node != nullptr) {
		ok(ref_string(node->value()) == fixture.first_value,
		   "%s: first node value '%s' (actual '%s')",
		   fixture.name, fixture.first_value, ref_string(node->value()).c_str());
	}
}

const ParseFixture kParseFixtures[] = {
	// --- complete input, comments and framing -------------------------------
	{
		"simple select literal",
		"SELECT 1",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT 1", true, Disposition::CANDIDATE,
	},
	{
		"select with one trailing semicolon",
		"SELECT 1;",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT 1", true, Disposition::CANDIDATE,
	},
	{
		"select followed by a second statement is partial",
		"SELECT 1; SELECT 2",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "SELECT 2", "SELECT 1", false, Disposition::REFUSED,
	},
	{
		"reserved keyword after select is partial",
		"SELECT 1 SELECT 2",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "SELECT 2", "SELECT 1", false, Disposition::REFUSED,
	},
	{
		"two trailing semicolons leave remaining input",
		"SELECT 1;;",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, ";", "SELECT 1", false, Disposition::REFUSED,
	},
	{
		"implicit alias is not trailing garbage",
		"SELECT 1 garbage",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT 1 AS garbage", true, Disposition::CANDIDATE,
	},
	{
		"leading block comment is consumed",
		"/* leading */ SELECT 1",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT 1", true, Disposition::CANDIDATE,
	},
	{
		"line comment after statement is consumed",
		"SELECT 1 -- trailing comment",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT 1", true, Disposition::CANDIDATE,
	},
	{
		"inline block comment is consumed but not retained",
		"SELECT 1 /* mid */ + 2",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT 1 + 2", true, Disposition::CANDIDATE,
	},
	{
		"unterminated block comment is an error",
		"/* unterminated SELECT 1",
		ParseResult::ERROR, StmtType::UNKNOWN, false, false,
		NodeType::NODE_UNKNOWN, "", nullptr, false, Disposition::REFUSED,
	},
	{
		"comment-only input has no statement",
		"/* only comment */",
		ParseResult::ERROR, StmtType::UNKNOWN, false, false,
		NodeType::NODE_UNKNOWN, "", nullptr, false, Disposition::REFUSED,
	},
	{
		"semicolon-only input is complete but has no AST",
		";",
		ParseResult::OK, StmtType::UNKNOWN, true, false,
		NodeType::NODE_UNKNOWN, "", nullptr, false, Disposition::REFUSED,
	},
	{
		"empty input is an error",
		"",
		ParseResult::ERROR, StmtType::UNKNOWN, false, false,
		NodeType::NODE_UNKNOWN, "", nullptr, false, Disposition::REFUSED,
	},

	// --- identifiers and quoting -------------------------------------------
	{
		"backtick identifier with doubled backtick",
		"SELECT `a``b`, `Order` FROM `t`",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT `a``b`, `Order` FROM `t`", true, Disposition::CANDIDATE,
	},
	{
		"qualified quoted identifiers",
		"SELECT `a`.`b` FROM `a`",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT `a`.`b` FROM `a`", true, Disposition::CANDIDATE,
	},
	{
		"quoted reserved word",
		"SELECT `select` FROM `t`",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT `select` FROM `t`", true, Disposition::CANDIDATE,
	},
	{
		"double quoted text is a MySQL string literal",
		"SELECT \"x\" FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT \"x\" FROM t", true, Disposition::DEFERRED,
	},
	{
		"duplicate output labels are preserved",
		"SELECT a AS x, b AS x FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT a AS x, b AS x FROM t", true, Disposition::CANDIDATE,
	},
	{
		"duplicate source columns are preserved",
		"SELECT a, a FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT a, a FROM t", true, Disposition::CANDIDATE,
	},
	{
		"quoted alias with doubled backtick",
		"SELECT 1 AS `x``y`",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT 1 AS `x``y`", true, Disposition::CANDIDATE,
	},

	// --- LIMIT forms --------------------------------------------------------
	{
		"limit count",
		"SELECT * FROM t LIMIT 10",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM t LIMIT 10", true, Disposition::CANDIDATE,
	},
	{
		"limit count offset",
		"SELECT * FROM t LIMIT 10 OFFSET 20",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM t LIMIT 10 OFFSET 20", true, Disposition::CANDIDATE,
	},
	{
		"MySQL limit offset comma count is normalised",
		"SELECT * FROM t LIMIT 20, 10",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM t LIMIT 10 OFFSET 20", true, Disposition::CANDIDATE,
	},
	{
		"limit with placeholders is parser-complete but text-refused",
		"SELECT * FROM t LIMIT ?, ?",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM t LIMIT ? OFFSET ?", true, Disposition::REFUSED,
	},
	{
		"limit with a third value is partial",
		"SELECT * FROM t LIMIT 1, 2, 3",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, ", 3", "SELECT * FROM t LIMIT 2 OFFSET 1", false, Disposition::PARSER_GAP,
	},
	{
		"fractional limit is an error",
		"SELECT * FROM t LIMIT 1.5",
		ParseResult::ERROR, StmtType::SELECT, false, false,
		NodeType::NODE_UNKNOWN, "5", nullptr, false, Disposition::REFUSED,
	},
	{
		"maximum unsigned limit literal parses",
		"SELECT * FROM t LIMIT 18446744073709551615",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM t LIMIT 18446744073709551615", true, Disposition::DEFERRED,
	},

	// --- joins and grouping -------------------------------------------------
	{
		"left join with grouping and ordering",
		"SELECT u.id, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id "
		"GROUP BY u.id HAVING COUNT(o.id) > 1 ORDER BY u.id DESC LIMIT 5",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "",
		"SELECT u.id, COUNT(o.id) FROM users AS u LEFT JOIN orders AS o ON u.id = o.user_id "
		"GROUP BY u.id HAVING COUNT(o.id) > 1 ORDER BY u.id DESC LIMIT 5",
		true, Disposition::CANDIDATE,
	},
	{
		"join using",
		"SELECT * FROM t1 JOIN t2 USING (id)",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM t1 JOIN t2 USING (id)", true, Disposition::CANDIDATE,
	},
	{
		"cross join",
		"SELECT * FROM t1 CROSS JOIN t2",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM t1 CROSS JOIN t2", true, Disposition::CANDIDATE,
	},
	{
		"comma join",
		"SELECT * FROM t1, t2",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM t1, t2", true, Disposition::CANDIDATE,
	},
	{
		"STRAIGHT_JOIN after FROM is partial",
		"SELECT * FROM t1 STRAIGHT_JOIN t2 ON t1.id = t2.id",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "STRAIGHT_JOIN", "SELECT * FROM t1", false, Disposition::PARSER_GAP,
	},
	{
		"group by with rollup is parsed but deferred",
		"SELECT * FROM t GROUP BY a WITH ROLLUP",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM t GROUP BY a WITH ROLLUP", true, Disposition::DEFERRED,
	},
	{
		"natural join is parsed but deferred",
		"SELECT * FROM t1 NATURAL JOIN t2",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM t1 NATURAL JOIN t2", true, Disposition::DEFERRED,
	},
	{
		"full outer join is not MySQL grammar",
		"SELECT * FROM t1 FULL OUTER JOIN t2 ON t1.id = t2.id",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM t1 FULL OUTER JOIN t2 ON t1.id = t2.id",
		true, Disposition::REFUSED,
	},

	// --- CTEs and subqueries ------------------------------------------------
	{
		"simple CTE",
		"WITH c AS (SELECT 1 AS x) SELECT x FROM c",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_CTE, "", "WITH c AS (SELECT 1 AS x) SELECT x FROM c", false, Disposition::DEFERRED,
	},
	{
		"recursive CTE",
		"WITH RECURSIVE c AS (SELECT 1 AS x UNION ALL SELECT x+1 FROM c WHERE x < 3) SELECT x FROM c",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_CTE, "",
		"WITH RECURSIVE c AS (SELECT 1 AS x UNION ALL SELECT x + 1 FROM c WHERE x < 3) SELECT x FROM c",
		false, Disposition::DEFERRED,
	},
	{
		"CTE with column list",
		"WITH c(a) AS (SELECT 1) SELECT a FROM c",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_CTE, "", "WITH c(a) AS (SELECT 1) SELECT a FROM c", false, Disposition::DEFERRED,
	},
	{
		"derived table subquery",
		"SELECT * FROM (SELECT id FROM t) AS d",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM (SELECT id FROM t) AS d", true, Disposition::DEFERRED,
	},
	{
		"IN subquery",
		"SELECT * FROM t WHERE id IN (SELECT id FROM u)",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM t WHERE id IN (SELECT id FROM u)",
		true, Disposition::DEFERRED,
	},
	{
		"scalar subquery in projection",
		"SELECT (SELECT MAX(a) FROM u) FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT (SELECT MAX(a) FROM u) FROM t", true, Disposition::DEFERRED,
	},
	{
		"correlated EXISTS subquery",
		"SELECT * FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.id=t.id)",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "",
		"SELECT * FROM t WHERE EXISTS (SELECT 1 FROM u WHERE u.id = t.id)", true, Disposition::DEFERRED,
	},
	{
		"ANY subquery is partial",
		"SELECT * FROM t WHERE a = ANY (SELECT a FROM u)",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "SELECT a FROM u)", "SELECT * FROM t WHERE a", false, Disposition::PARSER_GAP,
	},
	{
		"ALL subquery parses",
		"SELECT * FROM t WHERE a = ALL (SELECT a FROM u)",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM t WHERE a = ALL (SELECT a FROM u)",
		true, Disposition::DEFERRED,
	},

	// --- window functions ---------------------------------------------------
	{
		"row_number window",
		"SELECT ROW_NUMBER() OVER (PARTITION BY a ORDER BY b) FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "",
		"SELECT ROW_NUMBER() OVER (PARTITION BY a ORDER BY b) FROM t", true, Disposition::DEFERRED,
	},
	{
		"window frame",
		"SELECT SUM(x) OVER (ORDER BY a ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "",
		"SELECT SUM(x) OVER (ORDER BY a ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) FROM t",
		true, Disposition::DEFERRED,
	},
	{
		"named window clause",
		"SELECT SUM(x) OVER w FROM t WINDOW w AS (PARTITION BY a)",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "",
		"SELECT SUM(x) OVER w FROM t WINDOW w AS (PARTITION BY a)", true, Disposition::DEFERRED,
	},
	{
		"lag window function",
		"SELECT LAG(a, 1) OVER (ORDER BY b) FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "",
		"SELECT LAG(a, 1) OVER (ORDER BY b) FROM t", true, Disposition::DEFERRED,
	},
	{
		"empty window specification",
		"SELECT ROW_NUMBER() OVER () FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "",
		"SELECT ROW_NUMBER() OVER () FROM t", true, Disposition::DEFERRED,
	},

	// --- functions ----------------------------------------------------------
	{
		"basic aggregates including deferred AVG",
		"SELECT COUNT(*), SUM(a), AVG(b), MIN(c), MAX(d) FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "",
		"SELECT COUNT(*), SUM(a), AVG(b), MIN(c), MAX(d) FROM t", true, Disposition::DEFERRED,
	},
	{
		"date_format parses but is deferred",
		"SELECT DATE_FORMAT(d, '%Y-%m') FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "",
		"SELECT DATE_FORMAT(d, '%Y-%m') FROM t", true, Disposition::DEFERRED,
	},
	{
		"group_concat parses but is deferred",
		"SELECT GROUP_CONCAT(DISTINCT a ORDER BY a SEPARATOR ',') FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "",
		"SELECT GROUP_CONCAT(DISTINCT a ORDER BY a SEPARATOR ',') FROM t", true, Disposition::DEFERRED,
	},
	{
		"null handling functions are parser-complete",
		"SELECT COALESCE(a,b), IFNULL(a,b), NULLIF(a,b) FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "",
		"SELECT COALESCE(a, b), IFNULL(a, b), NULLIF(a, b) FROM t", true, Disposition::DEFERRED,
	},
	{
		"unknown function parses but must be refused semantically",
		"SELECT definitely_unknown_func(1)",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "",
		"SELECT DEFINITELY_UNKNOWN_FUNC(1)", true, Disposition::REFUSED,
	},
	{
		"side-effecting functions parse but must be refused",
		"SELECT NEXTVAL('s'), SETVAL('s', 1)",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "",
		"SELECT NEXTVAL('s'), SETVAL('s', 1)", true, Disposition::REFUSED,
	},
	{
		"aggregate DISTINCT produces an incomplete AST",
		"SELECT COUNT(DISTINCT a) FROM t",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "DISTINCT a) FROM t", "SELECT ", false, Disposition::PARSER_GAP,
	},
	{
		"sum DISTINCT produces an incomplete AST",
		"SELECT SUM(DISTINCT a) FROM t",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "DISTINCT a) FROM t", "SELECT ", false, Disposition::PARSER_GAP,
	},

	// --- typed SELECT and literal syntax -----------------------------------
	{
		"CAST type names",
		"SELECT CAST(a AS DECIMAL(10,2)), CAST(b AS SIGNED), CAST(c AS CHAR) FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "",
		"SELECT CAST(a AS DECIMAL(10,2)), CAST(b AS SIGNED), CAST(c AS CHAR) FROM t",
		true, Disposition::DEFERRED,
	},
	{
		"collation clause parses but is deferred",
		"SELECT 'a' COLLATE utf8mb4_bin",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT 'a' COLLATE utf8mb4_bin", true, Disposition::DEFERRED,
	},
	{
		"charset introducer parses but is deferred",
		"SELECT _utf8mb4'abc'",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT _utf8mb4'abc'", true, Disposition::DEFERRED,
	},
	{
		"binary and hex literals",
		"SELECT 0x41, X'41', b'101'",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT 0x41, X'41', b'101'", true, Disposition::DEFERRED,
	},
	{
		"standard DATE literal is left unparsed",
		"SELECT DATE '2024-01-01'",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "DATE '2024-01-01'", "SELECT ", false, Disposition::PARSER_GAP,
	},
	{
		"national string literal is left unparsed",
		"SELECT N'abc'",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "N'abc'", "SELECT ", false, Disposition::PARSER_GAP,
	},
	{
		"unary BINARY operator is left unparsed",
		"SELECT BINARY 'a'",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "BINARY 'a'", "SELECT ", false, Disposition::PARSER_GAP,
	},
	{
		"null-safe equality preserves its operator",
		"SELECT a <=> b FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT a <=> b FROM t", true, Disposition::DEFERRED,
	},
	{
		"logical AND preserves its operator",
		"SELECT a && b FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT a && b FROM t", true, Disposition::DEFERRED,
	},
	{
		"REGEXP followed by RLIKE is partial",
		"SELECT a REGEXP 'x', a RLIKE 'x' FROM t",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "'x' FROM t", "SELECT a REGEXP 'x', a AS RLIKE",
		false, Disposition::PARSER_GAP,
	},
	{
		"LIKE ESCAPE is partial",
		"SELECT * FROM t WHERE a LIKE '%x%' ESCAPE '!'",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "ESCAPE", "SELECT * FROM t WHERE a LIKE '%x%'",
		false, Disposition::PARSER_GAP,
	},
	{
		"IS UNKNOWN is partial",
		"SELECT * FROM t WHERE a IS UNKNOWN",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "UNKNOWN", "SELECT * FROM t WHERE a",
		false, Disposition::PARSER_GAP,
	},
	{
		"executable comment silently changes an otherwise complete expression",
		"SELECT 1 /*! + 1 */",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT 1", true, Disposition::PARSER_GAP,
	},
	{
		"MariaDB executable comment also loses its contents",
		"SELECT 1 /*M! + 1 */",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT 1", true, Disposition::PARSER_GAP,
	},
	{
		"MySQL executable comment is rejected",
		"SELECT /*!40101 1 */",
		ParseResult::ERROR, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "/", "SELECT ", false, Disposition::PARSER_GAP,
	},
	{
		"select option HIGH_PRIORITY is retained",
		"SELECT HIGH_PRIORITY a FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT HIGH_PRIORITY a FROM t",
		true, Disposition::REFUSED,
	},
	{
		"select option SQL_NO_CACHE is retained",
		"SELECT SQL_NO_CACHE a FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT SQL_NO_CACHE a FROM t",
		true, Disposition::REFUSED,
	},
	{
		"SQL_CALC_FOUND_ROWS is parsed as a select option",
		"SELECT SQL_CALC_FOUND_ROWS a FROM t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT SQL_CALC_FOUND_ROWS a FROM t",
		true, Disposition::REFUSED,
	},
	{
		"negative NULLS FIRST is not MySQL grammar",
		"SELECT * FROM t ORDER BY a NULLS FIRST",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "NULLS FIRST", "SELECT * FROM t ORDER BY a",
		false, Disposition::REFUSED,
	},

	// --- user variables, placeholders and system variables -----------------
	{
		"user variable read",
		"SELECT @a",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT @a", true, Disposition::REFUSED,
	},
	{
		"user variable in arithmetic",
		"SELECT @a + 1",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT @a + 1", true, Disposition::REFUSED,
	},
	{
		"quoted user variable",
		"SELECT @`a b`",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT @`a b`", true, Disposition::REFUSED,
	},
	{
		"user variable assignment is partial",
		"SELECT @a := 1",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "1", "SELECT @a AS :=",
		false, Disposition::PARSER_GAP,
	},
	{
		"placeholder expression",
		"SELECT ? + ?",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT ? + ?", true, Disposition::REFUSED,
	},
	{
		"placeholder predicate",
		"SELECT * FROM t WHERE a = ?",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM t WHERE a = ?", true, Disposition::REFUSED,
	},
	{
		"system variable is not flagged as a user variable",
		"SELECT @@version",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT @@version", true, Disposition::REFUSED,
	},

	// --- non-SELECT and endpoint boundaries --------------------------------
	{
		"insert parses as a non-select statement",
		"INSERT INTO t VALUES (1)",
		ParseResult::OK, StmtType::INSERT, true, true,
		NodeType::NODE_UNKNOWN, "", "INSERT INTO t VALUES (1)", false, Disposition::OUT_OF_SCOPE,
	},
	{
		"update parses as a non-select statement",
		"UPDATE t SET a = 1",
		ParseResult::OK, StmtType::UPDATE, true, true,
		NodeType::NODE_UNKNOWN, "", "UPDATE t SET a = 1", false, Disposition::OUT_OF_SCOPE,
	},
	{
		"delete parses as a non-select statement",
		"DELETE FROM t WHERE a = 1",
		ParseResult::OK, StmtType::DELETE_STMT, true, true,
		NodeType::NODE_UNKNOWN, "", "DELETE FROM t WHERE a = 1", false, Disposition::OUT_OF_SCOPE,
	},
	{
		"TABLE statement classifies as SELECT but has no select AST",
		"TABLE t",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_UNKNOWN, "", "TABLE t", false, Disposition::OUT_OF_SCOPE,
	},
	{
		"locking select",
		"SELECT * FROM t FOR UPDATE",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_SELECT_STMT, "", "SELECT * FROM t FOR UPDATE", true, Disposition::REFUSED,
	},
	{
		"INTO OUTFILE is partial",
		"SELECT * FROM t INTO OUTFILE '/tmp/x'",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "INTO OUTFILE", "SELECT * FROM t",
		false, Disposition::REFUSED,
	},
	{
		"INTO user variable is partial",
		"SELECT 1 INTO @x",
		ParseResult::OK, StmtType::SELECT, false, true,
		NodeType::NODE_SELECT_STMT, "INTO @x", "SELECT 1",
		false, Disposition::PARSER_GAP,
	},
	{
		"UNION ALL has a compound root",
		"SELECT * FROM t1 UNION ALL SELECT * FROM t2",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_COMPOUND_QUERY, "", "SELECT * FROM t1 UNION ALL SELECT * FROM t2",
		false, Disposition::DEFERRED,
	},
	{
		"UNION DISTINCT normalises to UNION",
		"SELECT * FROM t1 UNION DISTINCT SELECT * FROM t2",
		ParseResult::OK, StmtType::SELECT, true, true,
		NodeType::NODE_COMPOUND_QUERY, "", "SELECT * FROM t1 UNION SELECT * FROM t2",
		false, Disposition::DEFERRED,
	},
};

const NodeFixture kNodeFixtures[] = {
	{"select root", "SELECT 1", NodeType::NODE_SELECT_STMT, 1, nullptr},
	{"from clause", "SELECT * FROM t", NodeType::NODE_FROM_CLAUSE, 1, nullptr},
	{"limit clause", "SELECT * FROM t LIMIT 10", NodeType::NODE_LIMIT_CLAUSE, 1, nullptr},
	{"join clause", "SELECT * FROM t1 LEFT JOIN t2 ON t1.id = t2.id", NodeType::NODE_JOIN_CLAUSE, 1, "LEFT JOIN"},
	{"CTE root", "WITH c AS (SELECT 1 AS x) SELECT x FROM c", NodeType::NODE_CTE, 1, nullptr},
	{"CTE definition", "WITH c AS (SELECT 1 AS x) SELECT x FROM c", NodeType::NODE_CTE_DEFINITION, 1, "c"},
	{"derived subquery", "SELECT * FROM (SELECT id FROM t) AS d", NodeType::NODE_SUBQUERY, 1, nullptr},
	{"window function", "SELECT ROW_NUMBER() OVER (ORDER BY a) FROM t", NodeType::NODE_WINDOW_FUNCTION, 1, nullptr},
	{"window clause", "SELECT SUM(x) OVER w FROM t WINDOW w AS (PARTITION BY a)", NodeType::NODE_WINDOW_CLAUSE, 1, nullptr},
	{"aggregate calls", "SELECT COUNT(*), SUM(a), AVG(b), MIN(c), MAX(d) FROM t", NodeType::NODE_FUNCTION_CALL, 5, "COUNT"},
	{"date_format call", "SELECT DATE_FORMAT(d, '%Y-%m') FROM t", NodeType::NODE_FUNCTION_CALL, 1, "DATE_FORMAT"},
	{"cast nodes", "SELECT CAST(a AS DECIMAL(10,2)), CAST(b AS SIGNED), CAST(c AS CHAR) FROM t", NodeType::NODE_TYPE_CAST, 3, nullptr},
	{"user variable node", "SELECT @a", NodeType::NODE_USER_VARIABLE, 1, "a"},
	{"placeholder nodes", "SELECT ? + ?", NodeType::NODE_PLACEHOLDER, 2, "?"},
	{"locking clause", "SELECT * FROM t FOR UPDATE", NodeType::NODE_LOCKING_CLAUSE, 1, nullptr},
	{"compound root", "SELECT * FROM t1 UNION ALL SELECT * FROM t2", NodeType::NODE_COMPOUND_QUERY, 1, nullptr},
	{"set operation", "SELECT * FROM t1 UNION ALL SELECT * FROM t2", NodeType::NODE_SET_OPERATION, 1, "UNION"},
};

void test_limit_shapes() {
	{
		Parser<Dialect::MySQL> parser;
		const char* sql = "SELECT * FROM t LIMIT 20, 10";
		ParseResult result = parser.parse(sql, std::strlen(sql));
		const AstNode* limit = direct_child(result.ast, NodeType::NODE_LIMIT_CLAUSE);
		ok(limit != nullptr, "limit comma: LIMIT clause exists");
		ok(limit != nullptr && (limit->flags & FLAG_LIMIT_COMMA) != 0,
		   "limit comma: FLAG_LIMIT_COMMA is set");
		ok(limit != nullptr && direct_child_count(limit) == 2,
		   "limit comma: exactly two bounds");
		const AstNode* count = limit != nullptr ? limit->first_child : nullptr;
		const AstNode* offset = count != nullptr ? count->next_sibling : nullptr;
		ok(count != nullptr && ref_string(count->value()) == "10",
		   "limit comma: first AST bound is the count");
		ok(offset != nullptr && ref_string(offset->value()) == "20",
		   "limit comma: second AST bound is the offset");
	}
	{
		Parser<Dialect::MySQL> parser;
		const char* sql = "SELECT * FROM t LIMIT 10 OFFSET 20";
		ParseResult result = parser.parse(sql, std::strlen(sql));
		const AstNode* limit = direct_child(result.ast, NodeType::NODE_LIMIT_CLAUSE);
		ok(limit != nullptr && (limit->flags & FLAG_LIMIT_COMMA) == 0,
		   "limit offset: comma flag is clear");
		ok(limit != nullptr && direct_child_count(limit) == 2,
		   "limit offset: exactly two bounds");
		const AstNode* count = limit != nullptr ? limit->first_child : nullptr;
		const AstNode* offset = count != nullptr ? count->next_sibling : nullptr;
		ok(count != nullptr && ref_string(count->value()) == "10",
		   "limit offset: first AST bound is the count");
		ok(offset != nullptr && ref_string(offset->value()) == "20",
		   "limit offset: second AST bound is the offset");
	}
}

void test_identifier_flags() {
	Parser<Dialect::MySQL> parser;
	const char* sql = "SELECT `a``b`, `Order` FROM `t`";
	ParseResult result = parser.parse(sql, std::strlen(sql));
	size_t count = 0;
	const AstNode* column = find_node(result.ast, NodeType::NODE_COLUMN_REF, count);
	ok(column != nullptr, "identifier flags: quoted column node exists");
	ok(count == 2, "identifier flags: both quoted projections are column references");
	ok(column != nullptr && (column->flags & FLAG_IDENT_DELIMITED) != 0,
	   "identifier flags: quoted column is marked delimited");
	ok(column != nullptr && ref_string(column->value()) == "a``b",
	   "identifier flags: doubled backtick remains in the AST value");
	ok(column != nullptr && ref_string(column->source()) == "`a``b`",
	   "identifier flags: original quoted source is retained");
	const AstNode* table = find_node(result.ast, NodeType::NODE_IDENTIFIER, count);
	ok(table != nullptr && ref_string(table->value()) == "t",
	   "identifier flags: quoted table name is decoded in the AST value");
	ok(table != nullptr && (table->flags & FLAG_IDENT_DELIMITED) != 0,
	   "identifier flags: quoted table name is marked delimited");
}

void test_double_quote_literal() {
	Parser<Dialect::MySQL> parser;
	const char* sql = "SELECT \"x\" FROM t";
	ParseResult result = parser.parse(sql, std::strlen(sql));
	size_t count = 0;
	const AstNode* literal = find_node(result.ast, NodeType::NODE_LITERAL_STRING, count);
	ok(literal != nullptr && count == 1, "double quote: double-quoted text is one string literal");
	ok(literal != nullptr && ref_string(literal->value()) == "x",
	   "double quote: literal value is x");
	const AstNode* identifier = find_node(result.ast, NodeType::NODE_COLUMN_REF, count);
	ok(identifier == nullptr,
	   "double quote: ANSI_QUOTES interpretation is not used by the MySQL parser");
}

void test_user_variables_and_placeholders() {
	{
		Parser<Dialect::MySQL> parser;
		const char* sql = "SELECT @a + 1";
		ParseResult result = parser.parse(sql, std::strlen(sql));
		ok(result.has_user_variables, "user variable: parse marks has_user_variables");
		ok(classify_mysql_user_variable_usage(result) == UserVariableUsage::READ_ONLY,
		   "user variable: read-only use is classified as read-only");
	}
	{
		Parser<Dialect::MySQL> parser;
		const char* sql = "SELECT @a := 1";
		ParseResult result = parser.parse(sql, std::strlen(sql));
		ok(result.has_user_variables, "user variable assignment: marked as user variable input");
		ok(classify_mysql_user_variable_usage(result) == UserVariableUsage::UNSAFE_OR_UNKNOWN,
		   "user variable assignment: usage is unsafe because the AST is incomplete");
	}
	{
		Parser<Dialect::MySQL> parser;
		const char* sql = "SELECT @@version";
		ParseResult result = parser.parse(sql, std::strlen(sql));
		ok(!result.has_user_variables,
		   "system variable: ParserSQL does not set has_user_variables");
		size_t count = 0;
		const AstNode* column = find_node(result.ast, NodeType::NODE_COLUMN_REF, count);
		ok(column != nullptr && ref_string(column->value()) == "@@version",
		   "system variable: disguised as an ordinary column reference");
		ok(find_node(result.ast, NodeType::NODE_USER_VARIABLE, count) == nullptr,
		   "system variable: no user-variable AST node is produced");
	}
	{
		Parser<Dialect::MySQL> parser;
		const char* sql = "SELECT ? + ?";
		ParseResult result = parser.parse(sql, std::strlen(sql));
		size_t count = 0;
		find_node(result.ast, NodeType::NODE_PLACEHOLDER, count);
		ok(count == 2, "placeholder: both placeholders are represented");
	}
}

void test_table_statement_root() {
	Parser<Dialect::MySQL> parser;
	const char* sql = "TABLE t";
	ParseResult result = parser.parse(sql, std::strlen(sql));
	ok(result.status == ParseResult::OK && result.full_input,
	   "TABLE: classified complete input");
	ok(result.stmt_type == StmtType::SELECT, "TABLE: classified as SELECT");
	ok(result.ast != nullptr && result.ast->type != NodeType::NODE_SELECT_STMT,
	   "TABLE: root is not an ordinary SELECT AST");
	ok(!parser_complete_select(result),
	   "TABLE: strict single-SELECT parser gate rejects it");
}

void test_parse_all_framing() {
	{
		Parser<Dialect::MySQL> parser;
		const char* sql = "SELECT 1; SELECT 2; /* x */ SELECT 3";
		BatchParseResult batch = parser.parse_all(sql, std::strlen(sql));
		ok(batch.statements.size() == 3, "parse_all: three statements are framed");
		ok(batch.ok(), "parse_all: every statement has a complete SELECT AST");
		if (batch.statements.size() == 3) {
			ok(batch.statements[0].offset == 0, "parse_all: first offset is zero");
			ok(ref_string(batch.statements[0].source) == "SELECT 1;",
			   "parse_all: first source span includes its semicolon");
			ok(batch.statements[1].offset == 10, "parse_all: second offset follows the semicolon");
			ok(ref_string(batch.statements[1].source) == "SELECT 2;",
			   "parse_all: second source span includes its semicolon");
			ok(batch.statements[2].offset == 28, "parse_all: comment before third statement is skipped");
			ok(ref_string(batch.statements[2].source) == "SELECT 3",
			   "parse_all: final source span has no semicolon");
			for (size_t i = 0; i < batch.statements.size(); ++i) {
				ok(batch.statements[i].result.ok() && batch.statements[i].result.full_input,
				   "parse_all: statement %zu is complete", i);
				ok(batch.statements[i].result.ast != nullptr &&
				   batch.statements[i].result.ast->type == NodeType::NODE_SELECT_STMT,
				   "parse_all: statement %zu has a SELECT root", i);
			}
		}
	}
	{
		Parser<Dialect::MySQL> parser;
		const char* sql = "  ; /* c */ ; SELECT 1; SELECT 2 /* x */; SELECT ; ";
		BatchParseResult batch = parser.parse_all(sql, std::strlen(sql));
		ok(batch.statements.size() == 3, "parse_all: empty and comment-only segments are skipped");
		ok(!batch.ok(), "parse_all: a failing statement makes the batch not ok");
		if (batch.statements.size() == 3) {
			ok(batch.statements[0].result.ok(), "parse_all: first real statement is ok");
			ok(batch.statements[1].result.ok(), "parse_all: second real statement is ok");
			ok(batch.statements[2].result.status == ParseResult::ERROR,
			   "parse_all: trailing SELECT is an error record");
			ok(batch.statements[2].result.error.offset == 49,
			   "parse_all: error offset points into the original input");
		}
	}
	{
		Parser<Dialect::MySQL> parser;
		BatchParseResult batch = parser.parse_all("", 0);
		ok(batch.statements.empty(), "parse_all: empty input produces no statements");
		ok(batch.ok(), "parse_all: empty batch is successful");
	}
}

void test_ast_walk_and_transform() {
	Parser<Dialect::MySQL> source;
	const char* sql = "SELECT 1 + 2 FROM t";
	ParseResult result = source.parse(sql, std::strlen(sql));
	ok(result.ast != nullptr, "ast transform: source query parses");

	size_t visited = 0;
	bool saw_root_depth_zero = false;
	AstWalkResult walked = walk_ast(result.ast, [&](const AstNode&, const AstVisitContext& context) {
		++visited;
		if (context.depth == 0 && context.parent == nullptr) {
			saw_root_depth_zero = true;
		}
		return AstVisitAction::Continue;
	});
	ok(walked.status == AstWalkStatus::Completed && visited > 0,
	   "ast walk: completes and visits nodes");
	ok(saw_root_depth_zero, "ast walk: root is reported at depth zero");

	Parser<Dialect::MySQL> copy;
	AstCloneResult cloned = clone_ast(result.ast, copy.arena());
	ok(cloned.ok() && cloned.ast != nullptr, "ast transform: clone succeeds");
	ok(cloned.ast != result.ast, "ast transform: clone is a distinct allocation");
	ok(emit_sql(copy, cloned.ast) == "SELECT 1 + 2 FROM t",
	   "ast transform: clone emits the same SQL");

	AstNode* literal_one = nullptr;
	walk_ast(cloned.ast, [&](const AstNode& node, const AstVisitContext&) {
		if (node.type == NodeType::NODE_LITERAL_INT && ref_string(node.value()) == "1") {
			literal_one = const_cast<AstNode*>(&node);
			return AstVisitAction::Stop;
		}
		return AstVisitAction::Continue;
	});
	ok(literal_one != nullptr, "ast transform: literal 1 is found");
	AstNode* replacement = make_owned_node(copy.arena(), NodeType::NODE_LITERAL_INT,
	                                       StringRef{"10", 2});
	AstError replaced = replace_ast_subtree(cloned.ast, literal_one, replacement);
	ok(replaced == AstError::None, "ast transform: subtree replacement succeeds");
	ok(emit_sql(copy, cloned.ast) == "SELECT 10 + 2 FROM t",
	   "ast transform: replacement changes emitted SQL");
}

void test_provenance_and_operators() {
	for (const char* sql : {"SELECT 1 /*! + 1 */", "SELECT 1 /*M! + 1 */"}) {
		Parser<Dialect::MySQL> parser;
		ParseResult result = parser.parse(sql, std::strlen(sql));
		ok(result.full_input && result.has_comments && result.has_executable_comments,
		   "provenance: executable comment is recorded for %s", sql);
	}
	for (const char* sql : {"SELECT 1 /* ordinary */", "SELECT '/*! quoted */'"}) {
		Parser<Dialect::MySQL> parser;
		ParseResult result = parser.parse(sql, std::strlen(sql));
		ok(!result.has_executable_comments, "provenance: no executable comment in %s", sql);
	}
	{
		Parser<Dialect::MySQL> parser;
		const char* sql = "SELECT (a /* inner */ + b) AS x, c <=> d, e && f FROM t";
		ParseResult result = parser.parse(sql, std::strlen(sql));
		ok(result.full_input && result.has_comments, "provenance: inline comment recorded");
		const AstNode* list = direct_child(result.ast, NodeType::NODE_SELECT_ITEM_LIST);
		const AstNode* item = list != nullptr ? list->first_child : nullptr;
		ok(item != nullptr && ref_string(item->source()) == "(a /* inner */ + b)",
		   "provenance: projection source preserves expression and excludes alias");
		ok(item != nullptr && item->source().ptr == std::strstr(sql, "(a"),
		   "provenance: projection source points into the input");
		size_t count = 0;
		const AstNode* op = find_node(result.ast, NodeType::NODE_BINARY_OP, count);
		bool null_safe = false, logical_and = false;
		walk_ast(result.ast, [&](const AstNode& node, const AstVisitContext&) {
			if (node.type == NodeType::NODE_BINARY_OP) {
				null_safe |= ref_string(node.value()) == "<=>";
				logical_and |= ref_string(node.value()) == "&&";
			}
			return AstVisitAction::Continue;
		});
		ok(op != nullptr && null_safe && logical_and,
		   "operators: null-safe equality and logical AND retain distinct AST values");
	}
}

void test_direct_emitter_comments() {
	Parser<Dialect::MySQL> parser;
	const char* sql = "SELECT 1 # hash comment\n";
	ParseResult result = parser.parse(sql, std::strlen(sql));
	ok(result.ok() && result.full_input, "comment handling: hash comment is consumed");
	ok(emit_sql(parser, result.ast) == "SELECT 1",
	   "comment handling: emitter does not retain the comment");
}

}  // namespace

int main() {
	plan(NO_PLAN);

	for (const ParseFixture& fixture : kParseFixtures) {
		run_fixture(fixture);
	}
	for (const NodeFixture& fixture : kNodeFixtures) {
		run_node_fixture(fixture);
	}
	test_limit_shapes();
	test_identifier_flags();
	test_double_quote_literal();
	test_user_variables_and_placeholders();
	test_table_statement_root();
	test_parse_all_framing();
	test_ast_walk_and_transform();
	test_direct_emitter_comments();
	test_provenance_and_operators();

	return exit_status();
}
