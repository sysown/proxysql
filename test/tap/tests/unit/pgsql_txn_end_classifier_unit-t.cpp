/**
 * @file pgsql_txn_end_classifier_unit-t.cpp
 * @brief Unit tests for pgsql_classify_plain_txn_end() (PgSQLTxnEndClassifier.h).
 *
 * PgSQL_Session answers some transaction ends itself instead of sending them to
 * PostgreSQL: a COMMIT / ROLLBACK received while the session holds no backend
 * transaction (handler_CommitRollback), and the statement that ends a poisoned
 * transaction. Both decisions go through pgsql_classify_plain_txn_end(), which
 * must accept only a lone, plain transaction end:
 *
 *     COMMIT | END | ROLLBACK | ABORT  [ WORK | TRANSACTION ]  [ ; ]
 *
 * with whitespace and comments around it. Everything else must be classified 0
 * so that it is forwarded. In particular:
 *   - COMMIT PREPARED 'gid' / ROLLBACK PREPARED 'gid' (two-phase commit). They
 *     used to be answered with a fake success and never reached PostgreSQL,
 *     leaving the prepared transaction (and its locks) behind;
 *   - "COMMIT; <more SQL>", whose trailing statements used to be dropped;
 *   - ROLLBACK TO SAVEPOINT and AND [NO] CHAIN;
 *   - words that merely start with a verb (ENDx, COMMITTED, ABORTED, ...).
 *
 * The end-to-end check of handler_CommitRollback is the TAP test
 * pgsql-commit_prepared_forwarded-t.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQLTxnEndClassifier.h"

#include <cstring>
#include <string>

struct txn_end_case {
	const char* sql;
	char expected;
};

// Statements that must be recognised as a plain transaction end.
static const txn_end_case plain_cases[] = {
	{ "COMMIT", 'C' },
	{ "commit", 'C' },
	{ "CoMmIt", 'C' },
	{ "END", 'C' },
	{ "end", 'C' },
	{ "ROLLBACK", 'R' },
	{ "rollback", 'R' },
	{ "ABORT", 'R' },
	{ "abort", 'R' },
	{ "COMMIT;", 'C' },
	{ "END;", 'C' },
	{ "ROLLBACK;", 'R' },
	{ "ABORT;", 'R' },
	{ "COMMIT WORK", 'C' },
	{ "COMMIT TRANSACTION", 'C' },
	{ "END WORK", 'C' },
	{ "END TRANSACTION;", 'C' },
	{ "ROLLBACK WORK", 'R' },
	{ "ROLLBACK TRANSACTION", 'R' },
	{ "ABORT WORK;", 'R' },
	{ "abort transaction", 'R' },
	{ "COMMIT ;", 'C' },
	{ "COMMIT   ", 'C' },
	{ "COMMIT\t\r\n", 'C' },
	{ "COMMIT\n;\n", 'C' },
	{ "COMMIT -- trailing comment", 'C' },
	{ "COMMIT; -- trailing comment", 'C' },
	{ "COMMIT /* c */", 'C' },
	{ "COMMIT /* c */ ;", 'C' },
	{ "ROLLBACK/*c*/WORK/*c*/;/*c*/", 'R' },
	{ "/* tag */ COMMIT", 'C' },
	{ "  ROLLBACK", 'R' },
	{ "-- c\nEND", 'C' },
};

// Statements that must NOT be answered locally: classified 0.
static const char* forward_cases[] = {
	// two-phase commit
	"COMMIT PREPARED 'gid'",
	"commit prepared 'gid'",
	"COMMIT PREPARED 'nonexistent';",
	"ROLLBACK PREPARED 'gid'",
	"rollback prepared 'gid'",
	"COMMIT /* c */ PREPARED 'gid'",
	"PREPARE TRANSACTION 'gid'",
	// multi-statement queries
	"COMMIT; INSERT INTO t VALUES (1)",
	"COMMIT;INSERT INTO t VALUES (1)",
	"END; SELECT 1",
	"ROLLBACK; DELETE FROM t",
	"ABORT; SELECT 1",
	"COMMIT;;",
	"COMMIT; COMMIT",
	"COMMIT WORK; SELECT 1",
	// savepoints
	"ROLLBACK TO SAVEPOINT s1",
	"ROLLBACK TO s1",
	"ROLLBACK WORK TO SAVEPOINT s1",
	"ROLLBACK TRANSACTION TO s1",
	"ABORT TO SAVEPOINT s1",
	"RELEASE SAVEPOINT s1",
	// chaining
	"COMMIT AND CHAIN",
	"COMMIT AND NO CHAIN",
	"ROLLBACK AND CHAIN",
	"ROLLBACK AND NO CHAIN",
	"END AND CHAIN",
	"ABORT AND CHAIN",
	"COMMIT WORK AND CHAIN",
	// no word boundary after the verb
	"ENDx",
	"END_x",
	"END1",
	"COMMITTED",
	"COMMIT_x",
	"ROLLBACKS",
	"ABORTED",
	"ABORT_ALL",
	// noise word not followed by a boundary, or doubled
	"COMMIT WORKS",
	"COMMIT TRANSACTIONS",
	"COMMIT WORK WORK",
	"COMMIT WORK TRANSACTION",
	// other statements
	"SELECT 1",
	"BEGIN",
	"START TRANSACTION",
	"COMMENT ON TABLE t IS 'x'",
	"",
	"   ",
	"/* only a comment */",
};

static std::string printable(const char* s) {
	std::string out;
	for (const char* p = s; *p; p++) {
		if (*p == '\n') out += "\\n";
		else if (*p == '\r') out += "\\r";
		else if (*p == '\t') out += "\\t";
		else out += *p;
	}
	return out;
}

static char classify(const char* sql) {
	return pgsql_classify_plain_txn_end(sql, strlen(sql));
}

// A Simple Query packet body ends with the null terminator, and
// handler_CommitRollback passes pkt->size - 5, which includes it.
static char classify_with_nul(const char* sql) {
	return pgsql_classify_plain_txn_end(sql, strlen(sql) + 1);
}

static void test_plain_cases() {
	for (const auto& c : plain_cases) {
		const char k = classify(c.sql);
		ok(k == c.expected, "plain: '%s' -> '%c' (got %d)",
			printable(c.sql).c_str(), c.expected, (int)k);
		const char kn = classify_with_nul(c.sql);
		ok(kn == c.expected, "plain, with trailing NUL: '%s' -> '%c' (got %d)",
			printable(c.sql).c_str(), c.expected, (int)kn);
	}
}

static void test_forward_cases() {
	for (const char* sql : forward_cases) {
		const char k = classify(sql);
		ok(k == 0, "forward: '%s' -> 0 (got %d)", printable(sql).c_str(), (int)k);
		const char kn = classify_with_nul(sql);
		ok(kn == 0, "forward, with trailing NUL: '%s' -> 0 (got %d)",
			printable(sql).c_str(), (int)kn);
	}
}

// The length bounds the scan: text past sql_len must not be read, and a
// statement cut short by the length must be classified on what is inside it.
static void test_length_bounds() {
	const char* buf = "COMMIT PREPARED 'gid'";
	ok(pgsql_classify_plain_txn_end(buf, 6) == 'C',
		"length bound: first 6 bytes of \"COMMIT PREPARED 'gid'\" are a plain COMMIT");
	ok(pgsql_classify_plain_txn_end(buf, 3) == 0,
		"length bound: \"COM\" is not a transaction end");
	ok(pgsql_classify_plain_txn_end(buf, 0) == 0,
		"length bound: empty input -> 0");
	const char nul_only[] = "";
	ok(pgsql_classify_plain_txn_end(nul_only, 1) == 0,
		"length bound: a lone NUL byte -> 0");
	// Embedded NUL in the middle is junk, not a terminator.
	const char embedded[] = "COMMIT\0; DELETE FROM t";
	ok(pgsql_classify_plain_txn_end(embedded, sizeof(embedded)) == 0,
		"embedded NUL before more SQL -> 0");
}

int main() {
	const int n_plain = sizeof(plain_cases) / sizeof(plain_cases[0]);
	const int n_forward = sizeof(forward_cases) / sizeof(forward_cases[0]);
	plan(1 + 2 * n_plain + 2 * n_forward + 5);

	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_plain_cases();
	test_forward_cases();
	test_length_bounds();

	test_cleanup_minimal();
	return exit_status();
}
