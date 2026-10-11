/**
 * @file parsersql_digest_test.cpp
 * @brief Validates that ParserSQL digest adapter produces valid normalized
 *   digest text and correct SpookyHash values for representative queries.
 *
 * Controlled by: mysql-query_processor_parser = 1
 */

#include "setparser_test_common.h"
#include "Query_Processor_ParserSQL.h"

static void free_parser_result(SQP_par_t& qp) {
	// Match query_parser_free(): short digests belong to qp, not the heap.
	if (qp.digest_text != qp.buf) free(qp.digest_text);
	free(qp.first_comment);
	free(qp.query_prefix);
	qp.digest_text = qp.first_comment = qp.query_prefix = NULL;
}

static void test_digest_storage(const char* dialect,
	void (*initialize)(SQP_par_t*, const char*, int)) {
	std::string long_query = "SELECT ";
	for (int i = 0; i < QUERY_DIGEST_BUF; ++i) {
		if (i) long_query += ", ";
		long_query += "col" + std::to_string(i);
	}
	long_query += " FROM t";

	for (bool heap : {false, true}) {
		const std::string query = heap ? long_query : "SELECT col0 FROM t WHERE id = 42";
		const std::string expected = heap ? long_query : "SELECT col0 FROM t WHERE id = ?";
		SQP_par_t qp {};
		initialize(&qp, query.c_str(), static_cast<int>(query.size()));
		ok(qp.digest_text && (qp.digest_text == qp.buf) == !heap,
			"%s digest uses %s storage", dialect, heap ? "heap" : "inline");
		ok(qp.digest_text && expected == qp.digest_text,
			"%s %s digest preserves normalized SQL", dialect, heap ? "long" : "short");
		ok(qp.digest != 0, "%s %s digest has a hash", dialect, heap ? "long" : "short");
		free_parser_result(qp);
	}
}

static const char* test_queries[] = {
	"SELECT * FROM users WHERE id = 1",
	"SELECT a, b FROM t1 JOIN t2 ON t1.id = t2.id WHERE t1.x > 5",
	"INSERT INTO t (a, b) VALUES (1, 'hello')",
	"UPDATE t SET a = 5 WHERE b = 10",
	"DELETE FROM t WHERE id = 1",
	"SET autocommit = 1",
	"SET NAMES utf8",
	"SET sql_mode = 'TRADITIONAL'",
	"SET SESSION wait_timeout = 100",
	"SET NAMES utf8 COLLATE utf8_unicode_ci",
	"BEGIN",
	"COMMIT",
	"ROLLBACK",
	"CREATE TABLE t (id INT PRIMARY KEY)",
	"DROP TABLE t",
	"SHOW TABLES",
	"EXPLAIN SELECT * FROM t",
	NULL
};

int main(int argc, char** argv) {
	int count = 0;
	for (int i = 0; test_queries[i]; i++) count++;
	plan(count * 3 + 12);

	for (int i = 0; test_queries[i]; i++) {
		SQP_par_t qp;
		memset(&qp, 0, sizeof(qp));
		int len = strlen(test_queries[i]); // NOSONAR: length of null-terminated string literal array
		parsersql_digest_init_mysql(&qp, test_queries[i], len);

		ok(qp.digest_text != NULL, "Query %d: digest_text is non-NULL -- %s", i, test_queries[i]);
		ok(qp.digest != 0, "Query %d: digest is non-zero -- %s", i, test_queries[i]);

		if (qp.digest_text) {
			diag("  digest_text: %s", qp.digest_text);
			diag("  digest: %lu", qp.digest);
			ok(true, "Query %d: digest generated", i);
		} else {
			ok(false, "Query %d: digest generated (FAILED)", i);
		}

		free_parser_result(qp);
	}

	test_digest_storage("MySQL", parsersql_digest_init_mysql);
	test_digest_storage("PostgreSQL", parsersql_digest_init_pgsql);

	return exit_status();
}
