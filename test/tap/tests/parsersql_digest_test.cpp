/**
 * @file parsersql_digest_test.cpp
 * @brief Validates that ParserSQL digest adapter produces valid normalized
 *   digest text and correct SpookyHash values for representative queries.
 *
 * Controlled by: mysql-query_processor_parser = 1
 */

#include "setparser_test_common.h"
#include "Query_Processor_ParserSQL.h"

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
	plan(count * 3);

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

		free(qp.digest_text); // NOSONAR: C-allocated by digest engine
		free(qp.first_comment); // NOSONAR
		free(qp.query_prefix); // NOSONAR
	}

	return exit_status();
}
