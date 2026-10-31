#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Query_Processor.h"

#include <cstring>
#include <string>

extern PgSQL_Query_Processor *GloPgQPro;

static SQP_par_t make_qp(const char* text) {
	SQP_par_t qp;
	memset(&qp, 0, sizeof(qp));
	qp.digest_text = strdup(text);
	return qp;
}

static void free_qp(SQP_par_t& qp) {
	if (qp.digest_text) { free(qp.digest_text); qp.digest_text = NULL; }
	if (qp.query_prefix) { free(qp.query_prefix); qp.query_prefix = NULL; }
}

static void test_select() {
	SQP_par_t qp = make_qp("SELECT * FROM t1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_SELECT,
		"PgSQL cmd_type: SELECT");
	free_qp(qp);
}

static void test_insert() {
	SQP_par_t qp = make_qp("INSERT INTO t1 VALUES (1)");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_INSERT,
		"PgSQL cmd_type: INSERT");
	free_qp(qp);
}

static void test_update() {
	SQP_par_t qp = make_qp("UPDATE t1 SET a = 1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_UPDATE,
		"PgSQL cmd_type: UPDATE");
	free_qp(qp);
}

static void test_delete() {
	SQP_par_t qp = make_qp("DELETE FROM t1 WHERE id = 1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_DELETE,
		"PgSQL cmd_type: DELETE");
	free_qp(qp);
}

static void test_begin() {
	SQP_par_t qp = make_qp("BEGIN");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_BEGIN,
		"PgSQL cmd_type: BEGIN");
	free_qp(qp);
}

static void test_commit() {
	SQP_par_t qp = make_qp("COMMIT");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_COMMIT,
		"PgSQL cmd_type: COMMIT");
	free_qp(qp);
}

static void test_rollback() {
	SQP_par_t qp = make_qp("ROLLBACK");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_ROLLBACK,
		"PgSQL cmd_type: ROLLBACK");
	free_qp(qp);
}

static void test_savepoint() {
	SQP_par_t qp = make_qp("SAVEPOINT sp1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_SAVEPOINT,
		"PgSQL cmd_type: SAVEPOINT");
	free_qp(qp);
}

static void test_set() {
	SQP_par_t qp = make_qp("SET search_path TO public");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_SET,
		"PgSQL cmd_type: SET");
	free_qp(qp);
}

static void test_show() {
	SQP_par_t qp = make_qp("SHOW TABLES");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_SHOW,
		"PgSQL cmd_type: SHOW");
	free_qp(qp);
}

static void test_create_table() {
	SQP_par_t qp = make_qp("CREATE TABLE t1 (id INT)");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_CREATE_TABLE,
		"PgSQL cmd_type: CREATE TABLE");
	free_qp(qp);
}

static void test_alter_table() {
	SQP_par_t qp = make_qp("ALTER TABLE t1 ADD COLUMN c INT");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_ALTER_TABLE,
		"PgSQL cmd_type: ALTER TABLE");
	free_qp(qp);
}

static void test_drop_table() {
	SQP_par_t qp = make_qp("DROP TABLE t1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_DROP_TABLE,
		"PgSQL cmd_type: DROP TABLE");
	free_qp(qp);
}

static void test_truncate() {
	SQP_par_t qp = make_qp("TRUNCATE TABLE t1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_TRUNCATE,
		"PgSQL cmd_type: TRUNCATE");
	free_qp(qp);
}

static void test_vacuum() {
	SQP_par_t qp = make_qp("VACUUM ANALYZE t1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_VACUUM,
		"PgSQL cmd_type: VACUUM");
	free_qp(qp);
}

static void test_analyze() {
	SQP_par_t qp = make_qp("ANALYZE t1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_ANALYZE,
		"PgSQL cmd_type: ANALYZE");
	free_qp(qp);
}

static void test_explain() {
	SQP_par_t qp = make_qp("EXPLAIN SELECT 1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_EXPLAIN,
		"PgSQL cmd_type: EXPLAIN");
	free_qp(qp);
}

static void test_grant() {
	SQP_par_t qp = make_qp("GRANT SELECT ON t1 TO user1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_GRANT,
		"PgSQL cmd_type: GRANT");
	free_qp(qp);
}

static void test_revoke() {
	SQP_par_t qp = make_qp("REVOKE SELECT ON t1 FROM user1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_REVOKE,
		"PgSQL cmd_type: REVOKE");
	free_qp(qp);
}

static void test_copy() {
	SQP_par_t qp = make_qp("COPY t1 FROM STDIN");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_COPY,
		"PgSQL cmd_type: COPY");
	free_qp(qp);
}

static void test_notify() {
	SQP_par_t qp = make_qp("NOTIFY my_channel");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_NOTIFY,
		"PgSQL cmd_type: NOTIFY");
	free_qp(qp);
}

static void test_listen() {
	SQP_par_t qp = make_qp("LISTEN my_channel");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_LISTEN,
		"PgSQL cmd_type: LISTEN");
	free_qp(qp);
}

static void test_unlisten() {
	SQP_par_t qp = make_qp("UNLISTEN my_channel");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_UNLISTEN,
		"PgSQL cmd_type: UNLISTEN");
	free_qp(qp);
}

static void test_lock() {
	SQP_par_t qp = make_qp("LOCK TABLE t1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_LOCK,
		"PgSQL cmd_type: LOCK");
	free_qp(qp);
}

static void test_reindex() {
	SQP_par_t qp = make_qp("REINDEX TABLE t1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_REINDEX,
		"PgSQL cmd_type: REINDEX");
	free_qp(qp);
}

static void test_create_index() {
	SQP_par_t qp = make_qp("CREATE INDEX idx ON t1 (id)");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_CREATE_INDEX,
		"PgSQL cmd_type: CREATE INDEX");
	free_qp(qp);
}

static void test_drop_index() {
	SQP_par_t qp = make_qp("DROP INDEX idx");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_DROP_INDEX,
		"PgSQL cmd_type: DROP INDEX");
	free_qp(qp);
}

static void test_create_schema() {
	SQP_par_t qp = make_qp("CREATE SCHEMA myschema");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_CREATE_SCHEMA,
		"PgSQL cmd_type: CREATE SCHEMA");
	free_qp(qp);
}

static void test_create_view() {
	SQP_par_t qp = make_qp("CREATE VIEW v1 AS SELECT 1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_CREATE_VIEW,
		"PgSQL cmd_type: CREATE VIEW");
	free_qp(qp);
}

static void test_create_sequence() {
	SQP_par_t qp = make_qp("CREATE SEQUENCE seq1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_CREATE_SEQUENCE,
		"PgSQL cmd_type: CREATE SEQUENCE");
	free_qp(qp);
}

static void test_create_function() {
	SQP_par_t qp = make_qp("CREATE FUNCTION f1() RETURNS INT AS $$ SELECT 1 $$ LANGUAGE SQL");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_CREATE_FUNCTION,
		"PgSQL cmd_type: CREATE FUNCTION");
	free_qp(qp);
}

static void test_create_trigger() {
	SQP_par_t qp = make_qp("CREATE TRIGGER tr1 BEFORE INSERT ON t1 FOR EACH ROW EXECUTE PROCEDURE f1()");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_CREATE_TRIGGER,
		"PgSQL cmd_type: CREATE TRIGGER");
	free_qp(qp);
}

static void test_create_extension() {
	SQP_par_t qp = make_qp("CREATE EXTENSION hstore");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_CREATE_EXTENSION,
		"PgSQL cmd_type: CREATE EXTENSION");
	free_qp(qp);
}

static void test_create_role() {
	SQP_par_t qp = make_qp("CREATE ROLE myrole");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_CREATE_ROLE,
		"PgSQL cmd_type: CREATE ROLE");
	free_qp(qp);
}

static void test_deallocate() {
	SQP_par_t qp = make_qp("DEALLOCATE stmt1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_DEALLOCATE,
		"PgSQL cmd_type: DEALLOCATE");
	free_qp(qp);
}

static void test_discard() {
	SQP_par_t qp = make_qp("DISCARD ALL");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_DISCARD,
		"PgSQL cmd_type: DISCARD");
	free_qp(qp);
}

static void test_reset() {
	SQP_par_t qp = make_qp("RESET ALL");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_RESET,
		"PgSQL cmd_type: RESET");
	free_qp(qp);
}

static void test_start_transaction() {
	SQP_par_t qp = make_qp("START TRANSACTION");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_BEGIN,
		"PgSQL cmd_type: START TRANSACTION → BEGIN");
	free_qp(qp);
}

static void test_rollback_to_savepoint() {
	SQP_par_t qp = make_qp("ROLLBACK TO SAVEPOINT sp1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_ROLLBACK_TO_SAVEPOINT,
		"PgSQL cmd_type: ROLLBACK TO SAVEPOINT");
	free_qp(qp);
}

static void test_release_savepoint() {
	SQP_par_t qp = make_qp("RELEASE SAVEPOINT sp1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_RELEASE_SAVEPOINT,
		"PgSQL cmd_type: RELEASE SAVEPOINT");
	free_qp(qp);
}

static void test_merge() {
	SQP_par_t qp = make_qp("MERGE INTO t1 USING t2 ON t1.id = t2.id WHEN MATCHED THEN UPDATE SET a = 1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_MERGE,
		"PgSQL cmd_type: MERGE");
	free_qp(qp);
}

static void test_fetch() {
	SQP_par_t qp = make_qp("FETCH FORWARD 10 FROM cur1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_FETCH,
		"PgSQL cmd_type: FETCH");
	free_qp(qp);
}

static void test_move() {
	SQP_par_t qp = make_qp("MOVE FORWARD 10 IN cur1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_MOVE,
		"PgSQL cmd_type: MOVE");
	free_qp(qp);
}

static void test_checkpoint() {
	SQP_par_t qp = make_qp("CHECKPOINT");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_CHECKPOINT,
		"PgSQL cmd_type: CHECKPOINT");
	free_qp(qp);
}

static void test_call() {
	SQP_par_t qp = make_qp("CALL my_procedure()");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_CALL,
		"PgSQL cmd_type: CALL");
	free_qp(qp);
}

static void test_create_database() {
	SQP_par_t qp = make_qp("CREATE DATABASE mydb");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_CREATE_DATABASE,
		"PgSQL cmd_type: CREATE DATABASE");
	free_qp(qp);
}

static void test_drop_database() {
	SQP_par_t qp = make_qp("DROP DATABASE mydb");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_DROP_DATABASE,
		"PgSQL cmd_type: DROP DATABASE");
	free_qp(qp);
}

static void test_create_type() {
	SQP_par_t qp = make_qp("CREATE TYPE mytype AS (a INT)");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_CREATE_TYPE,
		"PgSQL cmd_type: CREATE TYPE");
	free_qp(qp);
}

static void test_create_policy() {
	SQP_par_t qp = make_qp("CREATE POLICY p1 ON t1");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_CREATE_POLICY,
		"PgSQL cmd_type: CREATE POLICY");
	free_qp(qp);
}

static void test_pg_cancel_backend() {
	SQP_par_t qp = make_qp("SELECT pg_cancel_backend(123)");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_CANCEL_BACKEND,
		"PgSQL cmd_type: SELECT pg_cancel_backend → CANCEL_BACKEND");
	free_qp(qp);
}

static void test_pg_terminate_backend() {
	SQP_par_t qp = make_qp("SELECT pg_terminate_backend(123)");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_TERMINATE_BACKEND,
		"PgSQL cmd_type: SELECT pg_terminate_backend → TERMINATE_BACKEND");
	free_qp(qp);
}

static void test_unknown() {
	SQP_par_t qp = make_qp("XYZZY NOTASQLCOMMAND");
	ok(PgSQL_Query_Processor::query_parser_command_type(&qp) == PGSQL_QUERY_UNKNOWN,
		"PgSQL cmd_type: garbage → UNKNOWN");
	free_qp(qp);
}

int main() {
	plan(53);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_select();
	test_insert();
	test_update();
	test_delete();
	test_begin();
	test_commit();
	test_rollback();
	test_savepoint();
	test_set();
	test_show();
	test_create_table();
	test_alter_table();
	test_drop_table();
	test_truncate();
	test_vacuum();
	test_analyze();
	test_explain();
	test_grant();
	test_revoke();
	test_copy();
	test_notify();
	test_listen();
	test_unlisten();
	test_lock();
	test_reindex();
	test_create_index();
	test_drop_index();
	test_create_schema();
	test_create_view();
	test_create_sequence();
	test_create_function();
	test_create_trigger();
	test_create_extension();
	test_create_role();
	test_deallocate();
	test_discard();
	test_reset();
	test_start_transaction();
	test_rollback_to_savepoint();
	test_release_savepoint();
	test_merge();
	test_fetch();
	test_move();
	test_checkpoint();
	test_call();
	test_create_database();
	test_drop_database();
	test_create_type();
	test_create_policy();
	test_pg_cancel_backend();
	test_pg_terminate_backend();
	test_unknown();

	test_cleanup_minimal();
	return exit_status();
}
