#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

const int NUM_ROWS=5;

int restore_admin(MYSQL* mysqladmin) {
	MYSQL_QUERY(mysqladmin, "load mysql query rules from disk");
	MYSQL_QUERY(mysqladmin, "load mysql query rules to runtime");
	MYSQL_QUERY(mysqladmin, "load mysql servers from disk");
	MYSQL_QUERY(mysqladmin, "load mysql servers to runtime");

	return 0;
}

long long global_counter(MYSQL* mysqladmin, const char* counter_name) {
	const std::string query =
		"SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='" +
		std::string(counter_name) + "'";
	if (mysql_query(mysqladmin, query.c_str())) {
		diag("Failed to read global counter '%s': %s", counter_name, mysql_error(mysqladmin));
		return -1;
	}

	MYSQL_RES* result = mysql_store_result(mysqladmin);
	if (!result) {
		diag("No result while reading global counter '%s': %s", counter_name, mysql_error(mysqladmin));
		return -1;
	}
	MYSQL_ROW row = mysql_fetch_row(result);
	const long long value = row && row[0] ? strtoll(row[0], NULL, 10) : -1;
	mysql_free_result(result);
	return value;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(13);
	diag("Testing PS large resultset");

	MYSQL* mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();

	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	}

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();
	
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	MYSQL_QUERY(mysqladmin, "delete from mysql_query_rules");
	MYSQL_QUERY(mysqladmin, "load mysql query rules to runtime");

	MYSQL_QUERY(mysqladmin, "delete from mysql_servers where hostgroup_id=1");
	MYSQL_QUERY(mysqladmin, "load mysql servers to runtime");

	if (create_table_test_sbtest1(NUM_ROWS,mysql)) {
		fprintf(stderr, "File %s, line %d, Error: create_table_test_sbtest1() failed\n", __FILE__, __LINE__);
		return exit_status();
	}

	std::string query = "";

	#define STRING_SIZE 4096

	MYSQL_BIND bind2[8];
	int int_data1;
	int int_data2;
	int int_data3;
	int int_data4;
	char str_data1[STRING_SIZE];
	char str_data2[STRING_SIZE];
	char str_data3[STRING_SIZE];
	char str_data4[STRING_SIZE];
	my_bool is_null2[8];
	long unsigned int length2[8];
	my_bool error2[8];
	int row_count2=0;

	for (int loops=0; loops<3; loops++) {
	MYSQL_STMT *stmt2a = mysql_stmt_init(mysql);
	if (!stmt2a)
	{
		ok(false, " mysql_stmt_init(), out of memory\n");
		restore_admin(mysqladmin);
		return exit_status();
	}
	query = "SELECT t1.id id1, t2.id id2 FROM test.sbtest1 t1 JOIN test.sbtest1 t2 LIMIT 20";
	if (mysql_stmt_prepare(stmt2a,query.c_str(), query.size())) {
		fprintf(stderr, "Query error %s\n", mysql_error(mysql));
		mysql_close(mysql);
		mysql_library_end();
		restore_admin(mysqladmin);
		return exit_status();
	}

	if (mysql_stmt_execute(stmt2a))
	{
		fprintf(stderr, " mysql_stmt_execute(), failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt2a));
		restore_admin(mysqladmin);
		return exit_status();
	}

	#define STRING_SIZE 4096

	MYSQL_BIND bind2a[8];
	my_bool is_null2a[8];
	long unsigned int length2a[8];
	my_bool error2a[8];
	int row_count2a=0;
	memset(bind2a, 0, sizeof(bind2a));

	bind2a[0].buffer_type= MYSQL_TYPE_LONG;
	bind2a[0].buffer= (char *)&int_data1;
	bind2a[0].buffer_length= 8;

	bind2a[1].buffer_type= MYSQL_TYPE_LONG;
	bind2a[1].buffer= (char *)&int_data2;
	bind2a[1].buffer_length= 8;

	MYSQL_RES     * prepare_meta_result = mysql_stmt_result_metadata(stmt2a);
	if (mysql_stmt_bind_result(stmt2a, bind2a))
	{
		fprintf(stderr, " mysql_stmt_bind_result() failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt2a));
		restore_admin(mysqladmin);
		return exit_status();
	}

/*
	// WE INTENTIONALLY SKIP THIS
	if (mysql_stmt_store_result(stmt2a))
	{
		fprintf(stderr, " mysql_stmt_store_result() failed\n");
		ok(false, " %s\n", mysql_stmt_error(stmt2a));
		restore_admin(mysqladmin);
		return exit_status();
	}
*/

	int stmt2aRC = 0;
	while (!(stmt2aRC = mysql_stmt_fetch(stmt2a)))
	{
		 fprintf(stderr, "Row %d : %d , %d\n", row_count2a, int_data1, int_data2);
		row_count2a++;
	}
	ok(row_count2a==20, "Fetched %d rows. To fetch 20 rows", row_count2a);

	if (prepare_meta_result) {
		mysql_free_result(prepare_meta_result);
	}
	
	if (mysql_stmt_close(stmt2a))
	{
		fprintf(stderr, " failed while closing the statement\n");
		ok(false, " %s\n", mysql_error(mysql));
		restore_admin(mysqladmin);
		return exit_status();
		}
		}

	// The trailing comment avoids the direct suffix match. The FOR UPDATE clause
	// remains in the final 128 bytes, so this must use the long-query scan.
	if (mysql_query(mysql, "START TRANSACTION")) {
		diag("Failed to start transaction for FOR UPDATE: %s", mysql_error(mysql));
		restore_admin(mysqladmin);
		mysql_close(mysql);
		return exit_status();
	}
	MYSQL_STMT* locking_stmt = mysql_stmt_init(mysql);
	const std::string locking_query =
		"SELECT id FROM test.sbtest1 WHERE id=1" + std::string(160, ' ') +
		" FOR UPDATE /* long-query fallback scan */";
	const long long selects_for_update_before =
		global_counter(mysqladmin, "Selects_for_update__autocommit0");
	const bool locking_prepared = locking_stmt &&
		mysql_stmt_prepare(locking_stmt, locking_query.c_str(), locking_query.size()) == 0;
	ok(locking_prepared, "Prepared a long SELECT ... FOR UPDATE statement with trailing comment");
	if (!locking_prepared) {
		if (locking_stmt) mysql_stmt_close(locking_stmt);
		mysql_query(mysql, "ROLLBACK");
		restore_admin(mysqladmin);
		mysql_close(mysql);
		return exit_status();
	}
	const long long selects_for_update_after =
		global_counter(mysqladmin, "Selects_for_update__autocommit0");
	ok(
		selects_for_update_after == selects_for_update_before + 1,
		"The long-query FOR UPDATE scanner classifies exactly one prepared statement"
	);

	const bool locking_executed = mysql_stmt_execute(locking_stmt) == 0;
	ok(locking_executed, "Executed the long SELECT ... FOR UPDATE statement");
	if (!locking_executed) {
		diag("FOR UPDATE execution failed: %s", mysql_stmt_error(locking_stmt));
		mysql_stmt_close(locking_stmt);
		mysql_query(mysql, "ROLLBACK");
		restore_admin(mysqladmin);
		mysql_close(mysql);
		return exit_status();
	}

	int locked_id = 0;
	MYSQL_BIND locking_bind {};
	locking_bind.buffer_type = MYSQL_TYPE_LONG;
	locking_bind.buffer = &locked_id;
	const bool locked_row_fetched =
		mysql_stmt_bind_result(locking_stmt, &locking_bind) == 0 &&
		mysql_stmt_store_result(locking_stmt) == 0 &&
		mysql_stmt_fetch(locking_stmt) == 0 && locked_id == 1;
	ok(locked_row_fetched, "FOR UPDATE returns the expected row through ProxySQL");
	mysql_stmt_close(locking_stmt);
	if (mysql_query(mysql, "COMMIT")) {
		diag("Failed to commit FOR UPDATE transaction: %s", mysql_error(mysql));
		restore_admin(mysqladmin);
		mysql_close(mysql);
		return exit_status();
	}

	// Prepare a metadata query, alter its table through a second ordinary client
	// connection, then verify that the repeated execute sees the new metadata.
	MYSQL* schema_mysql = mysql_init(NULL);
	if (!schema_mysql || !mysql_real_connect(schema_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("Second ProxySQL connection failed: %s", schema_mysql ? mysql_error(schema_mysql) : "mysql_init failed");
		if (schema_mysql) mysql_close(schema_mysql);
		restore_admin(mysqladmin);
		mysql_close(mysql);
		return exit_status();
	}
	const bool metadata_table_ready =
		mysql_query(schema_mysql, "DROP TABLE IF EXISTS test.ps_metadata_refresh") == 0 &&
		mysql_query(schema_mysql, "CREATE TABLE test.ps_metadata_refresh (id INT NOT NULL)") == 0;
	ok(metadata_table_ready, "Created table for prepared-statement metadata refresh");
	if (!metadata_table_ready) {
		diag("Metadata table setup failed: %s", mysql_error(schema_mysql));
		mysql_close(schema_mysql);
		restore_admin(mysqladmin);
		mysql_close(mysql);
		return exit_status();
	}

	MYSQL_STMT* metadata_stmt = mysql_stmt_init(mysql);
	const char* metadata_query = "SELECT * FROM test.ps_metadata_refresh";
	const bool metadata_prepared = metadata_stmt &&
		mysql_stmt_prepare(metadata_stmt, metadata_query, strlen(metadata_query)) == 0 &&
		mysql_stmt_execute(metadata_stmt) == 0;
	ok(metadata_prepared, "Prepared and executed metadata query before ALTER TABLE");
	if (!metadata_prepared) {
		if (metadata_stmt) mysql_stmt_close(metadata_stmt);
		mysql_close(schema_mysql);
		restore_admin(mysqladmin);
		mysql_close(mysql);
		return exit_status();
	}

	MYSQL_RES* metadata = mysql_stmt_result_metadata(metadata_stmt);
	const bool initial_metadata = metadata && mysql_num_fields(metadata) == 1 && mysql_stmt_store_result(metadata_stmt) == 0;
	ok(initial_metadata, "Prepared statement initially exposes one metadata column");
	if (metadata) mysql_free_result(metadata);
	mysql_stmt_free_result(metadata_stmt);

	const bool altered = mysql_query(schema_mysql, "ALTER TABLE test.ps_metadata_refresh ADD COLUMN payload VARCHAR(32)") == 0;
	ok(altered, "Altered the prepared statement table through a second ProxySQL connection");
	if (!altered) {
		diag("ALTER TABLE failed: %s", mysql_error(schema_mysql));
		mysql_stmt_close(metadata_stmt);
		mysql_close(schema_mysql);
		restore_admin(mysqladmin);
		mysql_close(mysql);
		return exit_status();
	}

	const bool metadata_reexecuted = mysql_stmt_execute(metadata_stmt) == 0;
	ok(metadata_reexecuted, "Re-executed prepared statement after ALTER TABLE");
	metadata = mysql_stmt_result_metadata(metadata_stmt);
	const bool refreshed_metadata = metadata && mysql_num_fields(metadata) == 2;
	ok(refreshed_metadata, "Prepared statement metadata refresh exposes the added column");
	if (metadata) mysql_free_result(metadata);
	mysql_stmt_close(metadata_stmt);
	mysql_close(schema_mysql);

	restore_admin(mysqladmin);

	mysql_close(mysql);
	mysql_library_end();

	return exit_status();
}
