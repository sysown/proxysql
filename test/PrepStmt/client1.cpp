#include "proxysql.h"
#include "cpp.h"

#define QUERY1	"SELECT ?"
MYSQL *mysql;
MYSQL_STMT *stmt;
uint32_t statement_id;
uint16_t num_params;
uint16_t num_columns;
uint16_t warning_count;

int main() {
	mysql = mysql_init(NULL);
	if (!mysql_real_connect(mysql,"127.0.0.1","root","","test",3306,NULL,0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
		exit(EXIT_FAILURE);
	}
	stmt = mysql_stmt_init(mysql);
	if (!stmt) {
		fprintf(stderr, " mysql_stmt_init(), out of memory\n");
		exit(EXIT_FAILURE);
	}
	if (mysql_stmt_prepare(stmt, QUERY1, strlen(QUERY1))) {
		fprintf(stderr, " mysql_stmt_prepare(), failed: %s\n" , mysql_stmt_error(stmt));
		exit(EXIT_FAILURE);
	}
//	param_count= mysql_stmt_param_count(stmt);
//	fprintf(stdout, " total parameters in Query1 : %d\n", param_count);
	statement_id=stmt->stmt_id;
	num_params=stmt->param_count;
	num_columns=stmt->field_count;
	warning_count=stmt->upsert_status.warning_count;
	fprintf(stdout, "statement_id=%d , columns=%d , params=%d , warnings=%d\n", statement_id, num_columns, num_params, warning_count);
	return 0;
}
