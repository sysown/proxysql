#include <cstring>
#include <unistd.h>
#include <vector>
#include <string>
#include <stdio.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

CommandLine cl;

std::string get_admin_mysql_ifaces(MYSQL *admin) {
	std::string ret = "";
	const char * query = (const char *)"SELECT variable_value FROM runtime_global_variables WHERE variable_name='admin-mysql_ifaces';";
	diag("Running query: %s", query);
	int rc = mysql_query(admin, query);
	ok(rc==0,"Query: %s . Error: %s", query, (rc == 0 ? "None" : mysql_error(admin)));
	if (rc == 0 ) {
		MYSQL_RES* res = mysql_store_result(admin);
		int num_rows = mysql_num_rows(res);
		ok(num_rows==1,"1 row expected when querying admin-mysql_ifaces. Returned: %d", num_rows);
		if (num_rows == 0) {
			diag("Fatal error in line %d: No result", __LINE__);
		} else if (num_rows > 1) {
			diag("Fatal error in line %d: returned rows more than 1: %d", __LINE__, num_rows);
		} else {
			MYSQL_ROW row = nullptr;
			while (( row = mysql_fetch_row(res) )) {
				ret = std::string(row[0]);
			}
		}
		mysql_free_result(res);
	}
	return ret;
}


int main(int argc, char** argv) {

	plan(2+2 + 13);

	MYSQL* proxysql_admin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxysql_admin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	} else {
		const char * c = mysql_get_ssl_cipher(proxysql_admin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxysql_admin->net.compress, "Compression: (%d)", proxysql_admin->net.compress);
	}

	{
		std::string current = get_admin_mysql_ifaces(proxysql_admin);
		char * expected = (char *)"0.0.0.0:6032;0.0.0.0:6031;/tmp/proxysql_admin.sock";
		ok(strcmp(current.c_str(),expected)==0, "Line: %d , Current admin-mysql_ifaces = %s . Expected = %s", __LINE__, current.c_str(), expected);
	}

	diag("Changing admin-mysql_ifaces to: 0.0.0.0:6032;/tmp/proxysql_admin.sock");
	MYSQL_QUERY(proxysql_admin,"SET admin-mysql_ifaces=\"0.0.0.0:6032;/tmp/proxysql_admin.sock\"");
	MYSQL_QUERY(proxysql_admin,"LOAD ADMIN VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxysql_admin,"SAVE ADMIN VARIABLES FROM RUNTIME");

	{
		std::string current = get_admin_mysql_ifaces(proxysql_admin);
		char * expected = (char *)"0.0.0.0:6032;/tmp/proxysql_admin.sock";
		ok(strcmp(current.c_str(),expected)==0, "Line: %d , Current admin-mysql_ifaces = %s . Expected = %s", __LINE__, current.c_str(), expected);
	}

	sleep(1);

	{
		diag("Connecting on Unix Socket");

		MYSQL* proxysql_admin2 = mysql_init(NULL);
		diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
		if (cl.use_ssl)
			mysql_ssl_set(proxysql_admin2, NULL, NULL, NULL, NULL, NULL);
		if (cl.compression)
			mysql_options(proxysql_admin2, MYSQL_OPT_COMPRESS, NULL);
		if (!mysql_real_connect(proxysql_admin2, NULL, cl.admin_username, cl.admin_password, NULL, 0, "/tmp/proxysql_admin.sock", 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin2));
			return EXIT_FAILURE;
		} else {
			const char * c = mysql_get_ssl_cipher(proxysql_admin2);
			ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
			ok(cl.compression == proxysql_admin2->net.compress, "Compression: (%d)", proxysql_admin2->net.compress);
		}

		std::string current = get_admin_mysql_ifaces(proxysql_admin2);
		char * expected = (char *)"0.0.0.0:6032;/tmp/proxysql_admin.sock";
		ok(strcmp(current.c_str(),expected)==0, "Line: %d , Current admin-mysql_ifaces = %s . Expected = %s", __LINE__, current.c_str(), expected);
		mysql_close(proxysql_admin2);
	}

	diag("Changing admin-mysql_ifaces to: 0.0.0.0:6032");
	MYSQL_QUERY(proxysql_admin,"SET admin-mysql_ifaces=\"0.0.0.0:6032\"");
	MYSQL_QUERY(proxysql_admin,"LOAD ADMIN VARIABLES TO RUNTIME");
	MYSQL_QUERY(proxysql_admin,"SAVE ADMIN VARIABLES FROM RUNTIME");

	sleep(1);
	{
		std::string current = get_admin_mysql_ifaces(proxysql_admin);
		char * expected = (char *)"0.0.0.0:6032";
		ok(strcmp(current.c_str(),expected)==0, "Line: %d , Current admin-mysql_ifaces = %s . Expected = %s", __LINE__, current.c_str(), expected);
	}

	{
		diag("Connecting on Unix Socket. It should fail");
		MYSQL* proxysql_admin2 = mysql_init(NULL);
		diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
		if (cl.use_ssl)
			mysql_ssl_set(proxysql_admin2, NULL, NULL, NULL, NULL, NULL);
		if (cl.compression)
			mysql_options(proxysql_admin2, MYSQL_OPT_COMPRESS, NULL);
		MYSQL * ret = mysql_real_connect(proxysql_admin2, NULL, cl.admin_username, cl.admin_password, NULL, 0, "/tmp/proxysql_admin.sock", 0);
		if (ret)
			mysql_close(proxysql_admin2);
		ok(ret == NULL, "Connection to Unix Socket should fail with error: %s", mysql_error(proxysql_admin2));
	}

	mysql_close(proxysql_admin);

	return exit_status();
}
