#include <algorithm>
#include <string>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <tuple>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

CommandLine cl;

/* this test:
	* enables mysql-have_ssl
	* execute various command
*/

std::vector<std::string> queries = {
	"DELETE FROM history_mysql_query_digest",
	"PROXYSQLTEST 1 100",
	"SELECT COUNT(*) FROM stats_mysql_query_digest",
	"PROXYSQLTEST 7",
	"PROXYSQLTEST 1 100",
	"SELECT COUNT(*) FROM stats_mysql_query_digest",
	"PROXYSQLTEST 8",
	"SELECT COUNT(*) FROM history_mysql_query_digest",
	"INSERT INTO mysql_firewall_whitelist_rules(active, username, client_address, schemaname, digest, comment) SELECT DISTINCT 1, username, '', schemaname, digest, digest_text FROM history_mysql_query_digest",
	"INSERT INTO mysql_firewall_whitelist_users (active, username, client_address, mode, comment) SELECT DISTINCT 1, username, '', 'DETECTING', '' FROM history_mysql_query_digest",
	"SAVE MYSQL FIREWALL TO DISK",
	"LOAD MYSQL FIREWALL TO RUNTIME",
	"LOAD MYSQL FIREWALL FROM DISK",
	"LOAD MYSQL FIREWALL TO RUNTIME",
	"SAVE MYSQL FIREWALL FROM RUNTIME",
	"PROXYSQLTEST 31 1",
	"PROXYSQLTEST 31 1 1",
	"PROXYSQLTEST 31 1 5",
//	"PROXYSQLTEST 31 2", //FIXME: investigate why it doesn't work
//	"PROXYSQLTEST 31 3", //FIXME: investigate why it doesn't work
	"PROXYSQLTEST 31 4",
	"PROXYSQLTEST 31 4 1",
	"PROXYSQLTEST 31 4 5",
	"DELETE FROM history_mysql_query_digest",
	"DELETE FROM mysql_firewall_whitelist_users",
	"DELETE FROM mysql_firewall_whitelist_rules",
	"SAVE MYSQL FIREWALL TO DISK",
	"LOAD MYSQL FIREWALL TO RUNTIME",
};

int run_q(MYSQL *mysql, const char *q) {
	MYSQL_QUERY(mysql,q);
	return 0;
}
int main() {

	MYSQL* proxysql_admin = mysql_init(NULL);
	diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
	if (cl.use_ssl)
		mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
	if (cl.compression)
		mysql_options(proxysql_admin, MYSQL_OPT_COMPRESS, NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	} else {
		const char * c = mysql_get_ssl_cipher(proxysql_admin);
		ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
		ok(cl.compression == proxysql_admin->net.compress, "Compression: (%d)", proxysql_admin->net.compress);
	}

	MYSQL_QUERY(proxysql_admin, "SET mysql-have_ssl='true'");
	MYSQL_QUERY(proxysql_admin, "SET mysql-have_compress='true'");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");



	plan(2 + 3 * queries.size());

	for (std::vector<std::string>::iterator it2 = queries.begin(); it2 != queries.end(); it2++) {

		MYSQL* proxysql_admin = mysql_init(NULL); // local scope . We intentionally create new connections
		diag("Connecting: cl.admin_username='%s' cl.use_ssl=%d cl.compression=%d", cl.admin_username, cl.use_ssl, cl.compression);
		if (cl.use_ssl)
			mysql_ssl_set(proxysql_admin, NULL, NULL, NULL, NULL, NULL);
		if (cl.compression)
			mysql_options(proxysql_admin, MYSQL_OPT_COMPRESS, NULL);
		if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, CLIENT_SSL|CLIENT_COMPRESS)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return -1;
		} else {
			const char * c = mysql_get_ssl_cipher(proxysql_admin);
			ok(cl.use_ssl == 0 ? c == NULL : c != NULL, "Cipher: %s", c == NULL ? "NULL" : c);
			ok(proxysql_admin->net.compress == 1, "Compression: (%d)", proxysql_admin->net.compress);
		}

		int rc = run_q(proxysql_admin, it2->c_str());
		ok(rc==0, "Query: %s" , it2->c_str());
		if (strncasecmp(it2->c_str(), "SELECT", 6)==0) {
			// we don't really need to clean as we are closing the connection
			// but we do it anyway
			MYSQL_RES* proxy_res = mysql_store_result(proxysql_admin);
			mysql_free_result(proxy_res);
		}
		mysql_close(proxysql_admin);
	}
	mysql_close(proxysql_admin);

	return exit_status();
}
