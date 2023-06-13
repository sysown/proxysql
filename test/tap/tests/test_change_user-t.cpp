/**
 * @file test_change_user-t.cpp
 * @brief Test various mysql_change_user()
 * @details Create connections with both mysql_native_password and caching_sha2_password
 *   and try to reset them
 */

#include <cstring>
#include <string>
#include <stdio.h>
#include <utility>
#include <vector>

#include "mysql.h"

// copied from ma_common.h , but only the beginning
struct st_mysql_options_extension {
	char *plugin_dir;
	char *default_auth;
	// README: the struct is more complex, but we only need default_auth
};

#include "tap.h"
#include "command_line.h"
#include "utils.h"

#include "json.hpp"

using std::pair;
using std::string;

using namespace std;

using nlohmann::json;

#define NCONNS 16

int run_queries_sets(std::vector<std::string>& queries, MYSQL *my, const std::string& message_prefix) {
	for (std::vector<std::string>::iterator it = queries.begin(); it != queries.end(); it++) {
		std::string q = *it;
		diag("%s: %s", message_prefix.c_str(), q.c_str());
		MYSQL_QUERY(my, q.c_str());
	}
	return 0;
}

void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}


int get_internal_session(MYSQL *my, json& j) {
	MYSQL_QUERY(my, "PROXYSQL INTERNAL SESSION");
	MYSQL_RES* tr_res = mysql_store_result(my);
	parse_result_json_column(tr_res, j);
	mysql_free_result(tr_res);
	return 0;
}

/*
int get_user_def_hg(MYSQL* admin, const string& user) {
	const string sel_q { "SELECT default_hostgroup FROM mysql_users WHERE username='" + user + "'" };
	if (mysql_query(admin, sel_q.c_str())) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin)); \
		return -1;
	}

	MYSQL_RES* myres = mysql_store_result(admin);
	MYSQL_ROW myrow = mysql_fetch_row(myres);

	if (myrow && myrow[0]) {
		int def_hg = std::atoi(myrow[0]);
		mysql_free_result(myres);

		return def_hg;
	} else {
		const string err_msg { "Unexpected empty result received for query: " + sel_q };
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, err_msg.c_str());
		return -1;
	}
}

pair<string,int> get_def_srv_host_port(MYSQL* admin, int hg) {
	const string sel_q { "SELECT hostname,port FROM mysql_servers WHERE hostgroup_id=" + std::to_string(hg) };
	int myrc = mysql_query(admin, sel_q.c_str());

	if (myrc) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return { "", -1 };
	} else {
		MYSQL_RES* myres = mysql_store_result(admin);
		MYSQL_ROW myrow = mysql_fetch_row(myres);

		if (myrow && myrow[0] && myrow[1]) {
			string host { myrow[0] };
			int port { std::atoi(myrow[1]) };
			mysql_free_result(myres);

			return { host, port };
		} else {
			const string err_msg { "Unexpected empty result received for query: '" + sel_q + "'"};
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, err_msg.c_str());
			return { "", -1 };
		}
	}
}

pair<string,int> get_def_srv_host(MYSQL* admin, const string user) {
	// Get the server from the default hostgroup
	int def_hg = get_user_def_hg(admin, user);
	if (def_hg == -1) {
		return { "", -1 };
	}

	return get_def_srv_host_port(admin, def_hg);
}
*/

MYSQL* proxy[NCONNS];
MYSQL* admin = NULL;

bool create_connections(const CommandLine& cl, const char *plugin, bool use_ssl, bool check_plugin, bool check_ssl, bool incorrect_connect_password) {
	diag("Calling create_connections with plugin: %s , use_ssl: %d , check_plugin: %d , check_ssl: %d , incorrect_connect_password: %d",
		plugin, use_ssl, check_plugin, check_ssl, incorrect_connect_password);
	MYSQL * my = NULL;
	int rc = 0;
	for (int i=0; i<NCONNS; i++) {
		proxy[i] = mysql_init(NULL);
		if (proxy[i] == NULL) {
			diag("Error on mysql_init()");
			return false;
		}
		int flags = 0;
		rc = mysql_options(proxy[i], MYSQL_DEFAULT_AUTH, plugin);
		my_bool enforce_tls=1;
		if (use_ssl) {
			mysql_ssl_set(proxy[i], NULL, NULL, NULL, NULL, NULL);
			flags = CLIENT_SSL;
			mysql_optionsv(proxy[i], MYSQL_OPT_SSL_ENFORCE, (void *)&enforce_tls);
		}
		my = mysql_real_connect(proxy[i], cl.host, cl.username, cl.password, NULL, cl.port, NULL, flags);
		if (incorrect_connect_password == false) {
			ok(my != NULL , "Connection created: %d", i);
			if (my == NULL) {
				diag("File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy[i]));
				return false;
			}
			if (use_ssl && check_ssl) {
				const char * c = mysql_get_ssl_cipher(proxy[i]);
				diag("Cipher in use for connection %d: %s", i, c == NULL ? "NULL" : c);
				if (c == NULL) {
					return false;
				}
			}
			if (check_plugin) {
				if (strcmp(plugin,proxy[i]->options.extension->default_auth) != 0) {
					ok(false, "Plugin wanted: %s , used: %s", plugin, proxy[i]->options.extension->default_auth);
					return false;
				}
			}
		} else {
			ok(my == NULL, "Connect should fail");
		}
	}
	return true;
}

void close_connections() {
	for (int i=0; i<NCONNS; i++) {
		mysql_close(proxy[i]);
		proxy[i] = NULL;
	}
}


int TestSet1(const CommandLine& cl, const char *plugin, bool test_ssl , bool test_plugin, bool change_user, bool incorrect_connect_password) {
	{
		diag("Setting mysql-default_authentication_plugin='%s'", plugin);
		vector<string> query_set = {"SET mysql-default_authentication_plugin='" + string(plugin) + "'", "LOAD MYSQL VARIABLES TO RUNTIME"};
		if (run_queries_sets( query_set , admin, "Running on Admin"))
			return exit_status();
	}
	{
		// ok() : NCONNS * 2
		diag("mysql_native_password and no SSL");
		const char *auth_plugin = (const char *)"mysql_native_password";
		vector<string> query_set = {"SET mysql-have_ssl='false'", "LOAD MYSQL VARIABLES TO RUNTIME"};
		if (run_queries_sets( query_set , admin, "Running on Admin"))
			return exit_status();
		if (create_connections(cl, auth_plugin, false, true, test_ssl, incorrect_connect_password) != true) {
			return exit_status();
		}
		if (test_plugin) {
			for (int i = 0; i<NCONNS; i++) {
				json j = {};
				get_internal_session(proxy[i], j);
				ok(j["client"]["prot"]["auth_plugin"] == string(auth_plugin) ,  "%s: %d: Plugin wanted: %s , used: %s", plugin, __LINE__, auth_plugin, string(j["client"]["prot"]["auth_plugin"]).c_str());
			}
		}
		if (change_user) {
			for (int i = 0; i<NCONNS; i++) {
				MYSQL *my = proxy[i];
				int rc = mysql_change_user(my, cl.username, cl.password, NULL);
				ok(rc == 0, "mysql_change_user():%d : Plugin(default,current): (%s,%s)" , __LINE__, plugin, auth_plugin);
			}
		}
		close_connections;
	}
	{
		// ok() : NCONNS * 2
		diag("mysql_native_password and SSL");
		const char *auth_plugin = (const char *)"mysql_native_password";
		vector<string> query_set = {"SET mysql-have_ssl='true'", "LOAD MYSQL VARIABLES TO RUNTIME"};
		if (run_queries_sets( query_set , admin, "Running on Admin"))
			return exit_status();
		if (create_connections(cl, auth_plugin, true, true, test_ssl, incorrect_connect_password) != true) {
			return exit_status();
		}
		if (test_plugin) {
			for (int i = 0; i<NCONNS; i++) {
				json j = {};
				get_internal_session(proxy[i], j);
				ok(j["client"]["prot"]["auth_plugin"] == string(auth_plugin) ,  "%s: %d: Plugin wanted: %s , used: %s", plugin, __LINE__, auth_plugin, string(j["client"]["prot"]["auth_plugin"]).c_str());
			}
		}
		if (change_user) {
			for (int i = 0; i<NCONNS; i++) {
				MYSQL *my = proxy[i];
				int rc = mysql_change_user(my, cl.username, cl.password, NULL);
				ok(rc == 0, "mysql_change_user():%d : Plugin(default,current): (%s,%s)" , __LINE__, plugin, auth_plugin);
			}
		}
		close_connections;
	}
	{
		// ok(): NCONNS * 2
		diag("caching_sha2_password and SSL");
		const char *auth_plugin = (const char *)"caching_sha2_password";
		vector<string> query_set = {"SET mysql-have_ssl='true'", "LOAD MYSQL VARIABLES TO RUNTIME"};
		if (run_queries_sets( query_set , admin, "Running on Admin"))
			return exit_status();
		if (create_connections(cl, auth_plugin, true, true, test_ssl, incorrect_connect_password) != true) {
			return exit_status();
		}
		if (test_plugin) {
			for (int i = 0; i<NCONNS; i++) {
				json j = {};
				get_internal_session(proxy[i], j);
				// when mysql-default_authentication_plugin='mysql_native_password'
				// mysql_native_password is used even if client tries caching_sha2_password
				ok(j["client"]["prot"]["auth_plugin"] == string(plugin),
					"%s: %d: Plugin wanted: %s , used: %s", plugin, __LINE__, auth_plugin, string(j["client"]["prot"]["auth_plugin"]).c_str());
			}
		}
		if (change_user) {
			for (int i = 0; i<NCONNS; i++) {
				MYSQL *my = proxy[i];
				int rc = mysql_change_user(my, cl.username, cl.password, NULL);
				ok(rc == 0, "mysql_change_user():%d : Plugin(default,current): (%s,%s)" , __LINE__, plugin, auth_plugin);
			}
		}
		close_connections;
	}
	return 0;
}

int main(int argc, char** argv) {
	CommandLine cl;

	int p = 1; // admin connection
	// with mysql-default_authentication_plugin = mysql_native_password
	p += NCONNS*2*2; // mysql_native_password with and without SSL
	p += NCONNS*2*1; // caching_sha2_password with SSL
	// with mysql-default_authentication_plugin = caching_sha2_password
	p += NCONNS*2*2; // mysql_native_password with and without SSL
	p += NCONNS*2*1; // caching_sha2_password with SSL

	// with further checks disabled, but change_user() enabled
	// with mysql-default_authentication_plugin = mysql_native_password
	p += NCONNS*2*2; // mysql_native_password with and without SSL
	p += NCONNS*2*1; // caching_sha2_password with SSL
	// with mysql-default_authentication_plugin = caching_sha2_password
	p += NCONNS*2*2; // mysql_native_password with and without SSL
	p += NCONNS*2*1; // caching_sha2_password with SSL

	plan(p);

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	int rc = 0;
	admin = mysql_init(NULL);
	{
		MYSQL * my = mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0);
		ok(my != NULL , "Connected to admin");
		if (my == NULL) {
			diag("File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
			return exit_status();
		}
	}

	// ok() NCONNS*2*2 + NCONNS*2*1
	if (TestSet1(cl,"mysql_native_password", true, true, false, false)) {
		return exit_status();
	}
	// ok() NCONNS*2*2 + NCONNS*2*1
	if (TestSet1(cl,"caching_sha2_password", true, true, false, false)) {
		return exit_status();
	}
	// ok() NCONNS*2*2 + NCONNS*2*1
	if (TestSet1(cl,"mysql_native_password", false, false, true, false)) {
		return exit_status();
	}
	// ok() NCONNS*2*2 + NCONNS*2*1
	if (TestSet1(cl,"caching_sha2_password", false, false, true, false)) {
		return exit_status();
	}

	return exit_status();

cleanup:

	close_connections();
	return exit_status();
}
