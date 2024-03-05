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
		string pass = string(cl.password); // default
		if (incorrect_connect_password == true) {
			if (i%2 == 0) {
				pass = "a" + pass;
			} else {
				pass = pass + "a";
			}
		}
		my = mysql_real_connect(proxy[i], cl.host, cl.username, pass.c_str(), NULL, cl.port, NULL, flags);
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


int TestSet1(const CommandLine& cl, const char *plugin, bool test_ssl , bool test_plugin, bool change_user,
		bool incorrect_connect_password, bool incorrect_change_user_password) {
	diag("%d: Starting tests with plugin: %s , test_ssl: %d , check_plugin: %d , change_user: %d , incorrect_connect_password: %d , incorrect_change_user_password: %d",
		__LINE__, plugin, test_ssl, test_plugin, change_user, incorrect_connect_password, incorrect_change_user_password);
	vector <pair<string,bool>> vec = {
		{"mysql_native_password", false},
		{"mysql_native_password", true},
		{"caching_sha2_password", true}
	};
	for (auto it = vec.begin(); it != vec.end() ; it++) {
		diag("%d: Starting testing plugin %s and ssl %d" , __LINE__, it->first.c_str(), it->second);

		diag("Setting mysql-default_authentication_plugin='%s'", plugin);
		vector<string> query_set1 = {"SET mysql-default_authentication_plugin='" + string(plugin) + "'", "LOAD MYSQL VARIABLES TO RUNTIME"};
		if (run_queries_sets( query_set1 , admin, "Running on Admin"))
			return exit_status();

		const char *auth_plugin = it->first.c_str();
		vector<string> query_set2 = {string(string("SET mysql-have_ssl='") + (it->second ? "true" : "false") + "'"), "LOAD MYSQL VARIABLES TO RUNTIME"};
		if (run_queries_sets( query_set2 , admin, "Running on Admin"))
			return exit_status();
		if (create_connections(cl, auth_plugin, false, true, test_ssl, incorrect_connect_password) != true) {
			return exit_status();
		}
		if (incorrect_connect_password == false) {
			if (test_plugin) {
				for (int i = 0; i<NCONNS; i++) {
					json j = {};
					get_internal_session(proxy[i], j);
					// when mysql-default_authentication_plugin='mysql_native_password'
					// mysql_native_password is used even if client tries caching_sha2_password
					string s = string(auth_plugin);
					if (it->first == "caching_sha2_password") {
						s = string(plugin);
					}
					ok(j["client"]["prot"]["auth_plugin"] == s,
						"%s: %d: Plugin wanted: %s , used: %s", plugin, __LINE__, auth_plugin, string(j["client"]["prot"]["auth_plugin"]).c_str());
				}
			}
			if (change_user) {
				for (int i = 0; i<NCONNS; i++) {
					MYSQL *my = proxy[i];
					string pass = string(cl.password); // default
					if (incorrect_change_user_password == true) {
						if (i%2 == 0) {
							pass = "a" + pass;
						} else {
							pass = pass + "a";
						}
					}
					int rc = mysql_change_user(my, cl.username, pass.c_str(), NULL);
					if (incorrect_change_user_password == false) {
						ok(rc == 0, "mysql_change_user():%d : Should succeed. Plugin(default,current): (%s,%s)" , __LINE__, plugin, auth_plugin);
					} else {
						ok(rc != 0, "mysql_change_user():%d : Should fail . Plugin(default,current): (%s,%s)" , __LINE__, plugin, auth_plugin);
					}
				}
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

	// with incorrect connect password
	// with mysql-default_authentication_plugin = mysql_native_password
	p += NCONNS*1*2; // mysql_native_password with and without SSL
	p += NCONNS*1*1; // caching_sha2_password with SSL
	// with mysql-default_authentication_plugin = caching_sha2_password
	p += NCONNS*1*2; // mysql_native_password with and without SSL
	p += NCONNS*1*1; // caching_sha2_password with SSL

	// with incorrect change user password
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


	char *plugin = NULL;
	bool test_ssl;
	bool test_plugin;
	bool change_user;
	bool incorrect_connect_password;
	bool incorrect_change_user_password;


	test_ssl=true; test_plugin=true; change_user=false; incorrect_connect_password=false; incorrect_change_user_password=false;

	// ok() NCONNS*2*2 + NCONNS*2*1
	plugin = (char *)"mysql_native_password";
	diag("%d: Starting batch tests", __LINE__);
	if (TestSet1(cl, plugin, test_ssl, test_plugin, change_user, incorrect_connect_password, incorrect_change_user_password)) {
		return exit_status();
	}
	// ok() NCONNS*2*2 + NCONNS*2*1
	plugin = (char *)"caching_sha2_password";
	diag("%d: Starting batch tests", __LINE__);
	if (TestSet1(cl, plugin, test_ssl, test_plugin, change_user, incorrect_connect_password, incorrect_change_user_password)) {
		return exit_status();
	}

	test_ssl=false; test_plugin=false; change_user=true; incorrect_connect_password=false; incorrect_change_user_password=false;

	// ok() NCONNS*2*2 + NCONNS*2*1
	plugin = (char *)"mysql_native_password";
	diag("%d: Starting batch tests", __LINE__);
	if (TestSet1(cl, plugin, test_ssl, test_plugin, change_user, incorrect_connect_password, incorrect_change_user_password)) {
		return exit_status();
	}
	// ok() NCONNS*2*2 + NCONNS*2*1
	plugin = (char *)"caching_sha2_password";
	diag("%d: Starting batch tests", __LINE__);
	if (TestSet1(cl, plugin, test_ssl, test_plugin, change_user, incorrect_connect_password, incorrect_change_user_password)) {
		return exit_status();
	}

	test_ssl=false; test_plugin=false; change_user=true; incorrect_connect_password=true;  incorrect_change_user_password=false;

	// ok() NCONNS*1*2 + NCONNS*1*1
	plugin = (char *)"mysql_native_password";
	diag("%d: Starting batch tests", __LINE__);
	if (TestSet1(cl, plugin, test_ssl, test_plugin, change_user, incorrect_connect_password, incorrect_change_user_password)) {
		return exit_status();
	}
	// ok() NCONNS*1*2 + NCONNS*1*1
	diag("%d: Starting batch tests", __LINE__);
	plugin = (char *)"caching_sha2_password";
	if (TestSet1(cl, plugin, test_ssl, test_plugin, change_user, incorrect_connect_password, incorrect_change_user_password)) {
		return exit_status();
	}

	test_ssl=false; test_plugin=false; change_user=true; incorrect_connect_password=false; incorrect_change_user_password=true;

	// ok() NCONNS*2*2 + NCONNS*2*1
	plugin = (char *)"mysql_native_password";
	diag("%d: Starting batch tests", __LINE__);
	if (TestSet1(cl, plugin, test_ssl, test_plugin, change_user, incorrect_connect_password, incorrect_change_user_password)) {
		return exit_status();
	}
	// ok() NCONNS*2*2 + NCONNS*2*1
	plugin = (char *)"caching_sha2_password";
	diag("%d: Starting batch tests", __LINE__);
	if (TestSet1(cl, plugin, test_ssl, test_plugin, change_user, incorrect_connect_password, incorrect_change_user_password)) {
		return exit_status();
	}

	return exit_status();

cleanup:

	close_connections();
	return exit_status();
}
