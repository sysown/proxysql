#include <algorithm>
#include <chrono>
#include <string>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <numeric>
#include <memory>
#include <string>
#include <unistd.h>
#include <sys/wait.h>

#include <mysql.h>

#include "tap.h"
#include "utils.h"

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <iostream>

#include "proxysql_utils.h"

using std::string;

int show_variable(MYSQL *mysql, const std::string& var_name, std::string& var_value) {
	char query[128];

	snprintf(query, sizeof(query),"show variables like '%s'", var_name.c_str());
	if (mysql_query(mysql, query)) {
		fprintf(stderr, "Failed to execute query [%s] : no %d, %s\n",
				query, mysql_errno(mysql), mysql_error(mysql));
		return exit_status();
	}

	MYSQL_RES *result;
	MYSQL_ROW row;
	result = mysql_store_result(mysql);

	int num_fields = mysql_num_fields(result);

	row = mysql_fetch_row(result);
	var_value = row[1];
	mysql_free_result(result);
	return 0;
}

int select_config_file(MYSQL* mysql, std::string& resultset) {
	if (mysql_query(mysql, "select config file")) {
	    fprintf(stderr, "File %s, line %d, Error: %s\n",
	              __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	MYSQL_RES *result;
	MYSQL_ROW row;
	result = mysql_store_result(mysql);
	if (result) {
		row = mysql_fetch_row(result);
		resultset = row[0];
		mysql_free_result(result);
	} else {
		fprintf(stderr, "error\n");
	}

	return 0;
}

int show_admin_global_variable(MYSQL *mysql, const std::string& var_name, std::string& var_value) {
	char query[128];

	snprintf(query, sizeof(query),"select variable_value from global_variables where variable_name='%s'", var_name.c_str());
	if (mysql_query(mysql, query)) {
		fprintf(stderr, "Failed to execute SHOW VARIABLES LIKE : no %d, %s\n",
				mysql_errno(mysql), mysql_error(mysql));
		return exit_status();
	}

	MYSQL_RES *result;
	MYSQL_ROW row;
	result = mysql_store_result(mysql);

	int num_fields = mysql_num_fields(result);

	row = mysql_fetch_row(result);
	var_value = row[0];
	mysql_free_result(result);
	return 0;
}

int set_admin_global_variable(MYSQL *mysql, const std::string& var_name, const std::string& var_value) {
	char query[128];

	snprintf(query, sizeof(query),"update global_variables set variable_value = '%s' where variable_name='%s'", var_value.c_str(), var_name.c_str());
	if (mysql_query(mysql, query)) {
		fprintf(stderr, "Failed to execute SHOW VARIABLES LIKE : no %d, %s\n",
				mysql_errno(mysql), mysql_error(mysql));
		return exit_status();
	}
	return 0;
}


int get_server_version(MYSQL *mysql, std::string& version) {
	char query[128];

	if (mysql_query(mysql, "select @@version")) {
		fprintf(stderr, "Error %d, %s\n",
				mysql_errno(mysql), mysql_error(mysql));
		return exit_status();
	}

	MYSQL_RES *result;
	MYSQL_ROW row;
	result = mysql_store_result(mysql);

	int num_fields = mysql_num_fields(result);

	row = mysql_fetch_row(result);
	version = row[0];
	mysql_free_result(result);

	return 0;
}

int add_more_rows_test_sbtest1(int num_rows, MYSQL *mysql, bool sqlite) {
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<int> dist(0.0, 9.0);

	diag("Creating %d rows in sbtest1", num_rows);
	while (num_rows) {
		std::stringstream q;

		if (sqlite==false) {
		q << "INSERT INTO test.sbtest1 (k, c, pad) values ";
		} else {
			q << "INSERT INTO sbtest1 (k, c, pad) values ";
		}
		bool put_comma = false;
		int i=0;
		unsigned int cnt=5+rand()%50;
		if (cnt > num_rows) cnt = num_rows;
		for (i=0; i<cnt ; ++i) {
			num_rows--;
			int k = dist(mt);
			std::stringstream c;
			for (int j=0; j<10; j++) {
				for (int k=0; k<11; k++) {
					c << dist(mt);
				}
				if (j<9)
					c << "-";
			}
			std::stringstream pad;
			for (int j=0; j<5; j++) {
				for (int k=0; k<11; k++) {
					pad << dist(mt);
				}
				if (j<4)
					pad << "-";
			}
			if (put_comma) q << ",";
			if (!put_comma) put_comma=true;
			q << "(" << k << ",'" << c.str() << "','" << pad.str() << "')";
		}
		MYSQL_QUERY(mysql, q.str().c_str());
		diag("Inserted %d rows ...", i);
	}
	diag("Done!");
	return 0;
}
int create_table_test_sbtest1(int num_rows, MYSQL *mysql) {
	MYSQL_QUERY(mysql, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY(mysql, "DROP TABLE IF EXISTS test.sbtest1");
	MYSQL_QUERY(mysql, "CREATE TABLE if not exists test.sbtest1 (`id` int(10) unsigned NOT NULL AUTO_INCREMENT, `k` int(10) unsigned NOT NULL DEFAULT '0', `c` char(120) NOT NULL DEFAULT '', `pad` char(60) NOT NULL DEFAULT '',  PRIMARY KEY (`id`), KEY `k_1` (`k`))");

	return add_more_rows_test_sbtest1(num_rows, mysql);
}

int create_table_test_sqlite_sbtest1(int num_rows, MYSQL *mysql) {
	MYSQL_QUERY(mysql, "DROP TABLE IF EXISTS sbtest1");
	MYSQL_QUERY(mysql, "CREATE TABLE if not exists sbtest1 (id INTEGER PRIMARY KEY AUTOINCREMENT, `k` int(10) NOT NULL DEFAULT '0', `c` char(120) NOT NULL DEFAULT '', `pad` char(60) NOT NULL DEFAULT '')");
	MYSQL_QUERY(mysql, "CREATE INDEX IF NOT EXISTS idx_sbtest1_k1 ON sbtest1 (k)");

	return add_more_rows_test_sbtest1(num_rows, mysql, true);
}

int execvp(const std::string& cmd, const std::vector<const char*>& argv, std::string& result) {
	// Pipes definition
	constexpr uint8_t NUM_PIPES = 3;
	constexpr uint8_t PARENT_WRITE_PIPE = 0;
	constexpr uint8_t PARENT_READ_PIPE  = 1;
	constexpr uint8_t PARENT_ERR_PIPE   = 2;
	int pipes[NUM_PIPES][2];
	// Pipe selection
	constexpr uint8_t READ_FD  = 0;
	constexpr uint8_t WRITE_FD = 1;
	// Parent pipes
	const auto& PARENT_READ_FD  = pipes[PARENT_READ_PIPE][READ_FD];
	const auto& PARENT_READ_ERR = pipes[PARENT_ERR_PIPE][READ_FD];
	const auto& PARENT_WRITE_FD = pipes[PARENT_WRITE_PIPE][WRITE_FD];
	// Child pipes
	const auto& CHILD_READ_FD   = pipes[PARENT_WRITE_PIPE][READ_FD];
	const auto& CHILD_WRITE_FD  = pipes[PARENT_READ_PIPE][WRITE_FD];
	const auto& CHILD_WRITE_ERR = pipes[PARENT_ERR_PIPE][WRITE_FD];

	int err = 0;
	std::string result_ = "";
	std::vector<const char*> _argv = argv;

	// Append null to end of _argv for extra safety
	_argv.push_back(nullptr);

	// Pipes for parent to write and read
	pipe(pipes[PARENT_READ_PIPE]);
	pipe(pipes[PARENT_WRITE_PIPE]);
	pipe(pipes[PARENT_ERR_PIPE]);

	pid_t child_pid = fork();
	if(child_pid == 0) {
		// Copy the pipe descriptors
		dup2(CHILD_READ_FD, STDIN_FILENO);
		dup2(CHILD_WRITE_FD, STDOUT_FILENO);
		dup2(CHILD_WRITE_ERR, STDERR_FILENO);

		// Close no longer needed pipes
		close(CHILD_READ_FD);
		close(CHILD_WRITE_FD);
		close(CHILD_WRITE_ERR);

		close(PARENT_READ_FD);
		close(PARENT_READ_ERR);
		close(PARENT_WRITE_FD);

		char** args = const_cast<char**>(_argv.data());
		err = execvp(cmd.c_str(), args);

		if (err) {
			exit(errno);
		} else {
			exit(0);
		}
	} else {
		char buffer[128];
		int count;

		// Close no longer needed pipes
		close(CHILD_READ_FD);
		close(CHILD_WRITE_FD);
		close(CHILD_WRITE_ERR);

		if (err == 0) {
			// Read from child’s stdout
			count = read(PARENT_READ_FD, buffer, sizeof(buffer));
			while (count > 0) {
				buffer[count] = 0;
				result_ += buffer;
				count = read(PARENT_READ_FD, buffer, sizeof(buffer));
			}
		} else {
			// Read from child’s stderr
			count = read(PARENT_READ_ERR, buffer, sizeof(buffer));
			while (count > 0) {
				buffer[count] = 0;
				result_ += buffer;
				count = read(PARENT_READ_ERR, buffer, sizeof(buffer));
			}
		}

		waitpid(child_pid, &err, 0);
	}

	result = result_;

	return err;
}

int exec(const std::string& cmd, std::string& result) {
	char buffer[128];
	std::string result_ = "";
	int err = 0;

	// Try to invoke the shell
	FILE* pipe = popen(cmd.c_str(), "r");
	if (!pipe) {
		return errno;
	}

	try {
		while (fgets(buffer, sizeof buffer, pipe) != NULL) {
			result_ += buffer;
		}
	} catch (...) {
		err = -1;
	}

	pclose(pipe);

	if (err == 0) {
		// Return the result
		result = result_;
	}
	return err;
}

std::vector<mysql_res_row> extract_mysql_rows(MYSQL_RES* my_res) {
	if (my_res == nullptr) { return {}; }

	std::vector<mysql_res_row> result {};
	MYSQL_ROW row = nullptr;
	uint32_t num_fields = mysql_num_fields(my_res);

	while ((row = mysql_fetch_row(my_res))) {
		mysql_res_row row_values {};
		uint64_t *lengths = mysql_fetch_lengths(my_res);

		for (uint32_t i = 0; i < num_fields; i++) {
			std::string field_val(row[i], lengths[i]);
			row_values.push_back(field_val);
		}

		result.push_back(row_values);
	}

	return result;
};

struct memory {
	char* data;
	size_t size;
};

static size_t write_callback(void *data, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	struct memory *mem = (struct memory *)userp;

	char* ptr = static_cast<char*>(realloc(mem->data, mem->size + realsize + 1));
	if(ptr == NULL) {
		return 0;
	}

	mem->data = ptr;
	memcpy(&(mem->data[mem->size]), data, realsize);
	mem->size += realsize;
	mem->data[mem->size] = 0;

	return realsize;
}

CURLcode perform_simple_post(
	const std::string& endpoint, const std::string& post_params,
	uint64_t& curl_res_code, std::string& curl_out_err
) {
	CURL *curl;
	CURLcode res;

	curl_global_init(CURL_GLOBAL_ALL);

	curl = curl_easy_init();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_params.c_str());
		struct memory response = { 0 };
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

		res = curl_easy_perform(curl);

		if(res != CURLE_OK) {
			curl_out_err = std::string { curl_easy_strerror(res) };
		} else {
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &curl_res_code);

			if (curl_res_code != 200) {
				curl_out_err = string(response.data, response.size);
			}
		}

		curl_easy_cleanup(curl);
	}

	return res;
}

int wait_until_enpoint_ready(
	std::string endpoint, std::string post_params, uint32_t timeout, uint32_t delay
) {
	double waited = 0;
	int res = -1;

	while (waited < timeout) {
		std::string curl_str_err {};
		uint64_t curl_res_code = 0;
		int curl_err = perform_simple_post(endpoint, post_params, curl_res_code, curl_str_err);

		if (curl_err != CURLE_OK) {
			diag(
				"'curl_err_code': %d, 'curl_err': '%s', waiting for '%d'ms...",
				curl_err, curl_str_err.c_str(), delay
			);
			waited += static_cast<double>(delay) / 1000;
			usleep(delay * 1000);
		} else {
			res = 0;
			break;
		}
	}

	return res;
}

std::string random_string(std::size_t strSize) {
	std::string dic { "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" };

	std::random_device rd {};
	std::mt19937 generator { rd() };

	std::shuffle(dic.begin(), dic.end(), generator);

	if (strSize < dic.size()) {
		return dic.substr(0, strSize);
	} else {
		std::size_t req_modulus = static_cast<std::size_t>(strSize / dic.size());
		std::size_t req_reminder = strSize % dic.size();
		std::string random_str {};

		for (std::size_t i = 0; i < req_modulus; i++) {
			random_str.append(dic);
		}

		random_str.append(dic.substr(0, req_reminder));

		return random_str;
	}
}

const double COLISSION_PROB = 1e-8;

int wait_for_replication(
	MYSQL* proxy, MYSQL* proxy_admin, const std::string& check, uint32_t timeout, uint32_t read_hg
) {
	if (proxy == NULL) { return EXIT_FAILURE; }

	const std::string t_count_reader_hg_servers {
		"SELECT COUNT(*) FROM mysql_servers WHERE hostgroup_id=%d"
	};
	std::string count_reader_hg_servers {};
	size_t size =
		snprintf( nullptr, 0, t_count_reader_hg_servers.c_str(), read_hg) + 1;
	{
		std::unique_ptr<char[]> buf(new char[size]);
		snprintf(buf.get(), size, t_count_reader_hg_servers.c_str(), read_hg);
		count_reader_hg_servers = std::string(buf.get(), buf.get() + size - 1);
	}

	MYSQL_QUERY(proxy_admin, count_reader_hg_servers.c_str());
	MYSQL_RES* hg_count_res = mysql_store_result(proxy_admin);
	MYSQL_ROW row = mysql_fetch_row(hg_count_res);
	uint32_t srv_count = strtoul(row[0], NULL, 10);
	mysql_free_result(hg_count_res);

	if (srv_count > UINT_MAX) {
		return EXIT_FAILURE;
	}

	int waited = 0;
	int queries = 0;
	int result = EXIT_FAILURE;

	if (srv_count != 0) {
		int retries = ceil(log10(COLISSION_PROB) / log10(static_cast<long double>(1)/srv_count));
		auto start = std::chrono::system_clock::now();
		std::chrono::duration<double> elapsed {};

		while (elapsed.count() < timeout && queries < retries) {
			int rc = mysql_query(proxy, check.c_str());
			bool correct_result = false;

			if (rc == EXIT_SUCCESS) {
				MYSQL_RES* st_res = mysql_store_result(proxy);
				if (st_res) {
					uint32_t field_num = mysql_num_fields(st_res);
					uint32_t row_num = mysql_num_rows(st_res);

					if (field_num == 1 && row_num == 1) {
						MYSQL_ROW row = mysql_fetch_row(st_res);

						std::string exp_res { "TRUE" };
						if (strcasecmp(exp_res.c_str(), row[0]) == 0) {
							correct_result = true;
							queries += 1;
						}
					}

					mysql_free_result(st_res);
				}
			} else {
				diag(
					"Replication check failed due to query error: ('%d','%s')",
					mysql_errno(proxy), mysql_error(proxy)
				);
			}

			if (correct_result == false) {
				queries = 0;
				waited += 1;
				sleep(1);
			} else {
				continue;
			}

			auto it_end = std::chrono::system_clock::now();
			elapsed = it_end - start;
		}

		if (queries == retries) {
			result = EXIT_SUCCESS;
		}
	} else {
		result = EXIT_SUCCESS;
	}

	return result;
}

MARIADB_CHARSET_INFO * proxysql_find_charset_collate(const char *collatename) {
	MARIADB_CHARSET_INFO *c = (MARIADB_CHARSET_INFO *)mariadb_compiled_charsets;
	do {
		if (!strcasecmp(c->name, collatename)) {
			return c;
		}
		++c;
	} while (c[0].nr != 0);
	return NULL;
}

int create_proxysql_user(
	MYSQL* proxysql_admin,
	const std::string& user,
	const std::string& pass,
	const std::string& attributes
) {
	std::string t_del_user_query { "DELETE FROM mysql_users WHERE username='%s'" };
	std::string del_user_query {};
	string_format(t_del_user_query, del_user_query, user.c_str());

	std::string t_insert_user {
		"INSERT INTO mysql_users (username,password,active,attributes)"
		" VALUES ('%s','%s',1,'%s')"
	};
	std::string insert_user {};
	string_format(t_insert_user, insert_user, user.c_str(), pass.c_str(), attributes.c_str());

	MYSQL_QUERY(proxysql_admin, del_user_query.c_str());
	MYSQL_QUERY(proxysql_admin, insert_user.c_str());

	return EXIT_SUCCESS;
}

int create_mysql_user(
	MYSQL* mysql_server,
	const std::string& user,
	const std::string& pass
) {
	const std::string t_drop_user_query { "DROP USER IF EXISTS %s@'%%'" };
	std::string drop_user_query {};
	string_format(t_drop_user_query, drop_user_query, user.c_str());

	const std::string t_create_user_query {
		"CREATE USER IF NOT EXISTS %s@'%%' IDENTIFIED WITH 'mysql_native_password' BY \"%s\""
	};
	std::string create_user_query {};
	string_format(t_create_user_query, create_user_query, user.c_str(), pass.c_str());

	const std::string t_grant_all_query { "GRANT ALL ON *.* TO %s@'%%'" };
	std::string grant_all_query { };
	string_format(t_grant_all_query, grant_all_query, user.c_str());

	MYSQL_QUERY(mysql_server, drop_user_query.c_str());
	MYSQL_QUERY(mysql_server, create_user_query.c_str());
	MYSQL_QUERY(mysql_server, grant_all_query.c_str());

	return EXIT_SUCCESS;
}

int create_extra_users(
	MYSQL* proxysql_admin,
	MYSQL* mysql_server,
	const std::vector<user_config>& users_config
) {
	std::vector<std::pair<std::string, std::string>> v_user_pass {};
	std::transform(
		std::begin(users_config),
		std::end(users_config),
		std::back_inserter(v_user_pass),
		[](const user_config& u_config) {
			return std::pair<std::string, std::string> {
				std::get<0>(u_config),
				std::get<1>(u_config)
			};
		}
	);

	// create the MySQL users
	for (const auto& user_pass : v_user_pass) {
		int c_user_res =
			create_mysql_user(mysql_server, user_pass.first, user_pass.second);
		if (c_user_res) {
			return c_user_res;
		}
	}

	// create the ProxySQL users
	for (const auto& user_config : users_config) {
		int c_p_user_res =
			create_proxysql_user(
				proxysql_admin,
				std::get<0>(user_config),
				std::get<1>(user_config),
				std::get<2>(user_config)
			);
		if (c_p_user_res) {
			return c_p_user_res;
		}
	}

	return EXIT_SUCCESS;
}

std::string tap_curtime() {
	time_t __timer;
	char lut[30];
	struct tm __tm_info;
	time(&__timer);
	localtime_r(&__timer, &__tm_info);
	strftime(lut, 25, "%Y-%m-%d %H:%M:%S", &__tm_info);
	std::string s = std::string(lut);
	return s;
}

int get_proxysql_cpu_usage(const CommandLine& cl, uint32_t intv, uint32_t& cpu_usage) {
	// check if proxysql process is consuming higher cpu than it should
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// recover admin variables
	std::string set_stats_query { "SET admin-stats_system_cpu=" + std::to_string(intv) };
	MYSQL_QUERY(proxysql_admin, set_stats_query.c_str());
	MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	// sleep during the required interval + safe threshold
	sleep(intv + 2);

	MYSQL_QUERY(proxysql_admin, "SELECT * FROM system_cpu ORDER BY timestamp DESC LIMIT 1");
	MYSQL_RES* admin_res = mysql_store_result(proxysql_admin);
	MYSQL_ROW row = mysql_fetch_row(admin_res);

	double s_clk = (1.0 / sysconf(_SC_CLK_TCK)) * 1000;
	int utime_ms = atoi(row[1]) * s_clk;
	int stime_ms = atoi(row[2]) * s_clk;
	int t_ms = utime_ms + stime_ms;

	// return the cpu usage
	cpu_usage = t_ms;

	// free the result
	mysql_free_result(admin_res);

	// recover admin variables
	MYSQL_QUERY(proxysql_admin, "SET admin-stats_system_cpu=60");
	MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	mysql_close(proxysql_admin);

	return 0;
}

MYSQL* wait_for_proxysql(const conn_opts_t& opts, int timeout) {
	uint con_waited = 0;
	MYSQL* admin = mysql_init(NULL);

	const char* user = opts.user.c_str();
	const char* pass = opts.pass.c_str();
	const char* host = opts.host.c_str();
	const int port = opts.port;

	while (!mysql_real_connect(admin, host, user, pass, NULL, port, NULL, 0) && con_waited < timeout) {
		mysql_close(admin);
		admin = mysql_init(NULL);

		con_waited += 1;
		sleep(1);
	}

	if (con_waited >= timeout) {
		mysql_close(admin);
		return nullptr;
	} else {
		return admin;
	}
}

int get_variable_value(
	MYSQL* proxysql_admin, const std::string& variable_name, std::string& variable_value, bool runtime
) {
	if (proxysql_admin == NULL) {
		return EINVAL;
	}

	int res = EXIT_FAILURE;

	const std::string t_select_var_query {
		"SELECT * FROM %sglobal_variables WHERE Variable_name='%s'"
	};
	std::string select_var_query {};

	if (runtime) {
		string_format(t_select_var_query, select_var_query, "runtime_", variable_name.c_str());
	} else {
		string_format(t_select_var_query, select_var_query, "", variable_name.c_str());
	}

	MYSQL_QUERY(proxysql_admin, select_var_query.c_str());

	MYSQL_RES* admin_res = mysql_store_result(proxysql_admin);
	if (!admin_res) {
		diag("'mysql_store_result' at line %d failed: %s", __LINE__, mysql_error(proxysql_admin));
		goto cleanup;
	}

	{
		MYSQL_ROW row = mysql_fetch_row(admin_res);
		if (!row || row[0] == nullptr || row[1] == nullptr) {
			diag("'mysql_fetch_row' at line %d returned 'NULL'", __LINE__);
			res = -1;
			goto cleanup;
		}

		// Extract the result
		std::string _variable_value { row[1] };
		variable_value = _variable_value;

		res = EXIT_SUCCESS;
	}

cleanup:

	return res;
}
