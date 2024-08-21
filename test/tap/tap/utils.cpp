#include <algorithm>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <numeric>
#include <string>
#include <sstream>
#include <random>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

#include "json.hpp"
#include "re2/re2.h"

#include "proxysql_utils.h"

#include "mysql.h"
#include "utils.h"
#include "tap.h"

using std::pair;
using std::map;
using std::fstream;
using std::string;
using std::vector;

using std::to_string;
using nlohmann::json;

#define LAST_QUERY_EXECUTED_STR(mysql)	(*static_cast<std::string*>(mysql->unused_0)) 
#define STMT_VECTOR(stmt)				(*static_cast<std::vector<MYSQL_STMT*>*>(stmt->mysql->unused_3))
#define STMT_EXECUTED_VECTOR(stmt)		(*static_cast<std::vector<std::unique_ptr<char,decltype(&free)>>*>(stmt->mysql->unused_4))
#define LAST_QUERY_EXECUTED_PTR(mysql)	(static_cast<std::string*>(mysql->unused_0))
#define STMT_VECTOR_PTR(mysql)			(static_cast<std::vector<MYSQL_STMT*>*>(mysql->unused_3))
#define STMT_EXECUTED_VECTOR_PTR(mysql)	(static_cast<std::vector<std::unique_ptr<char,decltype(&free)>>*>(mysql->unused_4))

#define STMT_FIND_INDEX(stmt,idx)		const std::vector<MYSQL_STMT*>* vec_stmt = STMT_VECTOR_PTR(stmt->mysql);\
										size_t vec_size = vec_stmt ? vec_stmt->size() : 0;\
										for (size_t i = 0; i < vec_size; i++) {\
											if ((*vec_stmt)[i] == stmt) {\
												idx = i; \
												break; \
											}\
										}	

#define STMT_PUSH_QUERY(stmt,query)		size_t idx = -1; \
										STMT_FIND_INDEX(stmt,idx);\
										if (idx == -1) {\
											STMT_VECTOR(stmt).emplace_back(stmt); \
											STMT_EXECUTED_VECTOR(stmt).emplace_back(strdup(query), &free);\
										} else {\
											STMT_EXECUTED_VECTOR(stmt)[idx] = std::unique_ptr<char,decltype(&free)>(strdup(query), &free);\
										}

#define STMT_LOAD_QUERY(stmt,query)		size_t idx = -1; \
										STMT_FIND_INDEX(stmt,idx);\
										if (idx != -1) query = STMT_EXECUTED_VECTOR(stmt)[idx].get();

#define STMT_REMOVE(stmt)				size_t idx = -1; \
										STMT_FIND_INDEX(stmt,idx);\
										if (idx != -1) {\
											std::vector<MYSQL_STMT*>& vec_stmt = STMT_VECTOR(stmt);\
											std::vector<std::unique_ptr<char,decltype(&free)>>& vec_query = STMT_EXECUTED_VECTOR(stmt);\
											if (idx != vec_stmt.size() - 1) {\
												vec_stmt[idx] = vec_stmt.back();\
												vec_query[idx] = std::move(vec_query.back());\
											}\
											vec_stmt.pop_back();\
											vec_query.pop_back();\
										}

#ifndef DISABLE_WARNING_COUNT_LOGGING

extern "C" {

MYSQL* mysql_init_override(MYSQL* mysql, const char* file, int line) {
	static bool init = false;
	MYSQL* result = (*real_mysql_init)(mysql);
	if (init == false) {
		init = true;
		fprintf(stdout, ">> [mysql_init] Override functions attached <<\n");
	}
	result->unused_0 = new std::string;
	result->unused_3 = nullptr;
	result->unused_4 = nullptr;
	return result;
}

int mysql_query_override(MYSQL* mysql, const char* query, const char* file, int line) {
	const int result = (*real_mysql_query)(mysql, query);
	if (result == 0) {
		if (LAST_QUERY_EXECUTED_PTR(mysql)) {
			LAST_QUERY_EXECUTED_STR(mysql) = query;
		}
		if (mysql_errno(mysql) == 0 && mysql_field_count(mysql) == 0 && mysql_warning_count(mysql) > 0) {
			fprintf(stdout, "File %s, Line %d, [mysql_query] A warning was generated during the execution of the query:'%s', warning count:%d\n",
				file, line, query, mysql_warning_count(mysql));
		}
	}
	return result;
}

MYSQL_RES* mysql_store_result_override(MYSQL* mysql, const char* file, int line) {
	MYSQL_RES* result = (*real_mysql_store_result)(mysql);
	if (mysql_errno(mysql) == 0 && mysql_warning_count(mysql) > 0 && LAST_QUERY_EXECUTED_PTR(mysql)) {
		fprintf(stdout, "File %s, Line %d, [mysql_store_result] A warning was generated during the execution of the query:'%s', warning count:%d\n",
			file, line, LAST_QUERY_EXECUTED_STR(mysql).c_str(), mysql_warning_count(mysql));
	}
	return result;
}

void mysql_close_override(MYSQL* mysql, const char* file, int line) {
	if (LAST_QUERY_EXECUTED_PTR(mysql)) {
		delete LAST_QUERY_EXECUTED_PTR(mysql);
	}
	if (STMT_VECTOR_PTR(mysql)) {
		delete STMT_VECTOR_PTR(mysql);
		delete STMT_EXECUTED_VECTOR_PTR(mysql);
	}
	(*real_mysql_close)(mysql);
}

MYSQL_STMT* mysql_stmt_init_override(MYSQL* mysql, const char* file, int line) {
	MYSQL_STMT* result = (*real_mysql_stmt_init)(mysql);
	if (result->mysql->unused_3 == nullptr) {
		std::vector<MYSQL_STMT*>* vec_stmt = new std::vector<MYSQL_STMT*>;
		std::vector<std::unique_ptr<char,decltype(&free)>>* vec_query = 
			new std::vector<std::unique_ptr<char,decltype(&free)>>;
		vec_stmt->reserve(64);
		vec_query->reserve(64);
		result->mysql->unused_3 = vec_stmt;
		result->mysql->unused_4 = vec_query;
	}
	return result;
}

int mysql_stmt_prepare_override(MYSQL_STMT* stmt, const char* stmt_str, unsigned long length, const char* file, int line) {
	const int result = (*real_mysql_stmt_prepare)(stmt, stmt_str, length);
	if (result == 0) {
		STMT_PUSH_QUERY(stmt,stmt_str);
		// mysql_stmt_warning_count is not available in MySQL connector
		if (mysql_stmt_errno(stmt) == 0 && /*mysql_stmt_warning_count(stmt)*/mysql_warning_count(stmt->mysql) > 0) {
			fprintf(stdout, "File %s, Line %d, [mysql_stmt_prepare] A warning was generated during the execution of the query:'%s', warning count:%d\n",
				file, line, stmt_str, /*mysql_stmt_warning_count(stmt)*/mysql_warning_count(stmt->mysql));
		}
	}
	return result;
}

int mysql_stmt_execute_override(MYSQL_STMT* stmt, const char* file, int line) {
	const int result = (*real_mysql_stmt_execute)(stmt);
	if (result == 0) {
		// mysql_stmt_warning_count is not available in MySQL connector
		if (mysql_stmt_errno(stmt) == 0 && mysql_stmt_field_count(stmt) == 0 && 
			/*mysql_stmt_warning_count(stmt)*/mysql_warning_count(stmt->mysql) > 0) {
			char* query = nullptr;
			STMT_LOAD_QUERY(stmt, query);
			fprintf(stdout, "File %s, Line %d, [mysql_stmt_execute] A warning was generated during the execution of the query:'%s', warning count:%d\n",
				file, line, (query ? query : ""), /*mysql_stmt_warning_count(stmt)*/mysql_warning_count(stmt->mysql));
		}
	}
	return result;
}

int mysql_stmt_store_result_override(MYSQL_STMT* stmt, const char* file, int line) {
	const int result = (*real_mysql_stmt_store_result)(stmt);
	if (result == 0) {
		// mysql_stmt_warning_count is not available in MySQL connector
		if (mysql_stmt_errno(stmt) == 0 && /*mysql_stmt_warning_count(stmt)*/mysql_warning_count(stmt->mysql) > 0) {
			char* query = nullptr;
			STMT_LOAD_QUERY(stmt, query);
			fprintf(stdout, "File %s, Line %d, [mysql_stmt_store_result] A warning was generated during the execution of the query:'%s', warning count:%d\n",
				file, line, (query ? query : ""), /*mysql_stmt_warning_count(stmt)*/mysql_warning_count(stmt->mysql));
		}
	}
	return result;
}

my_bool mysql_stmt_close_override(MYSQL_STMT* stmt, const char* file, int line) {
	STMT_REMOVE(stmt)
	return (*real_mysql_stmt_close)(stmt);
}

}

#endif

pair<int,vector<MYSQL*>> disable_core_nodes_scheduler(CommandLine& cl, MYSQL* admin) {
	vector<MYSQL*> nodes_conns {};

	pair<int,vector<srv_addr_t>> nodes_fetch { fetch_cluster_nodes(admin, true) };
	if (nodes_fetch.first) {
		diag("Failed to fetch cluster nodes. Aborting further testing");
		return { EXIT_FAILURE, {} };
	}

	// Ensure a more idle status for ProxySQL
	for (const srv_addr_t& node : nodes_fetch.second) {
		const char* user { cl.admin_username };
		const char* pass { cl.admin_password };

		MYSQL* myconn = mysql_init(NULL);

		if (!mysql_real_connect(myconn, node.host.c_str(), user, pass, NULL, node.port, NULL, 0)) {
			diag(
				"Failed to connect to Cluster node. Abort further testing"
				"   host=%s port=%d errno=%d error='%s'",
				node.host.c_str(), node.port, mysql_errno(myconn), mysql_error(myconn)
			);
			return { EXIT_FAILURE, {} };
		}

		const vector<const char*> queries { "DELETE FROM scheduler", "LOAD SCHEDULER TO RUNTIME" };
		for (const char* q : queries) {
			if (mysql_query_t(myconn, q)) {
				diag("Failed to execute query   query=%s error='%s'", q, mysql_error(myconn));
				return { EXIT_FAILURE, {} };
			}
		}

		nodes_conns.push_back(myconn);
	}

	return { EXIT_SUCCESS, nodes_conns };
}

std::size_t count_matches(const string& str, const string& substr) {
	std::size_t result = 0;
	std::size_t pos = 0;

	while ((pos = str.find(substr, pos)) != string::npos) {
		result += 1;
		pos += substr.length();
	}

	return result;
}

int mysql_query_t__(MYSQL* mysql, const char* query, const char* f, int ln, const char* fn) {
	diag("%s:%d:%s(): Issuing query '%s' to ('%s':%d)", f, ln, fn, query, mysql->host, mysql->port);
	return mysql_query(mysql, query);
}

int show_variable(MYSQL *mysql, const string& var_name, string& var_value) {
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

int select_config_file(MYSQL* mysql, string& resultset) {
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

int show_admin_global_variable(MYSQL *mysql, const string& var_name, string& var_value) {
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

int set_admin_global_variable(MYSQL *mysql, const string& var_name, const string& var_value) {
	char query[128];

	snprintf(query, sizeof(query),"update global_variables set variable_value = '%s' where variable_name='%s'", var_value.c_str(), var_name.c_str());
	if (mysql_query(mysql, query)) {
		fprintf(stderr, "Failed to execute SHOW VARIABLES LIKE : no %d, %s\n",
				mysql_errno(mysql), mysql_error(mysql));
		return exit_status();
	}
	return 0;
}


int get_server_version(MYSQL *mysql, string& version) {
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
	MYSQL_QUERY(mysql, "CREATE TABLE IF NOT EXISTS test.sbtest1 (`id` int(10) unsigned NOT NULL AUTO_INCREMENT, `k` int(10) unsigned NOT NULL DEFAULT '0', `c` char(120) NOT NULL DEFAULT '', `pad` char(60) NOT NULL DEFAULT '',  PRIMARY KEY (`id`), KEY `k_1` (`k`))");

	return add_more_rows_test_sbtest1(num_rows, mysql);
}

int create_table_test_sqlite_sbtest1(int num_rows, MYSQL *mysql) {
	MYSQL_QUERY(mysql, "DROP TABLE IF EXISTS sbtest1");
	MYSQL_QUERY(mysql, "CREATE TABLE IF NOT EXISTS sbtest1 (id INTEGER PRIMARY KEY AUTOINCREMENT, `k` int(10) NOT NULL DEFAULT '0', `c` char(120) NOT NULL DEFAULT '', `pad` char(60) NOT NULL DEFAULT '')");
	MYSQL_QUERY(mysql, "CREATE INDEX IF NOT EXISTS idx_sbtest1_k1 ON sbtest1 (k)");

	return add_more_rows_test_sbtest1(num_rows, mysql, true);
}

int execvp(const string& cmd, const std::vector<const char*>& argv, string& result) {
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
	string result_ = "";
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
			count = read(PARENT_READ_FD, buffer, sizeof(buffer)-1);
			while (count > 0) {
				buffer[count] = 0;
				result_ += buffer;
				count = read(PARENT_READ_FD, buffer, sizeof(buffer)-1);
			}
		} else {
			// Read from child’s stderr
			count = read(PARENT_READ_ERR, buffer, sizeof(buffer)-1);
			while (count > 0) {
				buffer[count] = 0;
				result_ += buffer;
				count = read(PARENT_READ_ERR, buffer, sizeof(buffer)-1);
			}
		}

		waitpid(child_pid, &err, 0);
	}

	result = result_;

	return err;
}

int exec(const string& cmd, string& result) {
	char buffer[128];
	string result_ = "";
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
			string field_val(row[i], lengths[i]);
			row_values.push_back(field_val);
		}

		result.push_back(row_values);
	}

	return result;
};

pair<uint32_t,vector<mysql_res_row>> mysql_query_ext_rows(MYSQL* mysql, const string& query) {
	int rc = mysql_query(mysql, query.c_str());
	if (rc != EXIT_SUCCESS) {
		return { mysql_errno(mysql), {} };
	}

	MYSQL_RES* myres = mysql_store_result(mysql);
	if (myres == nullptr) {
		return { mysql_errno(mysql), {} };
	}

	const vector<mysql_res_row> rows { extract_mysql_rows(myres) };
	mysql_free_result(myres);

	return { EXIT_SUCCESS, rows };
}

ext_val_t<string> ext_single_row_val(const mysql_res_row& row, const string& def_val) {
	if (row.empty() || row.front().empty()) {
		return { -1, def_val, {} };
	} else {
		return { EXIT_SUCCESS, string { row[0] }, string { row[0] } };
	}
}

ext_val_t<int32_t> ext_single_row_val(const mysql_res_row& row, const int32_t& def_val) {
	if (row.empty() || row.front().empty()) {
		return { -1, def_val, {} };
	} else {
        errno = 0;
        char* p_end {};
        const int32_t val = std::strtol(row.front().c_str(), &p_end, 10);

		if (row[0] == p_end || errno == ERANGE) {
			return { -2, def_val, string { row[0] } };
		} else {
			return { EXIT_SUCCESS, val, string { row[0] } };
		}
	}
}

ext_val_t<uint32_t> ext_single_row_val(const mysql_res_row& row, const uint32_t& def_val) {
	if (row.empty() || row.front().empty()) {
		return { -1, def_val, {} };
	} else {
        errno = 0;
        char* p_end {};
        const uint32_t val = std::strtoul(row.front().c_str(), &p_end, 10);

		if (row[0] == p_end || errno == ERANGE) {
			return { -2, def_val, string { row[0] } };
		} else {
			return { EXIT_SUCCESS, val, string { row[0] } };
		}
	}
}


ext_val_t<int64_t> ext_single_row_val(const mysql_res_row& row, const int64_t& def_val) {
	if (row.empty() || row.front().empty()) {
		return { -1, def_val, {} };
	} else {
        errno = 0;
        char* p_end {};
        const int64_t val = std::strtoll(row.front().c_str(), &p_end, 10);

		if (row[0] == p_end || errno == ERANGE) {
			return { -2, def_val, string { row[0] } };
		} else {
			return { EXIT_SUCCESS, val, string { row[0] } };
		}
	}
}

ext_val_t<uint64_t> ext_single_row_val(const mysql_res_row& row, const uint64_t& def_val) {
	if (row.empty() || row.front().empty()) {
		return { -1, def_val, {} };
	} else {
        errno = 0;
        char* p_end {};
        const uint64_t val = std::strtoull(row.front().c_str(), &p_end, 10);

		if (row[0] == p_end || errno == ERANGE) {
			return { -2, def_val, string { row[0] } };
		} else {
			return { EXIT_SUCCESS, val, string { row[0] } };
		}
	}
}

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
	const string& endpoint, const string& params, uint64_t& curl_res_code, string& curl_res_data
) {
	CURL *curl;
	CURLcode res;

	curl_global_init(CURL_GLOBAL_ALL);

	curl = curl_easy_init();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.c_str());
		struct memory response = { 0 };
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

		res = curl_easy_perform(curl);

		if(res != CURLE_OK) {
			curl_res_data = string { curl_easy_strerror(res) };
		} else {
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &curl_res_code);
			curl_res_data = string(response.data, response.size);
		}

		free(response.data);
		curl_easy_cleanup(curl);
	}

	return res;
}

CURLcode perform_simple_get(
	const string& endpoint, uint64_t& curl_res_code, string& curl_res_data
) {
	CURL *curl;
	CURLcode res;

	curl_global_init(CURL_GLOBAL_ALL);

	curl = curl_easy_init();
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
		struct memory response = { 0 };
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

		res = curl_easy_perform(curl);

		if(res != CURLE_OK) {
			curl_res_data = string { curl_easy_strerror(res) };
		} else {
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &curl_res_code);
			curl_res_data = string(response.data, response.size);
		}

		free(response.data);
		curl_easy_cleanup(curl);
	}

	return res;
}

int wait_post_enpoint_ready(string endpoint, string post_params, uint32_t timeout, uint32_t delay) {
	double waited = 0;
	int res = -1;

	while (waited < timeout) {
		string curl_resp_err {};
		uint64_t curl_res_code = 0;
		int curl_res = perform_simple_post(endpoint, post_params, curl_res_code, curl_resp_err);

		if (curl_res != CURLE_OK || curl_res_code != 200) {
			diag("'curl_res': %d, 'curl_err': '%s', waiting for '%d'ms...", curl_res, curl_resp_err.c_str(), delay);
			waited += static_cast<double>(delay);
			usleep(delay * 1000);
		} else {
			res = 0;
			break;
		}
	}

	return res;
}

int wait_get_enpoint_ready(string endpoint, uint32_t timeout, uint32_t delay) {
	double waited = 0;
	int res = -1;

	while (waited < timeout) {
		string curl_resp_err {};
		uint64_t curl_res_code = 0;
		int curl_res = perform_simple_get(endpoint, curl_res_code, curl_resp_err);

		if (curl_res != CURLE_OK || curl_res_code != 200) {
			diag("'curl_res': %d, 'curl_err': '%s', waiting for '%d'ms...", curl_res, curl_resp_err.c_str(), delay);
			waited += static_cast<double>(delay);
			usleep(delay * 1000);
		} else {
			res = 0;
			break;
		}
	}

	return res;
}

string random_string(std::size_t strSize) {
	string dic { "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" };

	std::random_device rd {};
	std::mt19937 generator { rd() };

	std::shuffle(dic.begin(), dic.end(), generator);

	if (strSize < dic.size()) {
		return dic.substr(0, strSize);
	} else {
		std::size_t req_modulus = static_cast<std::size_t>(strSize / dic.size());
		std::size_t req_reminder = strSize % dic.size();
		string random_str {};

		for (std::size_t i = 0; i < req_modulus; i++) {
			random_str.append(dic);
		}

		random_str.append(dic.substr(0, req_reminder));

		return random_str;
	}
}

const double COLISSION_PROB = 1e-8;

int wait_for_replication(
	MYSQL* proxy, MYSQL* proxy_admin, const string& check, uint32_t timeout, uint32_t read_hg
) {
	if (proxy == NULL) { return EXIT_FAILURE; }

	const string t_count_reader_hg_servers {
		"SELECT COUNT(*) FROM mysql_servers WHERE hostgroup_id=%d"
	};
	string count_reader_hg_servers {};
	size_t size =
		snprintf( nullptr, 0, t_count_reader_hg_servers.c_str(), read_hg) + 1;
	{
		std::unique_ptr<char[]> buf(new char[size]);
		snprintf(buf.get(), size, t_count_reader_hg_servers.c_str(), read_hg);
		count_reader_hg_servers = string(buf.get(), buf.get() + size - 1);
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

						string exp_res { "TRUE" };
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

int create_proxysql_user(
	MYSQL* proxysql_admin,
	const string& user,
	const string& pass,
	const string& attributes
) {
	string t_del_user_query { "DELETE FROM mysql_users WHERE username='%s'" };
	string del_user_query {};
	string_format(t_del_user_query, del_user_query, user.c_str());

	string t_insert_user {
		"INSERT INTO mysql_users (username,password,active,attributes)"
		" VALUES ('%s','%s',1,'%s')"
	};
	string insert_user {};
	string_format(t_insert_user, insert_user, user.c_str(), pass.c_str(), attributes.c_str());

	MYSQL_QUERY(proxysql_admin, del_user_query.c_str());
	MYSQL_QUERY(proxysql_admin, insert_user.c_str());

	return EXIT_SUCCESS;
}

int create_mysql_user(
	MYSQL* mysql_server,
	const string& user,
	const string& pass
) {
	const string t_drop_user_query { "DROP USER IF EXISTS %s@'%%'" };
	string drop_user_query {};
	string_format(t_drop_user_query, drop_user_query, user.c_str());

	const string t_create_user_query {
		"CREATE USER IF NOT EXISTS %s@'%%' IDENTIFIED WITH 'mysql_native_password' BY \"%s\""
	};
	string create_user_query {};
	string_format(t_create_user_query, create_user_query, user.c_str(), pass.c_str());

	const string t_grant_all_query { "GRANT ALL ON *.* TO %s@'%%'" };
	string grant_all_query { };
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
	std::vector<std::pair<string, string>> v_user_pass {};
	std::transform(
		std::begin(users_config),
		std::end(users_config),
		std::back_inserter(v_user_pass),
		[](const user_config& u_config) {
			return std::pair<string, string> {
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

string tap_curtime() {
	time_t __timer;
	char lut[30];
	struct tm __tm_info;
	time(&__timer);
	localtime_r(&__timer, &__tm_info);
	strftime(lut, 25, "%Y-%m-%d %H:%M:%S", &__tm_info);
	string s = string(lut);
	return s;
}

int get_proxysql_cpu_usage(const CommandLine& cl, uint32_t intv, double& cpu_usage) {
	// Create Admin connection
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}

	// Set new interval
	const string set_stats_query { "SET admin-stats_system_cpu=" + std::to_string(intv) };
	MYSQL_QUERY(proxysql_admin, set_stats_query.c_str());
	MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	// Wait until 'system_cpu' is filled with newer entries
	time_t curtime = time(NULL);
	uint32_t entry_count { 0 };

	const char runtime_stats[] {
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='admin-stats_system_cpu'"
	};
	ext_val_t<int> ext_rintv { mysql_query_ext_val(proxysql_admin, runtime_stats, 10) };
	if (ext_rintv.err != EXIT_SUCCESS) {
		const string err { get_ext_val_err(proxysql_admin, ext_rintv) };
		diag("Failed query   query:`%s`, err:`%s`", runtime_stats, err.c_str());
		return EXIT_FAILURE;
	}

	if (ext_rintv.val != intv) {
		diag(
			"WARNING: Supplied interval not available, using rounded value   intv=%d rintv=%d",
			intv, ext_rintv.val
		);
	}

	// sleep during the required interval + safe threshold
	const uint32_t init_wait = 2 * ext_rintv.val + 2;
	diag("Waiting for %d secs for new 'system_cpu' entries...   curtime=%ld", init_wait, curtime);
	sleep(init_wait);

	const string count_query {
		"SELECT COUNT(*) FROM system_cpu WHERE timestamp > " + std::to_string(curtime)
	};
	ext_val_t<int> ext_stats_count { mysql_query_ext_val(proxysql_admin, count_query, 10) };

	if (ext_stats_count.err != EXIT_SUCCESS) {
		const string err { get_ext_val_err(proxysql_admin, ext_stats_count) };
		diag("Failed query   query:`%s`, err:`%s`", count_query.c_str(), err.c_str());
		return EXIT_FAILURE;
	}

	entry_count = ext_stats_count.val;
	diag("Finished initial wait for 'system_cpu'   entry_count=%d", entry_count);

	while (entry_count < 2) {
		diag("Waiting for more 'system_cpu' entries...   entry_count=%d", entry_count);
		ext_val_t<int> ext_stats_count { mysql_query_ext_val(proxysql_admin, count_query, 10) };

		if (ext_stats_count.err != EXIT_SUCCESS) {
			const string err { get_ext_val_err(proxysql_admin, ext_stats_count) };
			diag("Failed query   query:`%s`, err:`%s`", count_query.c_str(), err.c_str());
			return EXIT_FAILURE;
		}

		entry_count = ext_stats_count.val;
		sleep(1);
	}

	MYSQL_QUERY(proxysql_admin, "SELECT * FROM system_cpu ORDER BY timestamp DESC LIMIT 2");
	MYSQL_RES* admin_res = mysql_store_result(proxysql_admin);
	MYSQL_ROW row = mysql_fetch_row(admin_res);

	double s_clk = (1000.0 / sysconf(_SC_CLK_TCK));

	int final_utime_s = atoi(row[1]) * s_clk;
	int final_stime_s = atoi(row[2]) * s_clk;
	int final_t_s = final_utime_s + final_stime_s;

	row = mysql_fetch_row(admin_res);

	int init_utime_s = atoi(row[1]) * s_clk;
	int init_stime_s = atoi(row[2]) * s_clk;
	int init_t_s = init_utime_s + init_stime_s;

	cpu_usage = 100.0 * ((final_t_s - init_t_s) / (static_cast<double>(ext_rintv.val) * 1000));

	// free the result
	mysql_free_result(admin_res);

	// recover admin variables
	MYSQL_QUERY(proxysql_admin, "SET admin-stats_system_cpu=60");
	MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	mysql_close(proxysql_admin);

	return EXIT_SUCCESS;
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
	MYSQL* proxysql_admin, const string& variable_name, string& variable_value, bool runtime
) {
	if (proxysql_admin == NULL) {
		return EINVAL;
	}

	int res = EXIT_FAILURE;

	const string t_select_var_query {
		"SELECT * FROM %sglobal_variables WHERE Variable_name='%s'"
	};
	string select_var_query {};

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
		string _variable_value { row[1] };
		variable_value = _variable_value;

		res = EXIT_SUCCESS;
	}

cleanup:

	mysql_free_result(admin_res);

	return res;
}

vector<vector<bool>> get_all_bin_vec(size_t tg_size) {
	vector<vector<bool>> all_bin_strs {};
	vector<bool> bin_vec(tg_size, 0);

	for (size_t i = 0; i < tg_size; i++) {
		if (i == 0) {
			bin_vec[i] = 0;
			for (const vector<bool> p : get_permutations(bin_vec)) {
				all_bin_strs.push_back(p);
			}
		}

		bin_vec[i] = 1;
		for (const vector<bool> p : get_permutations(bin_vec)) {
			all_bin_strs.push_back(p);
		}
	}

	return all_bin_strs;
}

string to_string(const conn_cnf_t& cnf) {
	return string {
		string { "{" }
			+ "\"enable_client_deprecate_eof\":" + std::to_string(cnf.f_conn_eof) + ","
			+ "\"enable_server_deprecate_eof\":" + std::to_string(cnf.b_conn_eof) + ","
			+ "\"client_compression\":" + std::to_string(cnf.f_conn_compr) + ","
			+ "\"server_compression\":" + std::to_string(cnf.b_conn_compr) + ","
			+ "\"fast_forward\":" + std::to_string(cnf.fast_forward) + ","
			+ "\"fast_forward_user\":''" + cnf.fast_forward_user + "'"
		"}"
	};
}

int execute_eof_test(
	const CommandLine& cl, MYSQL* mysql, const string& test, bool cl_depr_eof, bool srv_depr_eof
) {
	if (!mysql) { return -1; }

	string q_client_deprecate_eof { "SET mysql-enable_client_deprecate_eof='" + std::to_string(cl_depr_eof) + "'" };
	string q_server_deprecate_eof { "SET mysql-enable_server_deprecate_eof='" + std::to_string(srv_depr_eof) + "'" };

	MYSQL_QUERY(mysql, q_client_deprecate_eof.c_str() );
	MYSQL_QUERY(mysql, q_server_deprecate_eof.c_str() );

	MYSQL_QUERY(mysql, "LOAD MYSQL VARIABLES TO RUNTIME");

	int cache_res = system(string { string(cl.workdir) + test }.c_str());
	ok(
		cache_res == 0,
		"'%s' succeed with ('mysql-enable_client_deprecate_eof': '%d', 'mysql-enable_server_deprecate_eof': '%d')",
		test.c_str(),
		cl_depr_eof,
		srv_depr_eof
	);

	return cache_res;
}

int execute_eof_test(const CommandLine& cl, MYSQL* mysql, const string& test, const conn_cnf_t& conn_cnf) {
	if (!mysql) { return -1; }

	int test_res = 0;

	// Set 'DEPRECATE_EOF' flags
	string q_client_deprecate_eof { "SET mysql-enable_client_deprecate_eof='" + std::to_string(conn_cnf.f_conn_eof) + "'" };
	string q_server_deprecate_eof { "SET mysql-enable_server_deprecate_eof='" + std::to_string(conn_cnf.b_conn_eof) + "'" };

	MYSQL_QUERY_T(mysql, q_client_deprecate_eof.c_str() );
	MYSQL_QUERY_T(mysql, q_server_deprecate_eof.c_str() );

	MYSQL_QUERY_T(mysql, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Set server 'compression' flags
	string q_server_compr { "UPDATE mysql_servers SET compression=" + std::to_string(conn_cnf.b_conn_compr) };
	// Set client connection flags enabling compression
	if (conn_cnf.f_conn_compr) {
		setenv("TAP_CLIENT_FLAGS", "32", 1);
	} else {
		setenv("TAP_CLIENT_FLAGS", "0", 1);
	}

	MYSQL_QUERY_T(mysql, "LOAD MYSQL SERVERS TO RUNTIME");

	// Backup current username before changing it for the next test
	const char* pre_tap_user = getenv("TAP_USERNAME");
	if (conn_cnf.fast_forward_user.empty() == false) {
		setenv("TAP_USERNAME", conn_cnf.fast_forward_user.c_str(), 1);
	}
	// Config assumes same name and password for the test user
	const char* pre_tap_pass = getenv("TAP_PASSWORD");
	if (conn_cnf.fast_forward_user.empty() == false) {
		setenv("TAP_PASSWORD", conn_cnf.fast_forward_user.c_str(), 1);
	}

	// Set 'fast-forward' for target connecting user
	const string ff_str { std::to_string(conn_cnf.fast_forward) };
	const string ff_user { conn_cnf.fast_forward_user };
	const string q_ff_user {
		"UPDATE mysql_users SET fast_forward=" + ff_str + " WHERE username='" + ff_user + "'"
	};

	int rc = mysql_query_t(mysql, q_ff_user.c_str());

	if (rc) {
		diag("Query '%s' failed with error '%s'", q_ff_user.c_str(), mysql_error(mysql));
		goto cleanup;
	}

	{
		rc = mysql_query_t(mysql, "LOAD MYSQL USERS TO RUNTIME");
		if (rc) {
			diag("Query '%s' failed with error '%s'", q_ff_user.c_str(), mysql_error(mysql));
			goto cleanup;
		}

		test_res = system(string { string(cl.workdir) + test }.c_str());
		ok(test_res == 0, "'%s' should succeed with config '%s'", test.c_str(), to_string(conn_cnf).c_str());
	}

cleanup:

	// Recover previous 'TAP_USERNAME' env variable
	if (pre_tap_user) {
		setenv("TAP_USERNAME", pre_tap_user, 1);
	}
	if (pre_tap_user) {
		setenv("TAP_PASSWORD", pre_tap_pass, 1);
	}

	return test_res;
}

int get_cur_backend_conns(MYSQL* proxy_admin, const string& conn_type, uint32_t& found_conn_num) {
	MYSQL_QUERY(proxy_admin, string {"SELECT SUM(" + conn_type + ") FROM stats_mysql_connection_pool"}.c_str());

	MYSQL_ROW row = nullptr;
	MYSQL_RES* myres = mysql_store_result(proxy_admin);
	uint32_t field_num = mysql_num_fields(myres);

	if (field_num != 1) {
		diag("Invalid number of columns in resulset from 'stats_mysql_connection_pool': %d", field_num);
	} else {
		found_conn_num = std::strtol(row[0], NULL, 10);
	}

	return EXIT_SUCCESS;
}

string join_path(const string& p1, const string& p2) {
	if (p1.back() == '/') {
		return p1 + p2;
	} else {
		return p1 + '/' + p2;
	}
}

int check_endpoint_exists(MYSQL* admin, const ept_info_t& ept, bool& exists) {
	const string select_query {
		"SELECT count(*) FROM restapi_routes WHERE uri='" + ept.name + "' AND method='" + ept.method + "'"
	};
	MYSQL_QUERY(admin, select_query.c_str());
	MYSQL_RES* myres = mysql_store_result(admin);
	MYSQL_ROW myrow = mysql_fetch_row(myres);
	bool res = EXIT_FAILURE;

	if (myrow && myrow[0]) {
		int entry_num = std::atoi(myrow[0]);
		exists = entry_num != 0;

		res = EXIT_SUCCESS;
	} else {
		diag("Invalid resultset returned from query '%s'", select_query.c_str());

		res = EXIT_FAILURE;
	}

	mysql_free_result(myres);

	return res;
}

const char t_restapi_insert[] {
	"INSERT INTO restapi_routes (active, timeout_ms, method, uri, script, comment) "
		"VALUES (1,%ld,'%s','%s','%s','comm')",
};

const string base_address { "http://localhost:6070/sync/" };

int configure_endpoints(
	MYSQL* admin,
	const string& script_base_path,
	const vector<ept_info_t>& epts_info,
	const ept_info_t& dummy_ept,
	bool prevent_dups
) {
	MYSQL_QUERY(admin, "DELETE FROM restapi_routes");

	vector<ept_info_t> _epts_info { epts_info };
	_epts_info.push_back(dummy_ept);

	for (const ept_info_t& ept : _epts_info) {
		string f_exe_name {};
		string_format(ept.file, f_exe_name, ept.name.c_str());

		const string script_path { join_path(script_base_path, f_exe_name) };
		string insert_query {};
		string_format(
			t_restapi_insert, insert_query, ept.timeout, ept.method.c_str(), ept.name.c_str(), script_path.c_str()
		);

		bool duplicate_entry = false;
		if (check_endpoint_exists(admin, ept, duplicate_entry)) {
			return EXIT_FAILURE;
		}

		if (!(prevent_dups && duplicate_entry)) {
			MYSQL_QUERY(admin, insert_query.c_str());
		} else {
			diag(
				"Warning: Test payload trying to insert invalid duplicated entry - uri: '%s', method: '%s'",
				ept.name.c_str(), ept.method.c_str()
			);
			exit(EXIT_FAILURE);
		}
	}

	MYSQL_QUERY(admin, "LOAD RESTAPI TO RUNTIME");

	const string full_endpoint { join_path(base_address, dummy_ept.name) };
	int endpoint_timeout = wait_post_enpoint_ready(full_endpoint, "{}", 1000, 100);

	if (endpoint_timeout) {
		diag("Timeout while trying to reach first valid enpoint");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int extract_sqlite3_host_port(MYSQL* admin, std::pair<std::string, int>& host_port) {
	if (admin == nullptr) { return EINVAL; }

	const char varname[] { "sqliteserver-mysql_ifaces" };
	string sqlite3_ifaces {};

	// ProxySQL is likely to have been launched without "--sqlite3-server" flag
	if (get_variable_value(admin, varname, sqlite3_ifaces)) {
		diag("ProxySQL was launched without '--sqlite3-server' flag");
		return EXIT_FAILURE;
	}

	// Extract the correct port to connect to SQLite server
	std::string::size_type colon_pos = sqlite3_ifaces.find(":");
	if (colon_pos == std::string::npos) {
		diag("ProxySQL returned a malformed 'sqliteserver-mysql_ifaces': %s", sqlite3_ifaces.c_str());
		return EXIT_FAILURE;
	}

	std::string sqlite3_host { sqlite3_ifaces.substr(0, colon_pos) };
	std::string sqlite3_port { sqlite3_ifaces.substr(colon_pos + 1) };

	// Check that port has valid conversion
	char* end_pos = nullptr;
	int i_sqlite3_port = std::strtol(sqlite3_port.c_str(), &end_pos, 10);

	if (errno == ERANGE || (end_pos != &sqlite3_port.back() + 1)) {
		diag("ProxySQL returned a invalid port number within 'sqliteserver-mysql_ifaces': %s", sqlite3_ifaces.c_str());
		return EXIT_FAILURE;
	}

	host_port = { sqlite3_host, i_sqlite3_port };

	return EXIT_SUCCESS;
}

std::vector<std::string> split(const std::string& s, char delim) {
	std::istringstream tokenStream(s);
	std::vector<std::string> tokens {};

	std::string token {};
	while (std::getline(tokenStream, token, delim)) {
		tokens.push_back(token);
	}

	return tokens;
}

string get_env(const string& var) {
	string f_path {};

	char* p_infra_datadir = std::getenv(var.c_str());
	if (p_infra_datadir != nullptr) {
		f_path = p_infra_datadir;
	}

	return f_path;
}

int open_file_and_seek_end(const string& f_path, std::fstream& f_stream) {
	const char* c_f_path { f_path.c_str() };
	f_stream.open(f_path.c_str(), std::fstream::in | std::fstream::out);

	if (!f_stream.is_open() || !f_stream.good()) {
		diag("Failed to open '%s' file: { path: %s, error: %d }", basename(c_f_path), c_f_path, errno);
		return EXIT_FAILURE;
	}

	f_stream.seekg(0, std::ios::end);

	return EXIT_SUCCESS;
}

vector<line_match_t> get_matching_lines(fstream& f_stream, const string& s_regex, bool get_matches) {
	vector<line_match_t> found_matches {};

	string next_line {};
	fstream::pos_type init_pos { f_stream.tellg() };

	while (getline(f_stream, next_line)) {
		re2::RE2 regex { s_regex };
		re2::StringPiece match;

		if (get_matches && RE2::PartialMatch(next_line, regex, &match)) {
			found_matches.push_back({ f_stream.tellg(), next_line, match.ToString() });
		}
		if (!get_matches && RE2::PartialMatch(next_line, regex)) {
			found_matches.push_back({ f_stream.tellg(), next_line, match.ToString() });
		}
	}

	if (found_matches.empty() == false) {
		const string& last_match { std::get<LINE_MATCH_T::LINE>(found_matches.back()) };
		const fstream::pos_type last_match_pos { std::get<LINE_MATCH_T::POS>(found_matches.back()) };

		f_stream.clear(f_stream.rdstate() & ~std::ios_base::failbit);
		f_stream.seekg(last_match_pos);
	} else {
		f_stream.clear(f_stream.rdstate() & ~std::ios_base::failbit);
		f_stream.seekg(init_pos);
	}

	return found_matches;
}

const uint32_t USLEEP_SQLITE_LOCKED = 100;

int open_sqlite3_db(const string& f_path, sqlite3** db, int flags) {
	const char* c_f_path { f_path.c_str() };
	const char* base_path { basename(c_f_path) };
	int rc = sqlite3_open_v2(f_path.c_str(), db, flags, NULL);

	if (rc) {
		const char* err_msg = *db == nullptr ? "Failed to allocate" : sqlite3_errmsg(*db);
		diag("Failed to open sqlite3 db-file '%s': { path: %s, error: %s }", base_path, c_f_path, err_msg);
		return EXIT_FAILURE;
	} else {
		return EXIT_SUCCESS;
	}
}

sq3_res_t sqlite3_execute_stmt(sqlite3* db, const string& query) {
	int rc = 0;
	sqlite3_stmt* stmt = NULL;
	sq3_res_t res {};

	do {
		rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, 0);
		if (rc==SQLITE_LOCKED || rc==SQLITE_BUSY) {
			usleep(USLEEP_SQLITE_LOCKED);
		}
	} while (rc==SQLITE_LOCKED || rc==SQLITE_BUSY);

	if (rc != SQLITE_OK) {
		res = {{}, {}, {}, sqlite3_errmsg(db)};
		goto cleanup;
	}

	{
		// extract a resultset or just evaluate
		uint32_t cols_count = sqlite3_column_count(stmt);

		if (cols_count == 0) {
			do {
				rc = sqlite3_step(stmt);
				if (rc==SQLITE_LOCKED || rc==SQLITE_BUSY) {
					usleep(USLEEP_SQLITE_LOCKED);
				}
			} while (rc==SQLITE_LOCKED || rc==SQLITE_BUSY);

			if (rc == SQLITE_DONE) {
				uint32_t affected_rows = sqlite3_changes(db);
				res = {{}, {}, affected_rows, {}};
			} else {
				res = {{}, {}, {}, sqlite3_errmsg(db)};
				goto cleanup;
			}
		} else {
			vector<sq3_col_def_t> cols_defs {};
			vector<sq3_row_t> rows {};

			for (uint32_t i = 0; i < cols_count; i++) {
				cols_defs.push_back(sqlite3_column_name(stmt, i));
			}

			while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
				sq3_row_t row {};

				for (uint32_t i = 0; i < cols_count; i++) {
					if (sqlite3_column_type(stmt, i) == SQLITE_NULL) {
						row.push_back({});
					} else {
						row.push_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt, i)));
					}
				}

				rows.push_back(row);
			}

			res = { cols_defs, rows, 0, {} };
		}
	}

cleanup:
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	return res;
}

json fetch_internal_session(MYSQL* proxy, bool verbose) {
	int rc = 0;

	if (verbose) {
		rc = mysql_query_t(proxy, "PROXYSQL INTERNAL SESSION");
	} else {
		rc = mysql_query(proxy, "PROXYSQL INTERNAL SESSION");
	}

	if (rc) {
		return json {};
	} else {
		MYSQL_RES* myres = mysql_store_result(proxy);
		MYSQL_ROW row = mysql_fetch_row(myres);
		json j_session = json::parse(row[0]);
		mysql_free_result(myres);

		return j_session;
	}
}

pair<string, string> split_line_by_last(const string& ln, char c) {
	size_t pos = ln.find_last_of(c);

	if (pos == string::npos) {
		return { ln, "" };
	} else {
		const string f { ln.substr(0, pos) };
		const string s { ln.substr(pos + 1) };

		return { f, s };
	}
}

map<string, double> parse_prometheus_metrics(const string& s) {
	const vector<string> lines { split(s, '\n') };
	map<string, double> metrics_map {};

	for (const string ln : lines) {
		if (ln.empty() == false && ln[0] != '#') {
			pair<string, string> p_line_val { split_line_by_last(ln, ' ') };
			metrics_map.insert({p_line_val.first, stod(p_line_val.second)});
		}
	}

	return metrics_map;
}

struct cols_table_info_t {
	vector<string> names;
	vector<size_t> widths;
};

std::string dump_as_table(MYSQL_RES* result, const cols_table_info_t& cols_info) {
	if (!result) { return {}; }

	const vector<string>& cols_names { cols_info.names };
	const vector<size_t>& cols_widths { cols_info.widths };

	uint32_t num_fields = mysql_num_fields(result);
	std::string table_str { "+" };

	for (size_t width : cols_widths) {
		table_str += std::string(width + 2, '-') + "+";
	}
	table_str += "\n";

	table_str += "|";
	for (size_t col = 0; col < num_fields; col++) {
		table_str += " " + cols_names[col] + std::string(cols_widths[col] - cols_names[col].size(), ' ') + " |";
	}
	table_str += "\n";

	table_str += "+";
	for (size_t width : cols_widths) {
		table_str += std::string(width + 2, '-') + "+";
	}
	table_str += "\n";

	while (MYSQL_ROW row = mysql_fetch_row(result)) {
		table_str += "|";
		for (size_t col = 0; col < num_fields; col++) {
			std::string value = row[col] ? row[col] : "";
			table_str += " " + value + std::string(cols_widths[col] - value.size(), ' ') + " |";
		}
		table_str += "\n";
	}

	table_str += "+";
	for (size_t width : cols_widths) {
		table_str += std::string(width + 2, '-') + "+";
	}
	table_str += "\n";

	mysql_data_seek(result, 0);

	return table_str;
}

std::string dump_as_table(MYSQL_RES* result) {
	if (!result) { return {}; }

	uint32_t num_fields = mysql_num_fields(result);
	MYSQL_FIELD* fields = mysql_fetch_fields(result);

	vector<string> columns {};
	for (uint32_t i = 0; i < num_fields; ++i) {
		columns.push_back(fields[i].name);
	}

	vector<size_t> cols_widths(num_fields, 0);

	for (int col = 0; col < num_fields; ++col) {
		cols_widths[col] = std::max(cols_widths[col], columns[col].size());
	}

	while (MYSQL_ROW row = mysql_fetch_row(result)) {
		for (uint32_t col = 0; col < num_fields; col++) {
			if (row[col]) {
				cols_widths[col] = std::max(cols_widths[col], strlen(row[col]));
			}
		}
	}

	mysql_data_seek(result, 0);
	std::string res { dump_as_table(result, {columns, cols_widths}) };

	return res;
}

pair<int,vector<mysql_row_t>> exec_dql_query(MYSQL* conn, const string& query, bool dump_res) {
	if (mysql_query(conn, query.c_str())) {
		diag("Failed to executed query `%s`", query.c_str());
		return { EXIT_FAILURE, {} };
	}

	MYSQL_RES* my_stats_res = mysql_store_result(conn);
	if (my_stats_res == nullptr) {
		diag("Failed to retrieve a resultset, expected DQL query");

		return { EXIT_FAILURE, {} };
	} else {
		if (dump_res) {
			fprintf(stderr, "%s", dump_as_table(my_stats_res).c_str());
		}

		vector<mysql_row_t> my_rows { extract_mysql_rows(my_stats_res) };
		mysql_free_result(my_stats_res);

		return { EXIT_SUCCESS, my_rows };
	}
}

string join(string delim, const vector<string>& words) {
	return std::accumulate(
		words.begin(), words.end(), string {},
		[&delim] (const string& s1, const string& s2) {
			if (s1.empty()) {
				return s2;
			} else {
				return s1 + delim + s2;
			}
		}
	);
}

string gen_conn_stats_query(const vector<uint32_t>& hgs) {
	const auto _to_string = [] (uint32_t n) -> string { return to_string(n); };

	vector<string> hgs_str {};
	std::transform(hgs.begin(), hgs.end(), std::back_inserter(hgs_str), _to_string);

	const string CONN_STATS_HGS { join(",", hgs_str) };
	const string CONN_STATS_QUERY_T {
		"SELECT hostgroup,ConnUsed,ConnFree,ConnOk,ConnERR,MaxConnUsed,Queries"
			" FROM stats.stats_mysql_connection_pool"
	};

	if (hgs.empty()) {
		return CONN_STATS_QUERY_T;
	} else {
		return CONN_STATS_QUERY_T + " WHERE hostgroup IN (" + CONN_STATS_HGS +  ")";
	}
}

int dump_conn_stats(MYSQL* admin, const vector<uint32_t> hgs) {
	const string query { gen_conn_stats_query(hgs) };
	MYSQL_QUERY(admin, query.c_str());

	MYSQL_RES* myres = mysql_store_result(admin);
	const string table { dump_as_table(myres) };
	mysql_free_result(myres);
	fprintf(stderr, "%s", table.c_str());

	return EXIT_SUCCESS;
}

pair<int,pool_state_t> fetch_conn_stats(MYSQL* admin, const vector<uint32_t> hgs) {
	const string stats_query { gen_conn_stats_query(hgs) };
	const pair<int,vector<mysql_row_t>> conn_pool_stats { exec_dql_query(admin, stats_query, true) };

	if (conn_pool_stats.first || conn_pool_stats.second.size() != hgs.size()) {
		if (conn_pool_stats.first) {
			diag("Failed to extract stats from 'CONNPOOL'");
		}
		if (conn_pool_stats.second.size() != hgs.size()) {
			diag("Expected '%ld' row in 'CONNPOOL' stats resultset", hgs.size());
		}
		return { EXIT_FAILURE, {} };
	}

	if (conn_pool_stats.first) {
		return { conn_pool_stats.first, {} };
	} else {
		map<uint32_t,mysql_row_t> res_map {};

		for (const mysql_row_t& row : conn_pool_stats.second) {
			const string& column = row[POOL_STATS_IDX::HOSTGROUP];
			const uint32_t hg = std::stol(row[POOL_STATS_IDX::HOSTGROUP]);

			res_map.insert({ hg, row });
		}

		return { EXIT_SUCCESS, res_map };
	}
}

int check_cond(MYSQL* mysql, const string& q) {
	diag("Checking condition '%s' in ('%s':%d)", q.c_str(), mysql->host, mysql->port);

	int rc = mysql_query(mysql, q.c_str());
	int res = 1;

	if (rc == 0) {
		MYSQL_RES* myres = mysql_store_result(mysql);

		if (myres) {
			uint32_t field_num = mysql_num_fields(myres);
			uint32_t row_num = mysql_num_rows(myres);

			if (field_num == 1 && row_num == 1) {
				MYSQL_ROW myrow = mysql_fetch_row(myres);

				if (myrow && strcasecmp("TRUE", myrow[0]) == 0) {
					res = 0;
				} else if (myrow && atoi(myrow[0]) >= 1) {
					res = 0;
				}
			}
		}
	} else {
		diag("Check failed with error '%s'", mysql_error(mysql));
		res = -1;
	}

	return res;
}

int wait_for_cond(MYSQL* mysql, const string& q, uint32_t to) {
	diag("Waiting for condition '%s' in ('%s':%d)", q.c_str(), mysql->host, mysql->port);

	int result = 1;
	std::chrono::duration<double> elapsed {};

	auto start = std::chrono::system_clock::now();

	while (elapsed.count() < to && result == EXIT_FAILURE) {
		result = check_cond(mysql, q);

		if (result == 0 || result == -1) {
			break;
		}

		usleep(500 * 1000);

		auto it_end = std::chrono::system_clock::now();
		elapsed = it_end - start;
	}

	return result;
}

vector<check_res_t> wait_for_conds(MYSQL* mysql, const vector<string>& qs, uint32_t to) {
	diag("Waiting multiple conditions in ('%s':%d):", mysql->host, mysql->port);
	for (const string& q : qs) {
		diag("  - cond: '%s'", q.c_str());
	}

	std::chrono::duration<double> elapsed {};

	vector<check_res_t> res {};
	std::transform(qs.begin(), qs.end(), std::back_inserter(res),
		[] (const string& q) {
			return check_res_t { 1, q };
		}
	);
	auto start = std::chrono::system_clock::now();

	while (elapsed.count() < to) {
		int chk_res = 0;

		for (std::size_t i = 0; i < qs.size(); i++) {
			chk_res = check_cond(mysql, qs[i]);

			if (chk_res == -1) {
				diag("Error during query. Aborting further checks");
				res[i].first = -1;
				break;
			} else if (chk_res == 0) {
				res[i].first = 0;
			}
		}

		int acc = std::accumulate(res.begin(), res.end(), size_t(0),
			[] (size_t acc, const check_res_t& p) -> size_t {
				if (p.first == 0) {
					return acc + 1;
				} else {
					return acc;
				}
			});

		if (acc == qs.size() || chk_res == -1) {
			break;
		} else {
			usleep(500 * 1000);
			auto it_end = std::chrono::system_clock::now();
			elapsed = it_end - start;
		}
	}

	return res;
}

int proc_wait_checks(const vector<check_res_t>& chks) {
	int res = 0;

	for (const check_res_t& r : chks) {
		if (r.first == -1) {
			res = -1;
			diag("Waiting check FAILED to execute '%s'", r.second.c_str());
		} else if (r.first == 1)  {
			res = res == 0 ? 1 : res;
			diag("Waiting check TIMEOUT '%s'", r.second.c_str());
		}
	}

	return res;
}

void check_conn_count(MYSQL* admin, const string& conn_type, uint32_t conn_num, int32_t hg) {
	const string hg_s { to_string(hg) };
	const string conn_num_s { to_string(conn_num) };
	string select_conns_in_hg {};

	if (hg == -1) {
		select_conns_in_hg = "SELECT SUM(" + conn_type + ") FROM stats_mysql_connection_pool";
	} else {
		select_conns_in_hg = "SELECT " + conn_type + " FROM stats_mysql_connection_pool WHERE hostgroup=" + hg_s;
	}

	const string check_used_conns {
		"SELECT IIF((" + select_conns_in_hg + ")=" + conn_num_s + ",'TRUE','FALSE')"
	};

	int to = wait_for_cond(admin, check_used_conns, 3);
	ok(to == EXIT_SUCCESS, "Conns should met the required condition");

	if (to != EXIT_SUCCESS) {
		dump_conn_stats(admin, {});
	}
};

void check_query_count(MYSQL* admin, uint32_t queries, uint32_t hg) {
	const string queries_s { to_string(queries) };
	const string hg_s { to_string(hg) };

	const string select_hg_queries {
		"SELECT Queries FROM stats_mysql_connection_pool WHERE hostgroup=" + to_string(hg)
	};
	const string check_queries {
		"SELECT IIF((" + select_hg_queries + ")=" + queries_s + ",'TRUE','FALSE')"
	};

	int to = wait_for_cond(admin, check_queries, 3);
	ok(to == EXIT_SUCCESS, "Queries counted on hg '%d' should be '%d'", hg, queries);

	if (to != EXIT_SUCCESS) {
		dump_conn_stats(admin, {});
	}
};

void check_query_count(MYSQL* admin, vector<uint32_t> queries, uint32_t hg) {
	const string queries_s {
		std::accumulate(queries.begin(), queries.end(), std::string(),
			[](const std::string& str, const uint32_t& n) -> std::string {
				return str + (str.length() > 0 ? "," : "") + std::to_string(n);
			}
		)
	};
	const string hg_s { to_string(hg) };

	const string select_hg_queries {
		"SELECT Queries FROM stats_mysql_connection_pool WHERE hostgroup=" + to_string(hg)
	};
	const string check_queries {
		"SELECT IIF((" + select_hg_queries + ") IN (" + queries_s + "),'TRUE','FALSE')"
	};

	int to = wait_for_cond(admin, check_queries, 3);
	ok(to == EXIT_SUCCESS, "Queries counted on hg '%d' should be in '%s'", hg, queries_s.c_str());

	if (to != EXIT_SUCCESS) {
		dump_conn_stats(admin, {});
	} else {
		dump_conn_stats(admin, { hg });
	}
};

pair<int,vector<srv_addr_t>> fetch_cluster_nodes(MYSQL* admin, bool dump_fetch) {
	int rc = mysql_query_t(admin, "SELECT hostname,port FROM proxysql_servers");
	if (rc) { return { static_cast<int>(mysql_errno(admin)), {} }; }

	MYSQL_RES* myres = mysql_store_result(admin);
	if (myres == NULL) {
		diag("Storing resultset failed   error='%s'", mysql_error(admin));
		return { static_cast<int>(mysql_errno(admin)), {} };
	}

	if (dump_fetch) {
		const string res_table { dump_as_table(myres) };
		diag("Dumping fetched cluster nodes:");

		printf("%s", res_table.c_str());
	}

	vector<mysql_res_row> nodes_rows { extract_mysql_rows(myres) };
	mysql_free_result(myres);

	vector<srv_addr_t> nodes {};
	std::transform(nodes_rows.begin(), nodes_rows.end(), std::back_inserter(nodes),
		[] (const mysql_res_row& row) {
			return srv_addr_t { row[0], std::atoi(row[1].c_str()) };
		}
	);

	return { 0, nodes };
}

int check_nodes_sync(
	const CommandLine& cl, const vector<srv_addr_t>& nodes, const string& check, uint32_t to
) {
	for (const auto& node : nodes) {
		MYSQL* admin = mysql_init(NULL);

		if (
			!mysql_real_connect(
				admin, node.host.c_str(), cl.admin_username, cl.admin_password, NULL, node.port, NULL, 0
			)
		) {
			diag("File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
			return EXIT_FAILURE;
		}

		const vector<check_res_t> wres { wait_for_conds(admin, { check }, to) };
		int node_sync = proc_wait_checks(wres);

		if (node_sync != EXIT_SUCCESS) {
			const string err { "Node '" + node.host + ":" + std::to_string(node.port) + "' sync timed out" };
			diag("File %s, line %d, Error: %s\n", __FILE__, __LINE__, err.c_str());
			return EXIT_FAILURE;
		}

		mysql_close(admin);
	}

	return EXIT_SUCCESS;
}

const char* get_env_str(const char* envname, const char* envdefault) {
	const char* envval = std::getenv(envname);

	if (envval != NULL)
		return envval;

	return envdefault;
};

int get_env_int(const char* envname, int envdefault) {
	const char* envval = std::getenv(envname);
	int res = envdefault;

	if (envval != NULL)
		res = strtol(envval, NULL, 0);

	return res;
};

bool get_env_bool(const char* envname, bool envdefault) {

	const char* envval = std::getenv(envname);
	int res = envdefault;

	if (envval != NULL) {
		if (strcasecmp(envval, "true") == 0) {
			res = 1;
		} else if (strcasecmp(envval, "false") == 0) {
			res = 0;
		} else if (strcasecmp(envval, "yes") == 0) {
			res = 1;
		} else if (strcasecmp(envval, "no") == 0) {
			res = 0;
		} else if (strcasecmp(envval, "on") == 0) {
			res = 1;
		} else if (strcasecmp(envval, "off") == 0) {
			res = 0;
		} else {
			res = strtol(envval, NULL, 0);
		}
	}

	return (bool) res;
};
