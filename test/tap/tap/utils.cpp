
#include <stdio.h>
#include <mysql.h>
#include <unistd.h>
#include <sys/wait.h>

#include "tap.h"
#include "utils.h"

std::string err_msg(const std::string& msg, const char* file, int line) {
	const char* err_msg = "File %s, line %d, Error: \n";
	int size = snprintf(nullptr, 0, err_msg, file, line);

	std::unique_ptr<char[]> buf(new char[size]);
	snprintf(buf.get(), size, err_msg, file, line);
	std::string fmt_string(buf.get(), buf.get() + size - 1);

	return fmt_string + msg;
}

key_map fetch_assoc(MYSQL_RES* mysql_res) {
	key_map result_map {};
	MYSQL_ROW row = NULL;
	MYSQL_FIELD* field = NULL;

	std::vector<std::vector<std::string>> field_values {};
	unsigned int num_fields = mysql_num_fields(mysql_res);
	while ((row = mysql_fetch_row(mysql_res))) {
		unsigned long *lengths;
		lengths = mysql_fetch_lengths(mysql_res);
		for(int i = 0; i < num_fields; i++) {
			std::string value(row[i] ? row[i] : "NULL", static_cast<int>(lengths[i]));
			if (field_values.size() <= i) {
				field_values.push_back(std::vector<std::string> { value });
			} else {
				field_values[i].push_back(value);
			}
		}
	}

	int field_idx = 0;
	while ((field = mysql_fetch_field(mysql_res))) {
		std::string field_name = field->name;
		result_map.push_back({field_name, field_values[field_idx]});
		field_idx += 1;
	}

	return result_map;
}

std::vector<m_row> get_rows(key_map map) {
	std::vector<m_row> _rows {};
	if (map.size() == 0) {
		return _rows;
	}

	size_t row_num = map.front().second.size();
	for (size_t i = 0; i < row_num; i++) {
		_rows.push_back(m_row {});
	}

	for (const auto& key_values : map) {
		size_t row_idx = 0;
		for (const auto& val : key_values.second) {
			_rows[row_idx].push_back(val);
			row_idx++;
		}
	}

	return _rows;
}

std::string join(const std::vector<std::string>& vec, const std::string& sep) {
	std::string result {};
	for (size_t i = 0; i < vec.size(); i++) {
		if (i != 0 && i != vec.size()) {
			result += sep + vec[i];
		} else {
			result += vec[i];
		}
	}
	return result;
}

m_row get_matching_row(key_map map, const std::string& colum_name, const std::string& value) {
	m_row row {};

	auto name_colum = std::find_if(
		map.begin(),
		map.end(),
		[&colum_name] (const map_pair& key_val) {
			return key_val.first == colum_name;
		}
	);

	auto proxysql_servers_it =
		std::find(
			name_colum->second.begin(),
			name_colum->second.end(),
			value
		);

	if (proxysql_servers_it != std::end(name_colum->second)) {
		int proxysql_servers_idx =
			std::distance(name_colum->second.begin(), proxysql_servers_it);

		for (const auto& cname_values : map) {
			row.push_back(cname_values.second[proxysql_servers_idx]);
		}
	}

	return row;
}

std::vector<std::string> compare_row(const m_row& exp_row, const m_row& act_row) {
	if (exp_row.size() != act_row.size()) {
		return std::vector<std::string> { "compare_row: rows have different sizes."};
	}

	std::vector<std::string> errors {};
	size_t it = 0;

	for (const auto& exp_val : exp_row) {
		const auto& act_val = act_row[it];

		if (exp_val == "*") {
			if (act_val == "" || act_val == "NULL") {
				const std::string t_err_msg = "\"compare_row: colum %d value shouldn't be null.\"";
				std::string err_msg {};
				string_format(t_err_msg, err_msg, it);

				errors.push_back(err_msg);
			}
		} else if (exp_val != "\0") {
			if (exp_val != act_val) {
				const std::string t_err_msg = "\"compare_row: colum %d values doens't match - '%s' != '%s'.\"";
				std::string err_msg {};
				string_format(t_err_msg, err_msg, it, exp_val.c_str(), act_val.c_str());

				errors.push_back(err_msg);
			}
		}
		it++;
	}

	return errors;
}

int fetch_count(MYSQL_RES* mysql_res) {
	// Check if the query have just one field and one column
	if (mysql_num_fields(mysql_res) != 1 || mysql_num_rows(mysql_res) != 1) {
		return -1;
	}

	MYSQL_ROW row = mysql_fetch_row(mysql_res);
	unsigned long* lengths = mysql_fetch_lengths(mysql_res);
	std::string value(row[0], static_cast<int>(lengths[0]));

	// Parse the query number
	char* p_end = nullptr;
	int res = strtol(value.c_str(), &p_end, 10);
	// Query result number failed to be parsed
	if (p_end == value.c_str()) {
		res = -2;
	}

	return res;
}

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

int execvp(const std::string& cmd, const std::vector<const char*>& argv, std::string& result) {
	int err = 0;
	std::string result_ = "";
	std::vector<const char*> _argv = argv;

	// Append null to end of _argv for extra safety
	_argv.push_back(nullptr);

	int outfd[2];
	int infd[2];

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
