#include <mysql.h>
#include <unistd.h>
#include <sys/wait.h>

#include "tap.h"
#include "utils.h"

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
