#include <string>
#include <cstring>
#include <mysql.h>
#include <unistd.h>
#include <sys/wait.h>

#include "tap.h"
#include "utils.h"

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <iostream>

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

int kill_child_proc(pid_t child_pid, const uint timeout_us, const uint it_sleep_us) {
	uint err = 0;
	uint waited = 0;
	int child_status = 0;

	err = kill(child_pid, SIGTERM);

	while (waitpid(child_pid, &child_status, WNOHANG) == 0) {
		if (waited >= timeout_us) {
			kill(child_pid, SIGKILL);
			waited = 0;
		} else {
			waited += it_sleep_us;
		}

		usleep(it_sleep_us);
	}

	return err;
}

int read_pipe(int pipe_fd, std::string& sbuffer) {
	char buffer[128];
	ssize_t count = 0;
	int res = 1;

	for (;;) {
		count = read(pipe_fd, (void*)buffer, sizeof(buffer) - 1);
		if (count > 0) {
			buffer[count] = 0;
			sbuffer += buffer;
		} else if (count == 0){
			res = 0;
			break;
		} else {
			if (errno != EWOULDBLOCK && errno != EINTR) {
				res = -1;
			}
			break;
		}
	}

	return res;
}

int wexecvp(const std::string& file, const std::vector<const char*>& argv, const to_opts* opts, std::string& s_stdout, std::string& s_stderr) {
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
	to_opts to_opts { 1000*1000, 100*1000, 500*1000 };

	int outfd[2];
	int infd[2];

	// Pipes for parent to write and read
	pipe(pipes[PARENT_READ_PIPE]);
	pipe(pipes[PARENT_WRITE_PIPE]);
	pipe(pipes[PARENT_ERR_PIPE]);

	pid_t child_pid = fork();
	if(child_pid == 0) {
		std::vector<const char*> _argv = argv;

		// Append null to end of _argv for extra safety
		_argv.push_back(nullptr);
		// Duplicate file argument to avoid manual duplication
		_argv.insert(_argv.begin(), file.c_str());

		if (opts) {
			to_opts.timeout_us = opts->timeout_us;
			to_opts.it_delay_us = opts->it_delay_us;
		}

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
		err = execvp(file.c_str(), args);

		if (err) {
			exit(errno);
		} else {
			exit(0);
		}
	} else {
		int errno_cpy = 0;
		int pipe_err = 0;

		std::string stdout_ = "";
		std::string stderr_ = "";

		// Close no longer needed pipes
		close(CHILD_READ_FD);
		close(CHILD_WRITE_FD);
		close(CHILD_WRITE_ERR);

		// Set the pipes in non-blocking mode
		fcntl(PARENT_READ_FD, F_SETFL, fcntl(PARENT_READ_FD, F_GETFL) | O_NONBLOCK);
		fcntl(PARENT_READ_ERR, F_SETFL, fcntl(PARENT_READ_ERR, F_GETFL) | O_NONBLOCK);

		fd_set read_fds;
		uint read_fds_sz = 2;
		int maxfd = PARENT_READ_FD > PARENT_READ_ERR ? PARENT_READ_FD : PARENT_READ_ERR;

		bool stdout_eof = false;
		bool stderr_eof = false;

		while (!stdout_eof || !stderr_eof) {
			FD_ZERO(&read_fds);
			FD_SET(PARENT_READ_FD, &read_fds);
			FD_SET(PARENT_READ_ERR, &read_fds);

			// Wait for the pipes to be ready
			timeval select_to = { 0, to_opts.select_to_us };
			select(maxfd + 1, &read_fds, NULL, NULL, &select_to);

			if (FD_ISSET(PARENT_READ_FD, &read_fds) && stdout_eof == false) {
				int read_res = read_pipe(PARENT_READ_FD, stdout_);

				if (read_res == 0) {
					stdout_eof = true;
				}
				// Unexpected error while reading pipe
				if (read_res < 0) {
					pipe_err = -1;
					// Backup read errno
					errno_cpy = errno;
					// Kill child and return error
					kill_child_proc(child_pid, to_opts.timeout_us, to_opts.it_delay_us);
					// Recover errno before return
					errno = errno_cpy;
					// Exit the loop
					break;
				}
			}

			if(FD_ISSET(PARENT_READ_ERR, &read_fds) && stderr_eof == false) {
				int read_res = read_pipe(PARENT_READ_ERR, stderr_);

				if (read_res == 0) {
					stderr_eof = true;
				}
				// Unexpected error while reading pipe
				if (read_res < 0) {
					pipe_err = -1;
					// Backup read errno
					errno_cpy = errno;
					// Kill child and return error
					kill_child_proc(child_pid, to_opts.timeout_us, to_opts.it_delay_us);
					// Recover errno before return
					errno = errno_cpy;
					// Exit the loop
					break;
				}
			}
		}

		if (pipe_err == 0) {
			waitpid(child_pid, &err, 0);
		}

		if (pipe_err == 0) {
			s_stdout = stdout_;
			s_stderr = stderr_;
		} else {
			err = pipe_err;
		}
	}

	return err;
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