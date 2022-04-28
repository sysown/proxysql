#include "proxysql_utils.h"

#include <functional>
#include <sstream>

#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/**
 * @brief Kills the given process sending an initial 'SIGTERM' to it. If the process doesn't
 *   respond within 'timeout_us' to the initial signal a 'SIGKILL' is issued to it.
 *
 * @param child_pid The process pid to be terminated.
 * @param timeout_us The timeout to be waited after sending the initial 'SIGTERM' before
 *   signaling the process with SIGKILL.
 * @param it_sleep_us The microseconds to sleep while waiting for the process to terminate.
 *
 * @return The error returned by 'kill' in case of it failing.
 */
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

/**
 * @brief Read the contents of the pipe, appending the result to supplied the supplied
 *   'std::string' till 'read()' returns '0' or error.
 *
 * @param pipe_fd The file descriptor from which to read.
 * @param sbuffer An 'std::string' in which to append the data readed from the pipe.
 *
 * @return '0' if all the contents of the pipe were read properly, otherwise '-1' is
 *   returned and 'errno' holds the error code for the failed 'read()'.
 */
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

uint64_t get_timestamp_us() {
	struct timeval start_tv {};
	gettimeofday(&start_tv, nullptr);
	uint64_t start_timestamp = (1000000ull * start_tv.tv_sec) + start_tv.tv_usec;

	return start_timestamp;
}

int wexecvp(
	const std::string& file,
	const std::vector<const char*>& argv,
	const to_opts* opts,
	std::string& s_stdout,
	std::string& s_stderr
) {
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
	to_opts to_opts { 0, 100*1000, 500*1000, 2000*1000 };

	if (opts) {
		to_opts.timeout_us = opts->timeout_us;
		to_opts.it_delay_us = opts->it_delay_us;
		to_opts.select_to_us = opts->select_to_us;
		to_opts.sigkill_timeout_us = opts->sigkill_timeout_us;
	}

	// Pipes for parent to write and read
	int read_p_err = pipe(pipes[PARENT_READ_PIPE]);
	int write_p_err = pipe(pipes[PARENT_WRITE_PIPE]);
	int err_p_err = pipe(pipes[PARENT_ERR_PIPE]);

	if (read_p_err || write_p_err || err_p_err) {
		return -1;
	}

	pid_t child_pid = fork();
	if (child_pid == -1) {
		return -2;
	}

	if(child_pid == 0) {
		int child_err = 0;
		std::vector<const char*> _argv = argv;

		// Append null to end of _argv for extra safety
		_argv.push_back(nullptr);
		// Duplicate file argument to avoid manual duplication
		_argv.insert(_argv.begin(), file.c_str());

		// Copy the pipe descriptors
		int dup_read_err = dup2(CHILD_READ_FD, STDIN_FILENO);
		int dup_write_err = dup2(CHILD_WRITE_FD, STDOUT_FILENO);
		int dup_err_err = dup2(CHILD_WRITE_ERR, STDERR_FILENO);

		if (dup_read_err == -1 || dup_write_err == -1 || dup_err_err == -1) {
			exit(errno);
		}

		// Close no longer needed pipes
		close(CHILD_READ_FD);
		close(CHILD_WRITE_FD);
		close(CHILD_WRITE_ERR);

		close(PARENT_READ_FD);
		close(PARENT_READ_ERR);
		close(PARENT_WRITE_FD);

		char** args = const_cast<char**>(_argv.data());
		child_err = execvp(file.c_str(), args);

		if (child_err) {
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
		int cntl_non_err = fcntl(PARENT_READ_FD, F_SETFL, fcntl(PARENT_READ_FD, F_GETFL) | O_NONBLOCK);
		int cntl_err_err = fcntl(PARENT_READ_ERR, F_SETFL, fcntl(PARENT_READ_ERR, F_GETFL) | O_NONBLOCK);

		fd_set read_fds;
		int maxfd = PARENT_READ_FD > PARENT_READ_ERR ? PARENT_READ_FD : PARENT_READ_ERR;

		bool stdout_eof = false;
		bool stderr_eof = false;

		// Record the start timestamp
		uint64_t start_timestamp = get_timestamp_us();

		if ((cntl_err_err || cntl_non_err) || maxfd >= FD_SETSIZE) {
			close(PARENT_READ_FD);
			close(PARENT_READ_ERR);
			close(PARENT_WRITE_FD);

			if (cntl_err_err || cntl_non_err) {
				pipe_err = -3;
			} else {
				pipe_err = -4;
			}

			// Kill child and return error
			kill_child_proc(child_pid, to_opts.sigkill_timeout_us, to_opts.it_delay_us);
			// Recover errno before return
			errno = errno_cpy;
			// Avoid loop
			goto loop_exit;
		}

		while (!stdout_eof || !stderr_eof) {
			FD_ZERO(&read_fds);
			FD_SET(PARENT_READ_FD, &read_fds);
			FD_SET(PARENT_READ_ERR, &read_fds);

			// Wait for the pipes to be ready
			timeval select_to = { 0, to_opts.select_to_us };
			int select_err = select(maxfd + 1, &read_fds, NULL, NULL, &select_to);

			// Unexpected error while executing 'select'
			if (select_err < 0 && errno != EINTR) {
				pipe_err = -5;
				// Backup read errno
				errno_cpy = errno;
				// Kill child and return error
				kill_child_proc(child_pid, to_opts.sigkill_timeout_us, to_opts.it_delay_us);
				// Recover errno before return
				errno = errno_cpy;
				// Exit the loop
				break;
			}

			if (FD_ISSET(PARENT_READ_FD, &read_fds) && stdout_eof == false) {
				int read_res = read_pipe(PARENT_READ_FD, stdout_);

				if (read_res == 0) {
					stdout_eof = true;
				}
				// Unexpected error while reading pipe
				if (read_res < 0) {
					pipe_err = -6;
					// Backup read errno
					errno_cpy = errno;
					// Kill child and return error
					kill_child_proc(child_pid, to_opts.sigkill_timeout_us, to_opts.it_delay_us);
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
					pipe_err = -6;
					// Backup read errno
					errno_cpy = errno;
					// Kill child and return error
					kill_child_proc(child_pid, to_opts.sigkill_timeout_us, to_opts.it_delay_us);
					// Recover errno before return
					errno = errno_cpy;
					// Exit the loop
					break;
				}
			}

			// Check that the execution hasn't execeed the specified timeout
			if (to_opts.timeout_us != 0) {
				uint64_t current_timestamp = get_timestamp_us();
				if ((start_timestamp + to_opts.timeout_us) < current_timestamp) {
					// Backup read errno
					errno_cpy = errno;
					kill_child_proc(child_pid, to_opts.sigkill_timeout_us, to_opts.it_delay_us);
					// Recover errno before return
					errno = errno_cpy;
					// Set 'pipe_err' to 'ETIME' to reflect timeout
					pipe_err = ETIME;
					// Exit the loop
					break;
				}
			}
		}

loop_exit:

		// Close no longer needed pipes
		close(PARENT_READ_FD);
		close(PARENT_READ_ERR);
		close(PARENT_WRITE_FD);

		if (pipe_err == 0) {
			waitpid(child_pid, &err, 0);
		} else {
			err = pipe_err;
		}

		if (pipe_err == 0 || pipe_err == ETIME) {
			s_stdout = stdout_;
			s_stderr = stderr_;
		}
	}

	return err;
}

std::string replace_str(const std::string& str, const std::string& match, const std::string& repl) {
	if(match.empty()) {
		return str;
	}

	std::string result = str;
	size_t start_pos = 0;

	while((start_pos = result.find(match, start_pos)) != std::string::npos) {
		result.replace(start_pos, match.length(), repl);
		start_pos += repl.length();
	}

	return result;
}
