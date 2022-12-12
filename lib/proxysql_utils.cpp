#include "proxysql_utils.h"

#include <functional>
#include <sstream>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>

using std::string;
using std::vector;

__attribute__((__format__ (__printf__, 1, 2)))
cfmt_t cstr_format(const char* fmt, ...) {
    va_list args;

    va_start(args, fmt);
    int size = vsnprintf(nullptr, 0, fmt, args);
    va_end(args);

    if (size <= 0) {
        return { size, {} };
    } else {
        size += 1;
        std::unique_ptr<char[]> buf(new char[size]);

        va_start(args, fmt);
        size = vsnprintf(buf.get(), size, fmt, args);
        va_end(args);

        if (size <= 0) {
            return { size, {} };
        } else {
            return { size, std::string(buf.get(), buf.get() + size) };
        }
    }
 }

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
int kill_child_proc(pid_t child_pid, const uint timeout_us, const uint waitpid_sleep_us) {
	uint err = 0;
	uint waited = 0;
	int child_status = 0;

	err = kill(child_pid, SIGTERM);

	while (waitpid(child_pid, &child_status, WNOHANG) == 0) {
		if (waited >= timeout_us) {
			kill(child_pid, SIGKILL);
			waited = 0;
		} else {
			waited += waitpid_sleep_us;
		}

		usleep(waitpid_sleep_us);
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

/**
 * @brief Verifies if the supplied process 'pid' exists within the supplied 'timeout'.
 *
 * @param pid The pid of the process to monitor.
 * @param status A point to an int to be updated with the child status reported by 'waitpid'.
 * @param timeout The maximum timeout to wait for the child to exit.
 *
 * @return 'True' in case the child exited before the timeout, 'false' otherwise.
 */
bool check_child_exit(pid_t pid, int* status, uint32_t timeout) {
	uint32_t check_delay = 100;
	uint32_t cur_waited = 0;

	bool proc_exit = false;

	while (cur_waited < timeout) {
		pid_t w_res = waitpid(pid, status, WNOHANG);

		if (w_res == -1 && errno == ECHILD) {
			proc_exit = true;
			break;
		}

		usleep(check_delay * 1000);
		cur_waited += check_delay;
	}

	return proc_exit;
}

/**
 * @brief Struct for holding an error code and current 'errno' after failed syscall.
 */
struct syserr_t {
	int err;
	int _errno;
};

/**
 * @brief Struct holding information about the child status.
 */
struct child_status_t {
	/* @brief Holds the state of the 'stdout' reading pipe */
	bool stdout_eof;
	/* @brief Holds the state of the 'stderr' reading pipe */
	bool stderr_eof;
	/* @brief Holds the error state from last syscall used to interact with child */
	syserr_t syserr;
};

/**
 * @brief Reads from 'pipe_fd' into 'buf' and updates the provided 'child_status_t'.
 *
 * @param pipe_fd The pipe fd from which to read.
 * @param buf The buffer to be udpated with the read contents.
 * @param st The child status to be updated with possible 'read' errors.
 *
 * @return 'True' in case 'read' returned '0', meaning pipe has been closed, 'false' otherwise.
 */
bool read_pipe(int pipe_fd, string& buf, child_status_t& st) {
	int read_res = read_pipe(pipe_fd, buf);

	// Unexpected error while reading pipe
	if (read_res < 0) {
		st.syserr = { -5, errno };
	} else {
		st.syserr = { 0, 0 };
	}

	return read_res == 0;
}

int wexecvp(
	const string& file, const vector<const char*>& argv, const to_opts_t& opts, string& s_stdout, string& s_stderr
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

	int child_err = 0;
	to_opts_t to_opts { 0, 100*1000, 500*1000, 2000*1000 };

	if (opts.timeout_us != 0) to_opts.timeout_us = opts.timeout_us;
	if (opts.poll_to_us != 0) to_opts.poll_to_us = opts.poll_to_us;
	if (opts.waitpid_delay_us != 0) to_opts.waitpid_delay_us = opts.waitpid_delay_us;
	if (opts.sigkill_to_us != 0) to_opts.sigkill_to_us = opts.sigkill_to_us;

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
		std::string stdout_ {};
		std::string stderr_ {};

		// Close no longer needed pipes
		close(CHILD_READ_FD);
		close(CHILD_WRITE_FD);
		close(CHILD_WRITE_ERR);

		// Record the start timestamp
		uint64_t start_timestamp = get_timestamp_us();

		// Declare the two pollfd to be used for the pipes
		struct pollfd read_fds[2] = { { 0 } };

		// Set the pipes in non-blocking mode
		int cntl_non_err = fcntl(PARENT_READ_FD, F_SETFL, fcntl(PARENT_READ_FD, F_GETFL) | O_NONBLOCK);
		int cntl_err_err = fcntl(PARENT_READ_ERR, F_SETFL, fcntl(PARENT_READ_ERR, F_GETFL) | O_NONBLOCK);

		child_status_t st { 0 };

		if (cntl_err_err || cntl_non_err) {
			st.syserr = { -3, errno };
		}

		while ((!st.stdout_eof || !st.stderr_eof) && !st.syserr.err) {
			memset(&read_fds, 0, sizeof(read_fds));

			// Ignore the already closed FDs
			read_fds[0].fd = st.stdout_eof == false ? PARENT_READ_FD : -1;
			read_fds[0].events = POLLIN;
			read_fds[1].fd = st.stderr_eof == false ? PARENT_READ_ERR : -1;
			read_fds[1].events = POLLIN;

			// Wait for the pipes to be ready
			uint poll_to = to_opts.poll_to_us / 1000;
			poll_to = poll_to == 0 ? 1 : poll_to;
			int poll_err = poll(read_fds, sizeof(read_fds)/sizeof(pollfd), poll_to);

			// Unexpected error while executing 'poll'
			if (poll_err < 0 && errno != EINTR) {
				st.syserr = { -4, errno };
				continue;
			}

			if ((read_fds[0].revents & POLLIN) && st.stdout_eof == false) {
				st.stdout_eof = read_pipe(PARENT_READ_FD, stdout_, st);
				if (st.syserr.err) { continue; }
			}

			if ((read_fds[1].revents & POLLIN) && st.stderr_eof == false) {
				st.stderr_eof = read_pipe(PARENT_READ_ERR, stderr_, st);
				if (st.syserr.err) { continue; }
			}

			// Update the closed state for the pipes
			st.stdout_eof = st.stdout_eof == false ? read_fds[0].revents & POLLHUP : true;
			st.stderr_eof = st.stderr_eof == false ? read_fds[1].revents & POLLHUP : true;

			// Check that execution hasn't exceed the specified timeout
			if (to_opts.timeout_us != 0) {
				uint64_t current_timestamp = get_timestamp_us();
				if ((start_timestamp + to_opts.timeout_us) < current_timestamp) {
					st.syserr = { ETIME, errno };
					continue;
				}
			}
		}

		// Close no longer needed pipes
		close(PARENT_READ_FD);
		close(PARENT_READ_ERR);
		close(PARENT_WRITE_FD);

		// In a best effort, we return read data also for expired timeouts
		if (st.syserr.err == 0 || st.syserr.err == ETIME) {
			s_stdout = stdout_;
			s_stderr = stderr_;
		}

		if (st.syserr.err == 0) {
			bool child_exited = check_child_exit(child_pid, &child_err, 1000);

			if (child_exited == false) {
				kill_child_proc(child_pid, to_opts.sigkill_to_us, to_opts.waitpid_delay_us);
			}
		} else {
			kill_child_proc(child_pid, to_opts.sigkill_to_us, to_opts.waitpid_delay_us);

			child_err = st.syserr.err;
			errno = st.syserr._errno;
		}
	}

	return child_err;
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

std::string generate_multi_rows_query(int rows, int params) {
	std::string s = "";
	int v = 1;
	for (int r = 0; r < rows; r++) {
		s += "(";
		for (int p = 0; p < params; p++) {
			s+= "?" + std::to_string(v);
			v++;
			if (p != (params-1)) {
				s+= ", ";
			}
		}
		s += ")";
		if (r != (rows -1) ) {
			s+= ", ";
		}
	}
	return s;
}
