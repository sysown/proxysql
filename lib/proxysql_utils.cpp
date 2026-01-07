#include "proxysql_utils.h"
#include "mysqld_error.h"

#include <algorithm>
#include <functional>
#include <sstream>
#include <algorithm>
#include <climits>

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <random>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <linux/close_range.h>

using std::function;
using std::string;
using std::string_view;
using std::unique_ptr;
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

string hex(const string_view& str) {
	std::ostringstream hex_stream;

	 for (unsigned char c : str) {
		hex_stream << std::hex << std::setfill('0') << std::setw(2) <<
			std::uppercase << static_cast<uint64_t>(c);
	}

	return hex_stream.str();
}

string unhex(const string_view& hex) {
	if (hex.size() % 2 || hex.size() == 0) { return {}; };

	string result {};

	for (size_t i = 0; i < hex.size() - 1; i += 2) {
		string hex_char { string { hex[i] } + hex[i+1] };
		uint64_t char_val { 0 };

		std::istringstream stream { hex_char };
		stream >> std::hex >> char_val;

		result += string { static_cast<char>(char_val) };
	}

	return result;
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

		// close all files , with the exception of the pipes
		close_all_non_term_fd({ CHILD_READ_FD, CHILD_WRITE_FD, CHILD_WRITE_ERR, PARENT_READ_FD, PARENT_READ_ERR, PARENT_WRITE_FD});

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

std::vector<std::string> split_str(const std::string& s, char delimiter) {
	std::vector<std::string> tokens {};
	std::string token {};
	std::istringstream tokenStream(s);

	while (std::getline(tokenStream, token, delimiter)) {
		tokens.push_back(token);
	}

	return tokens;
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

string rand_str(std::size_t strSize) {
	string dic { "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" };
	std::random_device rd {};
	std::mt19937 gen { rd() };

	std::shuffle(dic.begin(), dic.end(), gen);

	if (strSize < dic.size()) {
		return dic.substr(0, strSize);
	} else {
		std::size_t req_modulus = static_cast<std::size_t>(strSize / dic.size());
		std::size_t req_reminder = strSize % dic.size();
		string random_str {};

		for (std::size_t i = 0; i < req_modulus; i++) {
			std::shuffle(dic.begin(), dic.end(), gen);
			random_str.append(dic);
		}

		random_str.append(dic.substr(0, req_reminder));

		return random_str;
	}
}

std::string get_checksum_from_hash(uint64_t hash) {
	uint32_t d32[2] = { 0 };
	memcpy(&d32, &hash, sizeof(hash));

	vector<char> s_buf(ProxySQL_Checksum_Value_LENGTH, 0);
	sprintf(&s_buf[0],"0x%0X%0X", d32[0], d32[1]);
	replace_checksum_zeros(&s_buf[0]);

	return string { &s_buf.front() };
}

/**
 * @brief Closes all open file descriptors except stdin (0), stdout (1), stderr (2), and a specified exclusion list
 *
 * This function is typically called after fork() in the child process before exec() to ensure that
 * the child process does not inherit unintended file descriptors from the parent. This is crucial
 * for security, resource management, and preventing deadlocks in daemonized processes.
 *
 * **Security Implications:**
 * - Prevents child processes from accessing sensitive file descriptors (database connections, sockets, log files)
 * - Prevents information leaks through unintended descriptor inheritance
 * - Required for secure privilege separation and sandboxing
 *
 * **Resource Management:**
 * - Prevents resource exhaustion by closing descriptors not needed by the child
 * - Allows the parent to close descriptors without affecting the child
 * - Ensures proper cleanup in daemon/service contexts
 *
 * **Deadlock Prevention:**
 * - In multi-threaded programs, if fork() is called while other threads hold locks or resources,
 *   the child process inherits a "frozen" state where only the forking thread exists but the
 *   locked resources remain held. Closing file descriptors prevents potential deadlocks
 *   when those descriptors are associated with pipes or sockets that may block on I/O.
 *
 * **Implementation Details:**
 *
 * The function uses three strategies, tried in order:
 *
 * 1. **Primary Method (Linux 5.9+, empty excludeFDs only):** close_range() syscall
 *    - Uses syscall(__NR_close_range, 3, ~0U, 0) to atomically close all fds >= 3
 *    - Runtime detection: first call checks if syscall is available
 *    - This method is O(1) and the most efficient
 *    - ONLY used when excludeFDs is empty (otherwise would close excluded fds)
 *
 * 2. **Secondary Method:** Iterate through /proc/self/fd
 *    - Uses opendir("/proc/self/fd") to get a directory stream of open file descriptors
 *    - Uses dirfd() to get the directory's own fd and skips closing it (prevents self-referential closure bug)
 *    - Reads each entry and uses atoi() to convert to fd (no heap allocation)
 *    - Closes all descriptors > 2 (stdin/stdout/stderr) that are not in the exclusion list
 *    - This method is O(n) where n is the number of open file descriptors
 *
 * 3. **Fallback Method:** Iterate through rlimit
 *    - If /proc/self/fd is not available (e.g., on non-Linux systems or chroot environments),
 *      falls back to getrlimit(RLIMIT_NOFILE)
 *    - Iterates from 3 to rlim_cur-1, attempting to close each descriptor
 *    - Ignores EBADF errors for descriptors that aren't actually open
 *    - This method is O(rlim_cur) which can be much slower if rlim_max is large (e.g., 1048576)
 *
 * **Important Design Considerations for fork() Safety:**
 *
 * 1. **Heap Allocation Avoidance:** This function avoids heap allocations in the /proc/self/fd path:
 *    - Uses atoi() instead of std::stol(std::string(...))
 *    - Uses simple loops instead of std::find() which may allocate
 *    - This is critical in multi-threaded programs after fork() where malloc locks may be held
 *
 * 2. **Self-Referential Directory FD Closure Prevention:**
 *    - The opendir() call creates a fd for the directory stream
 *    - We use dirfd() to get this fd and explicitly skip closing it
 *    - This prevents undefined behavior from closing the fd while iterating
 *
 * **Thread Safety Considerations:**
 * - This function IS safe to call in the child process between fork() and execve()
 * - By avoiding heap allocations (using atoi() and simple loops), it prevents deadlocks
 *   on malloc locks that may be held by other threads in the parent at fork time
 * - For optimal safety, call with an empty excludeFDs initializer list: close_all_non_term_fd({})
 *
 * **Parameters:**
 * @param excludeFDs A vector of file descriptor numbers to keep open (in addition to 0, 1, 2)
 *                   For example, if you have pipes for communication with the parent process,
 *                   pass those pipe fds in this vector to preserve them.
 *                   When non-empty, close_range() optimization cannot be used.
 *
 * **Example Usage:**
 * @code
 * // In forked child before exec - close everything except stdin/stdout/stderr
 * close_all_non_term_fd({});
 *
 * // Keep specific communication pipes open (works with /proc and rlimit methods)
 * close_all_non_term_fd({read_pipe, write_pipe});
 *
 * // After fork() in a daemon that keeps log files open
 * close_all_non_term_fd({log_fd, status_pipe_fd});
 * @endcode
 *
 * **Portability:**
 * - /proc/self/fd is Linux-specific. FreeBSD has /dev/fd, macOS has /dev/fd as well
 * - The fallback method using getrlimit() is more portable but less efficient
 * - close_range() is Linux 5.9+, with runtime detection for backward compatibility
 *
 * **See Also:**
 * - close_range(2) - Linux 5.9+ syscall for efficient bulk closing
 * - posix_spawn(3) - Alternative to fork+exec that handles fd closing atomically
 * - fdwalk() - Solaris/IllumOS function for similar purposes
 *
 * @param excludeFDs Vector of file descriptors to preserve (in addition to 0, 1, 2)
 * @return void
 */
void close_all_non_term_fd(const std::vector<int>& excludeFDs) {
	// Try close_range() syscall first (Linux 5.9+) - most efficient and safe
	// We use syscall directly with runtime detection to avoid hard dependency on kernel version
	// close_range() can ONLY be used when excludeFDs is empty, because it closes all fds >= 3
#ifdef __NR_close_range
	if (excludeFDs.empty()) {
		static int close_range_available = -1;  // -1 = unknown, 0 = not available, 1 = available
		if (close_range_available == 1) {
			// close_range is available, use it to close all fds >= 3
			syscall(__NR_close_range, 3, ~0U, 0);
			return;
		}
		if (close_range_available == -1) {
			// First call: check if close_range is available
			long ret = syscall(__NR_close_range, 3, ~0U, 0);
			if (ret == 0) {
				close_range_available = 1;
				return;
			}
			// Only cache as "not available" on ENOSYS
			// For other errors (EBADF, EINVAL, etc.), don't cache - might be transient
			if (errno == ENOSYS) {
				close_range_available = 0;
			}
		}
	}
#endif

	// Fallback: iterate through /proc/self/fd
	DIR *d;
	struct dirent *dir;
	d = opendir("/proc/self/fd");
	if (d) {
		int dir_fd = dirfd(d);  // Get the fd of the directory stream we're reading
		while ((dir = readdir(d)) != NULL) {
			if (strlen(dir->d_name) && dir->d_name[0] != '.') {
				// Use atoi() instead of std::stol(std::string(...)) to avoid heap allocation
				// This is critical in fork() context where malloc locks may be held
				int fd = atoi(dir->d_name);
				if (fd > 2) {
					// Skip the directory fd itself to avoid closing what we're reading from
					if (fd == dir_fd)
						continue;
					// Check if fd is in exclusion list
					bool exclude = false;
					for (size_t i = 0; i < excludeFDs.size(); i++) {
						if (excludeFDs[i] == fd) {
							exclude = true;
							break;
						}
					}
					if (!exclude) {
						close(fd);
					}
				}
			}
		}
		closedir(d);
	} else {
		// Final fallback: iterate through rlimit
		struct rlimit nlimit;
		int rc = getrlimit(RLIMIT_NOFILE, &nlimit);
		if (rc == 0) {
			// Use rlim_t for the loop variable to avoid infinite loop when rlim_cur > UINT_MAX
			// Cap at INT_MAX since file descriptors are signed ints
			for (rlim_t fd_rlim = 3; fd_rlim < nlimit.rlim_cur && fd_rlim <= INT_MAX; fd_rlim++) {
				int fd = (int)fd_rlim;
				// Check if fd is in exclusion list
				bool exclude = false;
				for (size_t i = 0; i < excludeFDs.size(); i++) {
					if (excludeFDs[i] == fd) {
						exclude = true;
						break;
					}
				}
				if (!exclude) {
					close(fd);
				}
			}
		}
	}
}

std::pair<int,const char*> get_dollar_quote_error(const char* version) {
	const char* ER_PARSE_MSG {
		"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server"
			" version for the right syntax to use near '$$' at line 1"
	};

	if (strcasecmp(version,"8.1.0") == 0) {
		return { ER_PARSE_ERROR, ER_PARSE_MSG };
	} else {
		if (strncasecmp(version, "8.1", 3) == 0) {
			// SQLSTATE: 42000
			return { ER_PARSE_ERROR, ER_PARSE_MSG };
		} else {
			// SQLSTATE: 42S22
			return { ER_BAD_FIELD_ERROR, "Unknown column '$$' in 'field list'" };
		}
	}
}

const nlohmann::json* get_nested_elem(const nlohmann::json& j, const vector<string>& p) {
	if (j.is_discarded()) { return nullptr; }
	const nlohmann::json* next_step = &j;

	for (const auto& e : p) {
		if (next_step->contains(e)) {
			next_step = &next_step->at(e);
		} else {
			next_step = nullptr;
			break;
		}
	}

	return next_step;
}

/**
 * @brief Gets the client address stored in 'client_addr' member as
 *   an string if available. If member 'client_addr' is NULL, returns an
 *   empty string.
 *
 * @return Either an string holding the string representation of internal
 *   member 'client_addr', or empty string if this member is NULL.
 */
std::string get_client_addr(struct sockaddr* client_addr) {
	char buf[INET6_ADDRSTRLEN];
	std::string str_client_addr {};

	if (client_addr == NULL) {
		return str_client_addr;
	}

	switch (client_addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)client_addr;
			inet_ntop(client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
			str_client_addr = std::string { buf };
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)client_addr;
			inet_ntop(client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
			str_client_addr = std::string { buf };
			break;
		}
		default:
			str_client_addr = std::string { "localhost" };
			break;
	}

	return str_client_addr;
}
