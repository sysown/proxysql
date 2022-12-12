/**
 * @file test_wexecvp_syscall_failures.cpp
 * @brief Makes use of GCC wrap option for testing 'wexecvp' over different syscall failures.
 * @date 2022-12-08
 */

#include <string>
#include <utility>
#include <vector>

#include <poll.h>
#include <unistd.h>

#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

using std::string;
using std::vector;
using std::pair;

bool g_read_use_real = false;
int g_read_ret = -1;
int g_read_errno = EINVAL;

extern "C" ssize_t __real_read(int __fd, void *__buf, size_t __nbytes);
extern "C" ssize_t __wrap_read(int fd, void* buf, size_t nbytes);

ssize_t __wrap_read(int fd, void* buf, size_t nbytes) {
	if (g_read_use_real) {
		return __real_read(fd, buf, nbytes);
	}

	errno = g_read_errno;
	return g_read_ret;
}

bool g_pipe_use_real = true;
int g_pipe_ret = -1;
int g_pipe_errno = EINVAL;

extern "C" int __real_pipe(int __pipedes[2]);
extern "C" int __wrap_pipe(int __pipedes[2]);

int __wrap_pipe(int __pipedes[2]) {
	if (g_pipe_use_real) {
		return __real_pipe(__pipedes);
	}

	errno = g_pipe_errno;
	return g_pipe_ret;
}

bool g_fcntl_use_real = false;
int g_fcntl_ret = -1;
int g_fcntl_errno = EINVAL;

extern "C" int __real_fcntl(int __fd, int __cmd, ...);
extern "C" int __wrap_fcntl(int __fd, int __cmd, ...);

int __wrap_fcntl(int __fd, int __cmd, ...) {
	if (g_fcntl_use_real) {
		va_list args;
		va_start(args, __cmd);
		int res =  __real_fcntl(__fd, __cmd, args);
		va_end(args);

		return res;
	}

	usleep(500 * 1000);

	errno = g_fcntl_errno;
	return g_fcntl_ret;
}

bool g_poll_use_real = false;
int g_poll_ret = -1;
int g_poll_errno = EINVAL;

extern "C" int __real_poll(struct pollfd *__fds, nfds_t __nfds, int __timeout);
extern "C" int __wrap_poll(struct pollfd *__fds, nfds_t __nfds, int __timeout);

int __wrap_poll(struct pollfd *__fds, nfds_t __nfds, int __timeout) {
	if (g_poll_use_real) {
		return __real_poll(__fds, __nfds, __timeout);
	}

	usleep(500 * 1000);

	errno = g_poll_errno;
	return g_poll_ret;
}

using errno_t = int;
using test_pl_t = pair<bool&,errno_t>;

void enable_reals(const vector<test_pl_t>& test_pls) {
	for (const test_pl_t& test_pl : test_pls) {
		test_pl.first = true;
	}
}

int main(int argc, char** argv) {
	const char* workdir = getenv("TAP_WORKDIR");

	if (!workdir) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const string base_path { join_path(workdir, "reg_test_3223_scripts") };
	const auto check_read_failure =
		[] (const string& base_path, const test_pl_t& pl, const string& std_stream) -> void {
			const string exe_path { join_path(base_path, "write_to_std_streams.py") };

			string o_stdout {};
			string o_stderr {};

			to_opts_t wexecvp_opts {};
			wexecvp_opts.timeout_us = 1*1000*1000;
			wexecvp_opts.waitpid_delay_us = 100*1000;
			wexecvp_opts.sigkill_to_us = 500*1000;

			const string sigterm_file_flag { exe_path + "-RECV_SIGTERM" };
			diag("Removing previous SIGTERM flag file - '%s'", sigterm_file_flag.c_str());
			remove(sigterm_file_flag.c_str());

			diag("Launching executable '%s' with params '%s'", exe_path.c_str(), std_stream.c_str());
			int err = wexecvp(exe_path, { std_stream.c_str() }, wexecvp_opts, o_stdout, o_stderr);

			int exp_err = 0;
			int exp_errno = 0;
			int _errno = errno;

			// From function spec itself, 'read' failure implies '-6'
			if ((std_stream == "stdout" || std_stream == "stderr" ) || pl.second != -5) {
				exp_err = pl.second;
				exp_errno = EINVAL;
			} else {
				// If no output is performed by the target script, no 'read' should be call by ProxySQL. No read
				// calls should imply no failure.
				exp_err = ETIME;
				exp_errno = 0;
				_errno = 0;
			}

			ok(
				exp_err == err && _errno == exp_errno,
				"'wexecvp' should return exp err - { exp_err: %d, act_err:%d }, { exp_errno: %d, act_errno: %d }",
				exp_err, err, _errno, exp_errno
			);

			if (pl.second <= -3) {
				int f_exists = access(sigterm_file_flag.c_str(), F_OK);
				ok(f_exists == 0, "Script '%s' should receive a 'SIGTERM' signal", exe_path.c_str());
			}
		};

	const vector<test_pl_t> test_pls {
		{ g_pipe_use_real, -1 },
		{ g_fcntl_use_real, -3 },
		{ g_poll_use_real, -4 },
		{ g_read_use_real, -5 }
	};

	uint32_t planned_tests = 0;
	for (const test_pl_t& pl : test_pls) {
		if (pl.second <= -3) {
			planned_tests += 3 * 2;
		} else {
			planned_tests += 3;
		}
	}

	plan(planned_tests);

	for (const test_pl_t& pl : test_pls) {
		enable_reals(test_pls);

		pl.first = false;

		check_read_failure(base_path, pl, "stdout");
		check_read_failure(base_path, pl, "stderr");
		check_read_failure(base_path, pl, "");
	}

	return exit_status();
}
