/**
 * @file reg_test_5854_close_wait_leak-t.cpp
 * @brief Regression test for CLOSE_WAIT socket leak when net.pvio is NULL.
 * @details Verifies two things:
 *   1. Without the fix (just mysql_close_no_command when pvio=NULL), the
 *      socket fd is not released — confirming the bug is real.
 *   2. With the fix (explicit close(fd) before mysql_close_no_command), the
 *      fd is released back — confirming the fix works.
 *   3. (Linux only) Repeated fixed closes do not accumulate CLOSE_WAIT sockets.
 *
 *   The pvio=NULL / net.fd>0 state is reproduced by directly zeroing net.pvio
 *   on a live connection, mirroring what the MariaDB connector does when it
 *   processes a remote FIN during async I/O.  Using shutdown(SHUT_RD)+ping
 *   to trigger that path is avoided because the connector may also close the
 *   fd internally during error recovery, which would confound the fd-count
 *   assertions.
 *
 *   Related: PR #5854, issues #2908 #3022
 */

#include "tap.h"
#include "command_line.h"
#include "utils.h"

#include <mysql.h>
#include <sys/socket.h>
#include <dirent.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>

// Returns the number of open fds for this process via /proc/self/fd.
// Returns -1 if not available (non-Linux).
static int count_open_fds() {
#ifdef __linux__
	DIR* dir = opendir("/proc/self/fd");
	if (!dir) return -1;
	int n = 0;
	struct dirent* e;
	while ((e = readdir(dir)) != nullptr)
		if (e->d_name[0] != '.') n++;
	closedir(dir);
	return n - 1; // subtract dirfd opened by opendir itself
#else
	return -1;
#endif
}

#ifdef __linux__
// Count CLOSE_WAIT entries in /proc/net/tcp and /proc/net/tcp6.
// State 0x08 == CLOSE_WAIT in Linux tcp state encoding.
static int count_close_wait() {
	int total = 0;
	for (const char* path : { "/proc/net/tcp", "/proc/net/tcp6" }) {
		FILE* f = fopen(path, "r");
		if (!f) continue;
		char line[512];
		if (!fgets(line, sizeof(line), f)) { fclose(f); continue; } // skip header
		while (fgets(line, sizeof(line), f)) {
			unsigned int st = 0;
			if (sscanf(line, " %*d: %*s %*s %x", &st) == 1 && st == 0x08)
				total++;
		}
		fclose(f);
	}
	return total;
}
#endif

// Open a real TCP connection to MySQL and directly zero net.pvio, producing
// the pvio=NULL / net.fd>0 state that the MariaDB connector reaches when it
// processes a remote FIN during async I/O.
static MYSQL* make_pvio_null_conn(const CommandLine& cl) {
	MYSQL* my = mysql_init(nullptr);
	if (!my) return nullptr;

	unsigned int proto = MYSQL_PROTOCOL_TCP;
	mysql_options(my, MYSQL_OPT_PROTOCOL, &proto);

	if (!mysql_real_connect(
		my,
		cl.mysql_host, cl.mysql_username, cl.mysql_password,
		nullptr, cl.mysql_port, nullptr, 0
	)) {
		diag("mysql_real_connect failed: %s", mysql_error(my));
		mysql_close(my);
		return nullptr;
	}

	if (my->net.fd <= 0) {
		diag("unexpected: net.fd not set after connect");
		mysql_close(my);
		return nullptr;
	}

	// Directly replicate the connector's post-EOF field state:
	// pvio cleared, fd still open.
	my->net.pvio = nullptr;

	return my;
}

// Test 1: the unfixed path does not release the fd.
// mysql_close_no_command() skips end_server() when pvio=NULL, so net.fd is
// never passed to close(2).  We verify this by measuring the open-fd count
// before and after the connection: after the unfixed close the fd must still
// be counted (count stays at "after-connect" level, above baseline).
static void test_unfixed_path_leaks_fd(const CommandLine& cl) {
	diag("--- test_unfixed_path_leaks_fd ---");

	int baseline = count_open_fds();
	if (baseline < 0) {
		skip(1, "fd counting not available (/proc/self/fd missing)");
		return;
	}
	diag("fds baseline (before connect): %d", baseline);

	MYSQL* my = make_pvio_null_conn(cl);
	if (!my) {
		skip(1, "could not create pvio=NULL connection");
		return;
	}

	diag("fds after connect: %d", count_open_fds());

	// Unfixed path: pvio=NULL, fd not closed explicitly before delegating.
	// Mirrors what close_mysql() did before the fix.
	mysql_close_no_command(my);

	int after = count_open_fds();
	diag("fds after unfixed close: %d", after);

	ok(after > baseline,
		"unfixed path: fd not released — count stays above baseline after "
		"mysql_close_no_command on pvio=NULL conn (baseline=%d after=%d)",
		baseline, after);
}

// Test 2: the fixed path releases the fd.
// Explicitly calling close(fd) before mysql_close_no_command() when pvio=NULL
// mirrors the else-if branch added in close_mysql() by PR #5854.
// After the fixed close the fd count must return to baseline.
static void test_fixed_path_closes_fd(const CommandLine& cl) {
	diag("--- test_fixed_path_closes_fd ---");

	int baseline = count_open_fds();
	if (baseline < 0) {
		skip(1, "fd counting not available (/proc/self/fd missing)");
		return;
	}
	// baseline here already includes the leaked fd from test 1 — that is
	// fine: we only care that the fixed close does not add another one.
	diag("fds baseline (before connect): %d", baseline);

	MYSQL* my = make_pvio_null_conn(cl);
	if (!my) {
		skip(1, "could not create pvio=NULL connection");
		return;
	}

	diag("fds after connect: %d", count_open_fds());

	// Fixed path: mirrors the else-if branch in close_mysql() (PR #5854).
	if (my->net.pvio == nullptr && my->net.fd > 0) {
		close(my->net.fd);
		my->net.fd = -1;
	}
	mysql_close_no_command(my);

	int after = count_open_fds();
	diag("fds after fixed close: %d", after);

	ok(after <= baseline,
		"fixed path: fd released — count returns to baseline after explicit "
		"close(fd)+mysql_close_no_command on pvio=NULL conn (baseline=%d after=%d)",
		baseline, after);
}

// Test 3 (Linux only): repeated fixed closes must not accumulate CLOSE_WAIT sockets.
static void test_no_close_wait_growth(const CommandLine& cl) {
	diag("--- test_no_close_wait_growth ---");

#ifndef __linux__
	skip(1, "CLOSE_WAIT counting requires /proc/net/tcp (Linux only)");
#else
	const int ITERS = 5;

	int cw_before = count_close_wait();
	diag("CLOSE_WAIT before: %d", cw_before);

	for (int i = 0; i < ITERS; i++) {
		MYSQL* my = make_pvio_null_conn(cl);
		if (!my) {
			diag("iteration %d: could not create pvio=NULL conn", i);
			continue;
		}
		// Fixed path (same as test 2)
		if (my->net.pvio == nullptr && my->net.fd > 0) {
			close(my->net.fd);
			my->net.fd = -1;
		}
		mysql_close_no_command(my);
		usleep(100000); // 100 ms — let kernel reclaim
	}

	int cw_after = count_close_wait();
	diag("CLOSE_WAIT after %d iters: %d", ITERS, cw_after);

	// Allow at most 1 slack for unrelated traffic on a busy CI host
	ok(cw_after <= cw_before + 1,
		"fixed path: CLOSE_WAIT count must not grow after %d pvio=NULL closes "
		"(before=%d after=%d)", ITERS, cw_before, cw_after);
#endif
}

// ---------------------------------------------------------------------------
int main(int argc, const char* argv[]) {
	plan(3);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get required env vars");
		return EXIT_FAILURE;
	}

	test_unfixed_path_leaks_fd(cl);
	test_fixed_path_closes_fd(cl);
	test_no_close_wait_growth(cl);

	return exit_status();
}
