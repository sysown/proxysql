#include "tap.h"
#include "../cluster_replica_helpers.h"

#include <fstream>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>

using namespace std::chrono;

static std::string quote(const std::string& value) {
	std::string quoted = "'";
	for (char c : value) quoted += c == '\'' ? "'\\''" : std::string(1, c);
	return quoted + "'";
}

static std::vector<std::string> output_lines(const std::string& path) {
	std::vector<std::string> lines;
	cluster_replica::read_output(path, [&](const char* line) { lines.emplace_back(line); });
	return lines;
}

// Reserve an ephemeral port. Without listen(), readiness must fail even if
// other unit tests are creating listeners at the same time.
static int reserve_port(unsigned& port) {
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in address {};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (fd == -1 || bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
		BAIL_OUT("Unable to reserve readiness port: %s", strerror(errno));
	}
	socklen_t size = sizeof(address);
	if (getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) != 0) {
		BAIL_OUT("Unable to inspect readiness port: %s", strerror(errno));
	}
	port = ntohs(address.sin_port);
	return fd;
}

int main() {
	plan(25);
	char dirname[] = "cluster-replica-unit-'XXXXXX";
	if (!mkdtemp(dirname)) BAIL_OUT("Unable to create replica test directory: %s", strerror(errno));
	const std::string output = std::string(dirname) + "/output.txt";
	const std::string missing = std::string(dirname) + "/missing.txt";
	std::atomic<pid_t> pid { 0 };

	auto result = cluster_replica::run("/bin/sh -c 'printf \"stdout\\n\"; printf \"stderr\\r\\n\" >&2' > " +
		quote(output) + " 2>&1", pid);
	ok(result.error == 0 && result.exit_code() == 0, "Normal replica exit is successful");
	ok(pid.load() == 0, "Launcher clears PID after normal exit");
	ok(output_lines(output) == std::vector<std::string>({"stdout", "stderr"}),
		"Captured stdout and stderr retain their contents without line endings");
	result = cluster_replica::run("/bin/sh -c 'exit 7'", pid);
	ok(result.exit_code() == 7, "Nonzero replica exit is preserved for the caller");
	result = cluster_replica::run(quote(std::string(dirname) + "/no-such-replica") + " > " +
		quote(output) + " 2>&1", pid);
	ok(result.exit_code() == 127, "Missing replica executable reports launch failure");
	ok(!output_lines(output).empty(), "Failed launch retains the shell diagnostic");

	const std::string full_line(4095, 'x');
	{ std::ofstream boundary(output); boundary << full_line; }
	ok(output_lines(output) == std::vector<std::string>({full_line}),
		"A full diagnostic buffer without a newline is preserved");

	bool reported = false;
	int error = cluster_replica::read_output(missing, [&](const char*) { reported = true; });
	ok(error == ENOENT, "Missing replica output preserves the original open error");
	ok(!reported, "Missing output never produces fabricated diagnostic lines");
	{ std::ofstream empty(output); }
	ok(cluster_replica::read_output(output, [&](const char*) { reported = true; }) == 0 && !reported,
		"Empty replica output is read successfully without fabricated lines");

	std::thread launcher([&result, &output, &pid] {
		result = cluster_replica::run("/bin/sh -c 'printf \"%s\\n\" $$; printf \"replica startup diagnostic\\n\" >&2; exec sleep 60' > " + quote(output) + " 2>&1", pid);
	});
	pid_t replica_pid = 0;
	const auto deadline = steady_clock::now() + seconds(5);
	while (!replica_pid && steady_clock::now() < deadline) {
		const auto captured = output_lines(output);
		if (captured.size() == 2 && captured[1] == "replica startup diagnostic") {
			replica_pid = static_cast<pid_t>(strtol(captured[0].c_str(), nullptr, 10));
		}
		std::this_thread::sleep_for(milliseconds(10));
	}
	ok(replica_pid > 0, "Real replica publishes its PID after exec");
	const pid_t tracked_pid = pid.load();
	ok(replica_pid > 0 && replica_pid == tracked_pid, "Tracked PID belongs to the replica, not a waiting shell");
	pid_t stopped = cluster_replica::stop(pid, milliseconds(20));
	ok(stopped > 0 && stopped == tracked_pid, "Forced cleanup signals only the owned process");
	const auto reap_deadline = steady_clock::now() + seconds(5);
	while (pid.load() > 0 && steady_clock::now() < reap_deadline) {
		std::this_thread::sleep_for(milliseconds(10));
	}
	const bool reaped = pid.load() == 0;
	// Keep a broken cleanup helper from hanging the test's join forever.
	if (!reaped && tracked_pid > 0) kill(tracked_pid, SIGKILL);
	launcher.join();
	ok(reaped, "Forced cleanup lets the owning launcher finish within the deadline");
	ok(result.error == 0 && WIFSIGNALED(result.status) && WTERMSIG(result.status) == SIGKILL,
		"Launcher preserves the forced termination signal");
	ok(result.exit_code() == -1, "Signal termination cannot be mistaken for a successful exit");
	ok(pid.load() == 0, "Launcher clears the PID after forced termination");
	ok(tracked_pid > 0 && waitpid(tracked_pid, nullptr, WNOHANG) == -1 && errno == ECHILD,
		"Launcher reaps its child without a second waitpid owner");
	bool gone = replica_pid > 0 && kill(replica_pid, 0) == -1 && errno == ESRCH;
	ok(gone, "Forced cleanup leaves no replica running");
	// This also cleans up the historical orphan if exec is removed to verify
	// the regression test: only the PID reported by this test child is killed.
	if (!gone && replica_pid > 0) kill(replica_pid, SIGKILL);
	ok(cluster_replica::stop(pid, milliseconds(0)) == 0, "Cleanup after reaping does not signal another process");
	const auto lines = output_lines(output);
	ok(lines.size() == 2 && lines[1] == "replica startup diagnostic", "Forced cleanup retains child diagnostics");

	unsigned port;
	int reserved = reserve_port(port);
	MYSQL* probe = mysql_init(nullptr);
	mysql_real_connect(probe, "127.0.0.1", "replica", "", nullptr, port, nullptr, 0);
	const unsigned expected_errno = mysql_errno(probe);
	const std::string expected_error = mysql_error(probe);
	mysql_close(probe);
	std::vector<std::string> diagnostics;
	auto report = [&diagnostics](const std::string& message) { diagnostics.push_back(message); };
	MYSQL* admin = cluster_replica::wait_for_ready("127.0.0.1", "replica", "", port, 0, report);
	ok(admin == nullptr && expected_errno != 0, "Unlistened local port fails readiness without retries");
	ok(diagnostics.size() == 1 && diagnostics[0] == "Replica readiness failed at 127.0.0.1:" +
		std::to_string(port) + ": " + std::to_string(expected_errno) + " - " + expected_error,
		"Readiness preserves the actual endpoint, error code and message before closing its handle");
	diagnostics.clear();
	const auto started = steady_clock::now();
	admin = cluster_replica::wait_for_ready("127.0.0.1", "replica", "", port, 1, report);
	ok(admin == nullptr && steady_clock::now() - started >= seconds(1), "Readiness retries until the configured timeout");
	ok(diagnostics.size() == 1, "Readiness reports the final failure once after retrying");
	close(reserved);
	unlink(output.c_str());
	rmdir(dirname);
	return exit_status();
}
