#ifndef CLUSTER_REPLICA_HELPERS_H
#define CLUSTER_REPLICA_HELPERS_H

#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include "mysql.h"

namespace cluster_replica {

struct process_result {
	int status = 0;
	int error = 0;

	int exit_code() const {
		return error == 0 && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	}
};

// The calling thread alone owns waitpid. Other threads may observe the PID
// and signal it, but must not reap it.
inline process_result run(const std::string& command, std::atomic<pid_t>& child_pid) {
	process_result result;
	// Replace the shell so the published PID is the replica itself.
	const std::string shell_command = "exec " + command;
	pid_t pid = fork();
	if (pid == 0) {
		execl("/bin/sh", "sh", "-c", shell_command.c_str(), nullptr);
		_exit(127);
	}
	if (pid == -1) {
		result.error = errno;
		return result;
	}
	child_pid.store(pid);
	pid_t waited;
	do {
		waited = waitpid(pid, &result.status, 0);
	} while (waited == -1 && errno == EINTR);
	if (waited == -1) result.error = errno;
	child_pid.store(0);
	return result;
}

// Return the PID signalled, or zero if the launcher has already reaped it.
// On kill failure return -1, leaving errno available to the caller.
inline pid_t stop(std::atomic<pid_t>& child_pid, std::chrono::milliseconds grace) {
	const auto deadline = std::chrono::steady_clock::now() + grace;
	while (child_pid.load() > 0 && std::chrono::steady_clock::now() < deadline) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	pid_t pid = child_pid.load();
	if (pid <= 0) return 0;
	return kill(pid, SIGKILL) == 0 ? pid : -1;
}

template<typename Report>
int read_output(const std::string& path, Report report) {
	FILE* output = fopen(path.c_str(), "r");
	if (!output) return errno;
	char line[4096];
	while (fgets(line, sizeof(line), output)) {
		if (char* newline = strpbrk(line, "\r\n")) *newline = '\0';
		report(line);
	}
	fclose(output);
	return 0;
}

template<typename Report>
MYSQL* wait_for_ready(const std::string& host, const std::string& user, const std::string& pass,
	int port, unsigned timeout, Report report) {
	MYSQL* admin = mysql_init(nullptr);
	for (unsigned waited = 0; ; ++waited) {
		if (mysql_real_connect(admin, host.c_str(), user.c_str(), pass.c_str(),
			nullptr, port, nullptr, 0)) {
			return admin;
		}
		if (waited >= timeout) {
			report("Replica readiness failed at " + host + ":" + std::to_string(port) + ": " +
				std::to_string(mysql_errno(admin)) + " - " + mysql_error(admin));
			mysql_close(admin);
			return nullptr;
		}
		mysql_close(admin);
		admin = mysql_init(nullptr);
		sleep(1);
	}
}

} // namespace cluster_replica
#endif
