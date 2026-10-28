#ifndef PROXYSQL_PRIVATE_DAEMON_PROBE_H
#define PROXYSQL_PRIVATE_DAEMON_PROBE_H

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

/** @brief Runs a backend-free daemon probe beside the restored test executable. */
inline bool run_private_daemon_probe(const char* executable, const char* binary_override, const char* script_name) {
	std::error_code error;
	auto root = std::filesystem::canonical(executable, error);
	if (error) return false;
	for (int i = 0; i < 5; ++i) root = root.parent_path();
	const std::string script = (root / "test/infra/control" / script_name).string();
	const std::string binary = binary_override ? binary_override : (root / "src/proxysql").string();
	const pid_t child = fork();
	if (child == 0) {
		// Match the documented lifecycle probe mode. Memory safety remains
		// enabled; leak ownership has its own startup_tls_ownership_unit test.
		std::string options = getenv("ASAN_OPTIONS") ? getenv("ASAN_OPTIONS") : "";
		options += ":detect_leaks=0";
		setenv("ASAN_OPTIONS", options.c_str(), 1);
		execlp("python3", "python3", script.c_str(), binary.c_str(), nullptr);
		_exit(127);
	}
	int status = 0;
	pid_t waited = -1;
	if (child > 0) {
		do { waited = waitpid(child, &status, 0); } while (waited == -1 && errno == EINTR);
	}
	return child > 0 && waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif
