#include "tap.h"

#include <cerrno>
#include <filesystem>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char** argv) {
	plan(1);
	// Resolve assets beside the restored executable rather than embedding the
	// producer's build path, which can differ from the CI consumer's checkout.
	auto repo = std::filesystem::canonical(argv[0]);
	for (int i = 0; i < 5; ++i) repo = repo.parent_path();
	const std::string script = (repo / "test/infra/control/test_startup_tls_ownership.py").string();
	const std::string binary = argc > 1 ? argv[1] : (repo / "src/proxysql").string();
	const pid_t child = fork();
	if (child == 0) {
		execlp("python3", "python3", script.c_str(), binary.c_str(), nullptr);
		_exit(127);
	}
	int status = 0;
	pid_t waited = -1;
	if (child > 0) {
		do { waited = waitpid(child, &status, 0); } while (waited == -1 && errno == EINTR);
	}
	if (waited == child && child > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 77) {
		skip(1, "startup TLS ownership requires an ASan DEBUG daemon");
	} else {
		ok(waited == child && child > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0,
			"the real daemon releases its displaced startup TLS context without sanitizer errors");
	}
	return exit_status();
}
