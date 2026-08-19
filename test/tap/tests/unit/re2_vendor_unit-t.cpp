#include "tap.h"
#include "re2/re2.h"
#include "absl/base/config.h"

int main() {
	plan(2);
	ok(RE2::PartialMatch("ProxySQL", "Proxy.*SQL"),
		"vendored RE2 performs a partial match");
	ok(ABSL_LTS_RELEASE_VERSION == 20260107,
		"vendored Abseil is pinned to 20260107.0");
	return exit_status();
}
