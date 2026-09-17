/**
 * A failed cache-entry allocation must reject admission, release the
 * transferred value, and preserve any entry already stored under the key.
 * Allocator interception is confined to the included production source.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Query_Cache.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static bool fail_entry_allocation = false;
static void* transferred_value = nullptr;
static unsigned int transferred_value_frees = 0;

static void* cache_malloc(size_t size) {
	if (fail_entry_allocation) {
		fail_entry_allocation = false;
		return nullptr;
	}
	return malloc(size);
}

static void cache_free(void* ptr) {
	if (ptr == transferred_value) ++transferred_value_frees;
	free(ptr);
}

// Headers are already loaded, so only this source's allocation calls change.
#define malloc cache_malloc
#define free cache_free
#include "../../../../lib/PgSQL_Query_Cache.cpp"
#undef free
#undef malloc

static const unsigned char key[] = "allocation-failure";

static unsigned char* value_copy(const char* value) {
	return reinterpret_cast<unsigned char*>(strdup(value));
}

static int failed_admission(bool replace_existing) {
	PgSQL_Query_Cache cache;
	if (replace_existing && !cache.set(1, key, sizeof(key), value_copy("old"), 4,
		1000, 1000, 11000, 7, 9)) return 1;

	transferred_value = value_copy("new");
	transferred_value_frees = 0;
	fail_entry_allocation = true;
	const bool admitted = cache.set(1, key, sizeof(key),
		static_cast<unsigned char*>(transferred_value), 4, 1000, 1000, 11000, 2, 3);
	if (admitted) return 2;
	if (transferred_value_frees != 1) return 3;
	transferred_value = nullptr;

	auto entry = cache.get(1, key, sizeof(key), 1000, 10000);
	if (!replace_existing) return entry ? 4 : 0;
	return entry && entry->length == 4 && memcmp(entry->value, "old", 4) == 0 &&
		entry->rows_sent == 7 && entry->affected_rows == 9 ? 0 : 5;
}

static void test_failed_admission(bool replace_existing) {
	// A regression may dereference NULL. Isolate it so TAP reports the failure
	// and the other admission case still runs, without leaving a core file.
	fflush(nullptr);
	const pid_t child = fork();
	if (child == 0) {
		const struct rlimit no_core = {0, 0};
		setrlimit(RLIMIT_CORE, &no_core);
		_exit(failed_admission(replace_existing));
	}
	int status = 0;
	pid_t waited = -1;
	if (child > 0) {
		do {
			waited = waitpid(child, &status, 0);
		} while (waited == -1 && errno == EINTR);
	}
	const bool passed = waited == child && child > 0 &&
		WIFEXITED(status) && WEXITSTATUS(status) == 0;
	ok(passed, "entry allocation failure releases value and %s",
		replace_existing ? "preserves existing cached result" : "rejects new cached result");
	if (!passed) diag("child=%ld wait=%ld status=%d (exit 2: admitted, 3: ownership, 4/5: cache contents)",
		static_cast<long>(child), static_cast<long>(waited), status);
}

int main() {
	plan(4);
	if (test_init_minimal() != 0) return EXIT_FAILURE;
	test_failed_admission(false);
	test_failed_admission(true);
	{
		PgSQL_Query_Cache cache;
		ok(cache.set(1, key, sizeof(key), value_copy("new"), 4,
			1000, 1000, 11000, 2, 3), "successful allocation admits cached result");
		auto entry = cache.get(1, key, sizeof(key), 1000, 10000);
		ok(entry && entry->length == 4 && memcmp(entry->value, "new", 4) == 0 &&
			entry->rows_sent == 2 && entry->affected_rows == 3,
			"successful admission preserves result bytes and row metadata");
	}
	test_cleanup_minimal();
	return exit_status();
}
