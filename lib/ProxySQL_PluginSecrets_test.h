#ifndef PROXYSQL_PLUGIN_SECRETS_TEST_H
#define PROXYSQL_PLUGIN_SECRETS_TEST_H

#include <cstddef>
#include <sys/types.h>

struct sqlite3_stmt;

// This private header exists only to drive fault injection in unit tests.
// Its hidden symbols are unavailable to dynamically loaded plugins.
#if defined(__GNUC__)
#define PROXYSQL_SECRETS_TEST_HIDDEN __attribute__((visibility("hidden")))
#else
#define PROXYSQL_SECRETS_TEST_HIDDEN
#endif

namespace proxysql_plugin_secrets_test {

using cleanse_observer_t = void (*)(void*, size_t);
using key_open_observer_t = void (*)(int flags);
using key_io_hook_t = ssize_t (*)(bool is_write, int fd, void* buffer,
	size_t length, int* error);
using sqlite_step_hook_t = int (*)(sqlite3_stmt* stmt);

struct hooks_t {
	cleanse_observer_t cleanse_observer { nullptr };
	key_open_observer_t key_open_observer { nullptr };
	key_io_hook_t key_io_hook { nullptr };
	sqlite_step_hook_t sqlite_step_hook { nullptr };
};

class PROXYSQL_SECRETS_TEST_HIDDEN scoped_hooks_t {
public:
	explicit scoped_hooks_t(hooks_t hooks);
	~scoped_hooks_t();

	scoped_hooks_t(const scoped_hooks_t&) = delete;
	scoped_hooks_t& operator=(const scoped_hooks_t&) = delete;
};

} // namespace proxysql_plugin_secrets_test

#endif /* PROXYSQL_PLUGIN_SECRETS_TEST_H */
