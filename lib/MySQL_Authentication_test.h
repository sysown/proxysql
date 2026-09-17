#ifndef MYSQL_AUTHENTICATION_TEST_H
#define MYSQL_AUTHENTICATION_TEST_H

// Private hidden fault/interleave seam for unit tests. It is not installed and
// is unavailable to dynamically loaded plugins.
#if defined(__GNUC__)
#define MYSQL_AUTH_TEST_HIDDEN __attribute__((visibility("hidden")))
#else
#define MYSQL_AUTH_TEST_HIDDEN
#endif

namespace mysql_authentication_test {

using atomic_replace_hook_t = void (*)(void*);

class MYSQL_AUTH_TEST_HIDDEN scoped_atomic_replace_hook {
public:
	scoped_atomic_replace_hook(atomic_replace_hook_t hook, void* opaque);
	~scoped_atomic_replace_hook();

	scoped_atomic_replace_hook(const scoped_atomic_replace_hook&) = delete;
	scoped_atomic_replace_hook& operator=(const scoped_atomic_replace_hook&) = delete;
};

} // namespace mysql_authentication_test

#endif /* MYSQL_AUTHENTICATION_TEST_H */
