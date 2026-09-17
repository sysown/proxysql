#ifndef MYSQL_THREAD_TEST_H
#define MYSQL_THREAD_TEST_H

#ifdef PROXYSQL40

#if defined(__GNUC__)
#define MYSQL_THREAD_TEST_HIDDEN __attribute__((visibility("hidden")))
#else
#define MYSQL_THREAD_TEST_HIDDEN
#endif

namespace mysql_thread_test {

using listener_add_hook_t = bool (*)(void*, const char*);
using commit_reject_hook_t = bool (*)(void*);

class MYSQL_THREAD_TEST_HIDDEN scoped_interface_hooks {
public:
	scoped_interface_hooks(listener_add_hook_t listener_hook,
		commit_reject_hook_t commit_hook, void* opaque);
	~scoped_interface_hooks();
	scoped_interface_hooks(const scoped_interface_hooks&) = delete;
	scoped_interface_hooks& operator=(const scoped_interface_hooks&) = delete;
};

} // namespace mysql_thread_test

#undef MYSQL_THREAD_TEST_HIDDEN

#endif /* PROXYSQL40 */
#endif /* MYSQL_THREAD_TEST_H */
