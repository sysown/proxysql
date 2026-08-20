#ifndef PROXYSQL_PLUGIN_CONFIG_TEST_H
#define PROXYSQL_PLUGIN_CONFIG_TEST_H

#ifdef PROXYSQL40

#if defined(__GNUC__)
#define PROXYSQL_PLUGIN_CONFIG_TEST_HIDDEN __attribute__((visibility("hidden")))
#else
#define PROXYSQL_PLUGIN_CONFIG_TEST_HIDDEN
#endif

namespace proxysql_plugin_config_test {

enum class sql_action {
	normal,
	fail,
};

using sql_hook_t = sql_action (*)(void*, const char*);
using before_copy_hook_t = void (*)(void*);

class PROXYSQL_PLUGIN_CONFIG_TEST_HIDDEN scoped_hooks {
public:
	scoped_hooks(sql_hook_t sql_hook, before_copy_hook_t before_copy_hook, void* opaque);
	~scoped_hooks();
	scoped_hooks(const scoped_hooks&) = delete;
	scoped_hooks& operator=(const scoped_hooks&) = delete;
};

} // namespace proxysql_plugin_config_test

#undef PROXYSQL_PLUGIN_CONFIG_TEST_HIDDEN

#endif /* PROXYSQL40 */
#endif /* PROXYSQL_PLUGIN_CONFIG_TEST_H */
