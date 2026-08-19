#ifndef PROXYSQL_PLUGIN_SECRETS_H
#define PROXYSQL_PLUGIN_SECRETS_H

#ifdef PROXYSQL40

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class SQLite3DB;

// Result values intentionally reveal only operation state.  They never carry
// secret material and are safe to surface in a plugin's own error handling.
enum class ProxySQL_PluginSecretResult : uint8_t {
	ok = 0,
	not_found,
	invalid_argument,
	not_available,
	key_error,
	storage_error,
	authentication_failed,
};

// Core-owned configdb definition.  Admin registers this through its normal
// table-definition path before live plugin services are exposed.
const char* proxysql_plugin_secrets_table_definition();

class ProxySQL_PluginSecrets {
public:
	using cleanse_observer_t = void (*)(void*, size_t);
	using key_open_observer_t = void (*)(int flags);

	ProxySQL_PluginSecrets(SQLite3DB* configdb, std::string datadir);

	ProxySQL_PluginSecretResult put(const char* owner, const char* name,
		const uint8_t* bytes, size_t length);
	ProxySQL_PluginSecretResult get(const char* owner, const char* name,
		std::vector<uint8_t>& plaintext);
	ProxySQL_PluginSecretResult erase(const char* owner, const char* name);

	// Test seams observe cleansing and the first-create open flags without
	// altering production crypto or filesystem behaviour.
	static void set_cleanse_observer(cleanse_observer_t observer);
	static void set_key_open_observer(key_open_observer_t observer);

private:
	bool ensure_schema() const;
	ProxySQL_PluginSecretResult load_master_key(uint8_t key[32]) const;

	SQLite3DB* configdb_;
	std::string datadir_;
};

#endif /* PROXYSQL40 */
#endif /* PROXYSQL_PLUGIN_SECRETS_H */
