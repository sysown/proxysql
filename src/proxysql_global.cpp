#define PROXYSQL_EXTERN
#include "proxysql.h"
//#include "proxysql_glovars.hpp"
#include "cpp.h"
//ProxySQL_GlobalVariables GloVars;

SSL_CTX * ProxySQL_GlobalVariables::get_SSL_ctx() {
	// take the mutex
	std::lock_guard<std::mutex> lock(global.ssl_mutex);
	return GloVars.global.ssl_ctx;
}

SSL * ProxySQL_GlobalVariables::get_SSL_new() {
	// take the mutex
	std::lock_guard<std::mutex> lock(global.ssl_mutex);
	return SSL_new(GloVars.global.ssl_ctx);
}

SSL * ProxySQL_GlobalVariables::get_admin_SSL_new() {
	{
		std::lock_guard<std::mutex> lock(global.admin_ssl_mutex);
		if (global.admin_ssl_enabled && global.admin_ssl_ctx) {
			return SSL_new(global.admin_ssl_ctx);
		}
	}

	// Admin TLS is disabled. Preserve the historical behavior and use the
	// shared frontend TLS context.
	return get_SSL_new();
}

bool ProxySQL_GlobalVariables::is_admin_SSL_enabled() {
	std::lock_guard<std::mutex> lock(global.admin_ssl_mutex);
	return global.admin_ssl_enabled;
}

void ProxySQL_GlobalVariables::set_admin_SSL_ctx(SSL_CTX *ctx, bool enabled) {
	assert(!enabled || ctx);

	SSL_CTX *old_ctx = NULL;
	{
		std::lock_guard<std::mutex> lock(global.admin_ssl_mutex);
		old_ctx = global.admin_ssl_ctx;
		global.admin_ssl_ctx = enabled ? ctx : NULL;
		global.admin_ssl_enabled = enabled;
	}

	// SSL_new() retains its SSL_CTX. It is therefore safe to release the
	// global reference after the swap while established connections continue
	// using the old context.
	if (old_ctx && old_ctx != ctx) {
		SSL_CTX_free(old_ctx);
	}
}

void ProxySQL_GlobalVariables::get_SSL_pem_mem(char **key, char **cert) {
	// take the mutex
	std::lock_guard<std::mutex> lock(global.ssl_mutex);
	*key = strdup(global.ssl_key_pem_mem);
	*cert = strdup(global.ssl_cert_pem_mem);
}
