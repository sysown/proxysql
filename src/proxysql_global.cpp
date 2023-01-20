#define PROXYSQL_EXTERN
#include "proxysql.h"
//#include "proxysql_glovars.hpp"
#include "cpp.h"
//ProxySQL_GlobalVariables GloVars;

SSL * ProxySQL_GlobalVariables::get_SSL_ctx() {
	// take the mutex
	std::lock_guard<std::mutex> lock(global.ssl_mutex);
	return SSL_new(GloVars.global.ssl_ctx);
}

void ProxySQL_GlobalVariables::get_SSL_pem_mem(char **key, char **cert) {
	// take the mutex
	std::lock_guard<std::mutex> lock(global.ssl_mutex);
	*key = strdup(global.ssl_key_pem_mem);
	*cert = strdup(global.ssl_cert_pem_mem);
}
