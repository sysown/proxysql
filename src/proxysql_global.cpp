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

void ProxySQL_GlobalVariables::get_SSL_pem_mem(char **key, char **cert) {
	if (key == nullptr || cert == nullptr) {
		return;
	}
	// take the mutex
	std::lock_guard<std::mutex> lock(global.ssl_mutex);
	*key = global.ssl_key_pem_mem ? strdup(global.ssl_key_pem_mem) : nullptr;
	*cert = global.ssl_cert_pem_mem ? strdup(global.ssl_cert_pem_mem) : nullptr;
}

void ProxySQL_GlobalVariables::get_SSL_ca_pem_mem(char **ca) {
	if (ca == nullptr) {
		return;
	}
	*ca = nullptr;
	std::lock_guard<std::mutex> lock(global.ssl_mutex);
	if (global.tls_ca_file == nullptr) {
		return;
	}
	FILE* fp = fopen(global.tls_ca_file, "rb");
	if (fp == nullptr) {
		return;
	}
	if (fseek(fp, 0, SEEK_END) != 0) {
		fclose(fp);
		return;
	}
	long size = ftell(fp);
	if (size <= 0) {
		fclose(fp);
		return;
	}
	if (fseek(fp, 0, SEEK_SET) != 0) {
		fclose(fp);
		return;
	}
	char* buffer = static_cast<char*>(malloc(static_cast<size_t>(size) + 1));
	if (buffer == nullptr) {
		fclose(fp);
		return;
	}
	size_t read = fread(buffer, 1, static_cast<size_t>(size), fp);
	fclose(fp);
	if (read != static_cast<size_t>(size)) {
		free(buffer);
		return;
	}
	buffer[size] = '\0';
	*ca = buffer;
}
