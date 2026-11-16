#define PROXYSQL_EXTERN
#include "proxysql.h"
//#include "proxysql_glovars.hpp"
#include "cpp.h"

#include <cerrno>
#include <string>
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

	// Hold ssl_mutex only long enough to copy the configured path. The same
	// mutex guards get_SSL_new(), so file I/O while holding it would stall
	// every TLS client handshake.
	std::string ca_path;
	{
		std::lock_guard<std::mutex> lock(global.ssl_mutex);
		if (global.tls_ca_file == nullptr) {
			return;
		}
		ca_path = global.tls_ca_file;
	}

	FILE* fp = fopen(ca_path.c_str(), "rb");
	if (fp == nullptr) {
		const int saved_errno = errno;
		proxy_error("Cannot open TLS CA file '%s' for reading: %s\n",
			ca_path.c_str(), strerror(saved_errno));
		return;
	}
	if (fseek(fp, 0, SEEK_END) != 0) {
		const int saved_errno = errno;
		proxy_error("Cannot seek to end of TLS CA file '%s': %s\n",
			ca_path.c_str(), strerror(saved_errno));
		fclose(fp);
		return;
	}
	errno = 0;
	const long size = ftell(fp);
	if (size < 0) {
		const int saved_errno = errno;
		proxy_error("Cannot determine size of TLS CA file '%s': %s\n",
			ca_path.c_str(),
			saved_errno != 0 ? strerror(saved_errno) : "ftell failed without errno");
		fclose(fp);
		return;
	}
	if (size == 0) {
		proxy_error("TLS CA file '%s' is empty\n", ca_path.c_str());
		fclose(fp);
		return;
	}
	if (fseek(fp, 0, SEEK_SET) != 0) {
		const int saved_errno = errno;
		proxy_error("Cannot rewind TLS CA file '%s': %s\n",
			ca_path.c_str(), strerror(saved_errno));
		fclose(fp);
		return;
	}
	char* buffer = static_cast<char*>(malloc(static_cast<size_t>(size) + 1));
	if (buffer == nullptr) {
		proxy_error("Cannot allocate %ld bytes for TLS CA file '%s'\n",
			size + 1, ca_path.c_str());
		fclose(fp);
		return;
	}
	const size_t read = fread(buffer, 1, static_cast<size_t>(size), fp);
	const bool read_error = ferror(fp) != 0;
	const int read_errno = errno;
	fclose(fp);
	if (read != static_cast<size_t>(size)) {
		if (read_error) {
			proxy_error("Cannot read TLS CA file '%s': %s\n",
				ca_path.c_str(),
				read_errno != 0 ? strerror(read_errno) : "fread failed without errno");
		} else {
			proxy_error("Short read from TLS CA file '%s': read %zu of %ld bytes\n",
				ca_path.c_str(), read, size);
		}
		free(buffer);
		return;
	}
	buffer[size] = '\0';
	*ca = buffer;
}
