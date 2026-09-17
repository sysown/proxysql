#ifndef PROXYSQL_MYSQL_ROUTER_CONFIG_H
#define PROXYSQL_MYSQL_ROUTER_CONFIG_H

#include "mysql_router_bootstrap.h"

#include <cstdint>
#include <mutex>
#include <string>

class SQLite3DB;

enum class MysqlRouterConfigKey : uint8_t {
	refresh_interval_ms,
	connect_timeout_ms,
	read_timeout_ms,
	bind_address,
	rw_port,
	ro_port,
	rw_split_port,
	metadata_ssl_mode,
};

struct MysqlRouterRuntimeConfig {
	uint32_t refresh_interval_ms {2000};
	uint32_t connect_timeout_ms {5000};
	uint32_t read_timeout_ms {30000};
	std::string bind_address {"0.0.0.0"};
	uint16_t rw_port {6446};
	uint16_t ro_port {6447};
	uint16_t rw_split_port {6450};
	MetadataTlsMode metadata_ssl_mode {MetadataTlsMode::preferred};
};

class MysqlRouterConfigStore {
public:
	bool load(SQLite3DB& db, std::string& error);
	MysqlRouterRuntimeConfig snapshot() const;

private:
	mutable std::mutex mutex_;
	MysqlRouterRuntimeConfig config_;
};

#endif
