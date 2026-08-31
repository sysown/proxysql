#include "mysql_router_config.h"

#include "sqlite3db.h"

#include <cctype>
#include <cstdlib>
#include <limits>
#include <memory>
#include <stdexcept>

namespace {

uint32_t parse_uint32(const std::string& value, const std::string& key,
	uint32_t maximum = std::numeric_limits<uint32_t>::max()) {
	if (value.empty()) throw std::invalid_argument(key + " must not be empty");
	uint64_t parsed = 0;
	for (unsigned char character : value) {
		if (!std::isdigit(character)) throw std::invalid_argument(key + " must be an unsigned integer");
		const unsigned digit = static_cast<unsigned>(character - '0');
		if (parsed > (maximum - digit) / 10) {
			throw std::invalid_argument(key + " is outside the allowed range");
		}
		parsed = parsed * 10 + digit;
	}
	return static_cast<uint32_t>(parsed);
}

MetadataTlsMode parse_config_tls_mode(const std::string& value) {
	if (value == "DISABLED") return MetadataTlsMode::disabled;
	if (value == "PREFERRED") return MetadataTlsMode::preferred;
	if (value == "REQUIRED") return MetadataTlsMode::required;
	if (value == "VERIFY_CA") return MetadataTlsMode::verify_ca;
	if (value == "VERIFY_IDENTITY") return MetadataTlsMode::verify_identity;
	throw std::invalid_argument("metadata_ssl_mode has an invalid value");
}

void apply_config(MysqlRouterRuntimeConfig& config, const std::string& key,
	const std::string& value) {
	if (key == "refresh_interval_ms") config.refresh_interval_ms = parse_uint32(value, key);
	else if (key == "connect_timeout_ms") config.connect_timeout_ms = parse_uint32(value, key);
	else if (key == "read_timeout_ms") config.read_timeout_ms = parse_uint32(value, key);
	else if (key == "bind_address") {
		if (value.empty()) throw std::invalid_argument("bind_address must not be empty");
		config.bind_address = value;
	} else if (key == "rw_port") config.rw_port = static_cast<uint16_t>(parse_uint32(value, key, 65535));
	else if (key == "ro_port") config.ro_port = static_cast<uint16_t>(parse_uint32(value, key, 65535));
	else if (key == "rw_split_port") config.rw_split_port = static_cast<uint16_t>(parse_uint32(value, key, 65535));
	else if (key == "metadata_ssl_mode") config.metadata_ssl_mode = parse_config_tls_mode(value);
	else throw std::invalid_argument("unknown mysql_router_config key: " + key);
}

} // namespace

bool MysqlRouterConfigStore::load(SQLite3DB& db, std::string& error) {
	error.clear();
	char* sqlite_error = nullptr;
	std::unique_ptr<SQLite3_result> result(db.execute_statement(
		"SELECT config_key,config_value FROM mysql_router_config ORDER BY config_key",
		&sqlite_error));
	if (sqlite_error != nullptr) {
		error = sqlite_error;
		free(sqlite_error);
		return false;
	}
	if (!result) {
		error = "mysql_router_config query returned no result";
		return false;
	}
	MysqlRouterRuntimeConfig candidate;
	try {
		for (const auto* row : result->rows) {
			if (row == nullptr || row->fields[0] == nullptr || row->fields[1] == nullptr) {
				throw std::invalid_argument("mysql_router_config contains a NULL field");
			}
			apply_config(candidate, row->fields[0], row->fields[1]);
		}
		if (candidate.rw_port == 0 || candidate.ro_port == 0 || candidate.rw_split_port == 0) {
			throw std::invalid_argument("Router listener ports must be nonzero");
		}
	} catch (const std::exception& exception) {
		error = exception.what();
		return false;
	}
	{
		std::lock_guard<std::mutex> guard(mutex_);
		config_ = std::move(candidate);
	}
	return true;
}

MysqlRouterRuntimeConfig MysqlRouterConfigStore::snapshot() const {
	std::lock_guard<std::mutex> guard(mutex_);
	return config_;
}
