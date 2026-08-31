#include "mysql_router_metadata.h"

#include <charconv>
#include <algorithm>
#include <stdexcept>

namespace {

constexpr const char* kSchemaVersion =
	"SELECT major, minor, patch FROM mysql_innodb_cluster_metadata.schema_version";
constexpr const char* kCapabilityColumns =
	"SELECT SUM(TABLE_NAME='v2_this_instance' AND COLUMN_NAME='cluster_id') AS this_instance_cluster_id, "
	"SUM(TABLE_NAME='v2_gr_clusters' AND COLUMN_NAME='group_name') AS gr_clusters_group_name, "
	"SUM(TABLE_NAME='v2_instances' AND COLUMN_NAME='mysql_server_uuid') AS instances_server_uuid, "
	"SUM(TABLE_NAME='v2_instances' AND COLUMN_NAME='endpoint') AS instances_endpoint, "
	"SUM(TABLE_NAME='v2_router_options' AND COLUMN_NAME='router_options') AS router_options "
	"FROM information_schema.columns WHERE TABLE_SCHEMA='mysql_innodb_cluster_metadata'";

const std::string& required(const QueryRow& row, const char* column) {
	auto it = row.find(column);
	if (it == row.end() || !it->second || it->second->empty()) {
		throw std::runtime_error(std::string("metadata column is missing: ") + column);
	}
	return *it->second;
}

int parse_int(const QueryRow& row, const char* column) {
	const std::string& value = required(row, column);
	int result = 0;
	auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
	if (parsed.ec != std::errc() || parsed.ptr != value.data() + value.size()) {
		throw std::runtime_error(std::string("invalid integer metadata column: ") + column);
	}
	return result;
}

void require_capability(const QueryRow& row, const char* column) {
	if (parse_int(row, column) < 1) {
		throw std::runtime_error(std::string("required metadata 2.2 column is missing: ") + column);
	}
}

} // namespace

MetadataCapabilities probe_metadata(IMetadataSession& session) {
	QueryResult result = session.query(kSchemaVersion, {});
	if (result.rows.size() != 1) {
		throw std::runtime_error("metadata 2.2 requires exactly one schema_version row");
	}
	MetadataCapabilities capabilities;
	capabilities.version = {
		parse_int(result.rows[0], "major"),
		parse_int(result.rows[0], "minor"),
		parse_int(result.rows[0], "patch")
	};
	if (capabilities.version.major != 2 || capabilities.version.minor != 2) {
		throw std::runtime_error("only MySQL InnoDB Cluster metadata 2.2 is supported");
	}
	QueryResult columns = session.query(kCapabilityColumns, {});
	if (columns.rows.size() != 1) {
		throw std::runtime_error("required metadata 2.2 capability row is missing");
	}
	for (const char* column : {"this_instance_cluster_id", "gr_clusters_group_name",
		"instances_server_uuid", "instances_endpoint", "router_options"}) {
		require_capability(columns.rows[0], column);
	}
	capabilities.router_options_view = true;
	return capabilities;
}

#ifdef MYSQL_ROUTER_CONNECTOR_C

#include <mysql.h>
#include <openssl/crypto.h>

#include <cstring>
#include <limits>

struct ConnectorCMetadataSession::Impl {
	MYSQL* mysql {nullptr};
	~Impl() { if (mysql != nullptr) mysql_close(mysql); }
};

namespace {

class Statement {
public:
	explicit Statement(MYSQL* mysql) : stmt_(mysql_stmt_init(mysql)) {
		if (stmt_ == nullptr) throw std::runtime_error("mysql_stmt_init failed");
	}
	~Statement() { mysql_stmt_close(stmt_); }
	MYSQL_STMT* get() const { return stmt_; }
private:
	MYSQL_STMT* stmt_;
};

[[noreturn]] void statement_error(MYSQL_STMT* stmt, const char* operation) {
	throw std::runtime_error(std::string(operation) + ": " + mysql_stmt_error(stmt));
}

void prepare_and_bind(Statement& statement, std::string_view sql,
	const std::vector<SqlValue>& params, std::vector<MYSQL_BIND>& binds,
	std::vector<int64_t>& integers, std::vector<unsigned long>& lengths) {
	if (sql.size() > std::numeric_limits<unsigned long>::max()) {
		throw std::runtime_error("metadata SQL is too large");
	}
	if (mysql_stmt_prepare(statement.get(), sql.data(), static_cast<unsigned long>(sql.size())) != 0) {
		statement_error(statement.get(), "mysql_stmt_prepare failed");
	}
	if (mysql_stmt_param_count(statement.get()) != params.size()) {
		throw std::runtime_error("metadata SQL parameter count mismatch");
	}
	binds.resize(params.size());
	integers.resize(params.size());
	lengths.resize(params.size());
	for (size_t i = 0; i < params.size(); ++i) {
		MYSQL_BIND& bind = binds[i];
		std::memset(&bind, 0, sizeof(bind));
		if (const auto* integer = std::get_if<int64_t>(&params[i])) {
			integers[i] = *integer;
			bind.buffer_type = MYSQL_TYPE_LONGLONG;
			bind.buffer = &integers[i];
		} else {
			const std::string& value = std::get<std::string>(params[i]);
			if (value.size() > std::numeric_limits<unsigned long>::max()) {
				throw std::runtime_error("metadata SQL parameter is too large");
			}
			lengths[i] = static_cast<unsigned long>(value.size());
			bind.buffer_type = MYSQL_TYPE_STRING;
			bind.buffer = const_cast<char*>(value.data());
			bind.buffer_length = lengths[i];
			bind.length = &lengths[i];
		}
	}
	if (!binds.empty() && mysql_stmt_bind_param(statement.get(), binds.data()) != 0) {
		statement_error(statement.get(), "mysql_stmt_bind_param failed");
	}
}

QueryResult execute_query(MYSQL* mysql, std::string_view sql,
	const std::vector<SqlValue>& params, uint64_t* affected_rows) {
	Statement statement(mysql);
	std::vector<MYSQL_BIND> params_bind;
	std::vector<int64_t> integers;
	std::vector<unsigned long> param_lengths;
	prepare_and_bind(statement, sql, params, params_bind, integers, param_lengths);
	my_bool update_max_length = 1;
	if (mysql_stmt_attr_set(statement.get(), STMT_ATTR_UPDATE_MAX_LENGTH, &update_max_length) != 0 ||
		mysql_stmt_execute(statement.get()) != 0) {
		statement_error(statement.get(), "mysql_stmt_execute failed");
	}
	if (affected_rows != nullptr) *affected_rows = mysql_stmt_affected_rows(statement.get());
	MYSQL_RES* metadata = mysql_stmt_result_metadata(statement.get());
	if (metadata == nullptr) return {};
	std::unique_ptr<MYSQL_RES, decltype(&mysql_free_result)> metadata_guard(metadata, mysql_free_result);
	if (mysql_stmt_store_result(statement.get()) != 0) {
		statement_error(statement.get(), "mysql_stmt_store_result failed");
	}
	const unsigned count = mysql_num_fields(metadata);
	MYSQL_FIELD* fields = mysql_fetch_fields(metadata);
	std::vector<MYSQL_BIND> result_bind(count);
	std::vector<std::vector<char>> buffers(count);
	std::vector<unsigned long> lengths(count);
	std::vector<my_bool> is_null(count);
	std::vector<my_bool> errors(count);
	for (unsigned i = 0; i < count; ++i) {
		buffers[i].resize(static_cast<size_t>(fields[i].max_length) + 1);
		std::memset(&result_bind[i], 0, sizeof(MYSQL_BIND));
		result_bind[i].buffer_type = MYSQL_TYPE_STRING;
		result_bind[i].buffer = buffers[i].data();
		result_bind[i].buffer_length = static_cast<unsigned long>(buffers[i].size());
		result_bind[i].length = &lengths[i];
		result_bind[i].is_null = &is_null[i];
		result_bind[i].error = &errors[i];
	}
	if (count != 0 && mysql_stmt_bind_result(statement.get(), result_bind.data()) != 0) {
		statement_error(statement.get(), "mysql_stmt_bind_result failed");
	}
	QueryResult result;
	for (;;) {
		int fetch = mysql_stmt_fetch(statement.get());
		if (fetch == MYSQL_NO_DATA) break;
		if (fetch != 0 || std::find(errors.begin(), errors.end(), 1) != errors.end()) {
			statement_error(statement.get(), "mysql_stmt_fetch failed");
		}
		QueryRow row;
		for (unsigned i = 0; i < count; ++i) {
			row[fields[i].name] = is_null[i] ? SqlCell{} : SqlCell(std::string(buffers[i].data(), lengths[i]));
		}
		result.rows.push_back(std::move(row));
	}
	return result;
}

void set_option(MYSQL* mysql, enum mysql_option option, const void* value, const char* name) {
	if (mysql_options(mysql, option, value) != 0) {
		throw std::runtime_error(std::string("failed to set Connector/C option: ") + name);
	}
}

} // namespace

ConnectorCMetadataSession::ConnectorCMetadataSession(std::unique_ptr<Impl> impl)
	: impl_(std::move(impl)) {}

ConnectorCMetadataSession::~ConnectorCMetadataSession() = default;

std::unique_ptr<ConnectorCMetadataSession> ConnectorCMetadataSession::connect(
	const MetadataEndpoint& endpoint, const TlsOptions& tls,
	const SecureBytes& password, unsigned timeout_seconds) {
	auto impl = std::make_unique<Impl>();
	impl->mysql = mysql_init(nullptr);
	if (impl->mysql == nullptr) throw std::runtime_error("mysql_init failed");
	set_option(impl->mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout_seconds, "connect timeout");
	set_option(impl->mysql, MYSQL_OPT_READ_TIMEOUT, &timeout_seconds, "read timeout");
	set_option(impl->mysql, MYSQL_OPT_WRITE_TIMEOUT, &timeout_seconds, "write timeout");
	my_bool enforce = tls.mode != MetadataTlsMode::disabled && tls.mode != MetadataTlsMode::preferred;
	my_bool verify = tls.mode == MetadataTlsMode::verify_ca || tls.mode == MetadataTlsMode::verify_identity;
	set_option(impl->mysql, MYSQL_OPT_SSL_ENFORCE, &enforce, "TLS enforcement");
	set_option(impl->mysql, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &verify, "TLS verification");
	if (tls.mode != MetadataTlsMode::disabled) {
		if (mysql_ssl_set(impl->mysql,
			tls.key.empty() ? nullptr : tls.key.c_str(), tls.cert.empty() ? nullptr : tls.cert.c_str(),
			tls.ca.empty() ? nullptr : tls.ca.c_str(), tls.capath.empty() ? nullptr : tls.capath.c_str(),
			tls.cipher.empty() ? nullptr : tls.cipher.c_str()) != 0) {
			throw std::runtime_error("failed to configure Connector/C TLS");
		}
		if (!tls.crl.empty()) set_option(impl->mysql, MYSQL_OPT_SSL_CRL, tls.crl.c_str(), "TLS CRL");
		if (!tls.crlpath.empty()) {
			set_option(impl->mysql, MYSQL_OPT_SSL_CRLPATH, tls.crlpath.c_str(), "TLS CRL path");
		}
	}
	std::vector<char> password_copy(password.size() + 1, '\0');
	if (!password.empty()) std::memcpy(password_copy.data(), password.data(), password.size());
	MYSQL* connected = mysql_real_connect(impl->mysql, endpoint.host.c_str(), endpoint.username.c_str(),
		password_copy.data(), nullptr, endpoint.port, nullptr, 0);
	OPENSSL_cleanse(password_copy.data(), password_copy.size());
	if (connected == nullptr) {
		throw std::runtime_error(std::string("metadata connection failed: ") + mysql_error(impl->mysql));
	}
	return std::unique_ptr<ConnectorCMetadataSession>(new ConnectorCMetadataSession(std::move(impl)));
}

QueryResult ConnectorCMetadataSession::query(
	std::string_view sql, const std::vector<SqlValue>& params) {
	return execute_query(impl_->mysql, sql, params, nullptr);
}

ExecResult ConnectorCMetadataSession::execute(
	std::string_view sql, const std::vector<SqlValue>& params) {
	try {
		uint64_t affected = 0;
		(void)execute_query(impl_->mysql, sql, params, &affected);
		return {true, affected, {}};
	} catch (const std::exception& error) {
		return {false, 0, error.what()};
	}
}

ServerVersion ConnectorCMetadataSession::server_version() const {
	unsigned long version = mysql_get_server_version(impl_->mysql);
	return {static_cast<int>(version / 10000), static_cast<int>((version / 100) % 100),
		static_cast<int>(version % 100)};
}

#endif
