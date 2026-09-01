#include "mysql_router_bootstrap.h"

#include "mysql_router_compiler.h"
#include "mysql_router_metadata.h"
#include "mysql_router_users.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <random>
#include <set>
#include <stdexcept>

#ifdef MYSQL_ROUTER_CONNECTOR_C
#include <openssl/crypto.h>
#include <openssl/rand.h>
#endif

namespace {

constexpr std::string_view kAlphabet =
	"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr std::string_view kSuffixAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789";

std::vector<uint8_t> random_bytes(size_t count) {
	std::vector<uint8_t> bytes(count);
#ifdef MYSQL_ROUTER_CONNECTOR_C
	if (count > static_cast<size_t>(std::numeric_limits<int>::max()) ||
		RAND_bytes(bytes.data(), static_cast<int>(count)) != 1) {
		throw std::runtime_error("secure random generation failed");
	}
#else
	std::random_device random;
	for (uint8_t& byte : bytes) byte = static_cast<uint8_t>(random());
#endif
	return bytes;
}

std::string random_text(size_t count, std::string_view alphabet) {
	std::vector<uint8_t> random = random_bytes(count);
	std::string result(count, '\0');
	for (size_t i = 0; i < count; ++i) result[i] = alphabet[random[i] % alphabet.size()];
	return result;
}

std::vector<uint8_t> random_password() {
	std::string text = random_text(32, kAlphabet);
	return std::vector<uint8_t>(text.begin(), text.end());
}

class PasswordWiper {
public:
	explicit PasswordWiper(std::vector<uint8_t>& bytes) : bytes_(bytes) {}
	~PasswordWiper() {
#ifdef MYSQL_ROUTER_CONNECTOR_C
		if (!bytes_.empty()) OPENSSL_cleanse(bytes_.data(), bytes_.size());
#else
		std::fill(bytes_.begin(), bytes_.end(), 0);
#endif
	}
private:
	std::vector<uint8_t>& bytes_;
};

std::string phase_name(BootstrapPhase phase) {
	switch (phase) {
		case BootstrapPhase::discovered: return "discovered";
		case BootstrapPhase::account_ready: return "account_ready";
		case BootstrapPhase::registered: return "registered";
		case BootstrapPhase::local_configured: return "local_configured";
		case BootstrapPhase::complete: return "complete";
	}
	return "unknown";
}

std::string account_sql(IMetadataSession& session, std::string_view username,
	std::string_view host) {
	return session.quote_sql_string(username) + "@" + session.quote_sql_string(host);
}

void require_execute(IMetadataSession& session, const std::string& sql) {
	ExecResult result = session.execute(sql, {});
	if (!result.ok) throw std::runtime_error(result.error.empty() ? "metadata mutation failed" : result.error);
}

std::string uppercase(std::string value) {
	std::transform(value.begin(), value.end(), value.begin(),
		[](unsigned char c) { return static_cast<char>(std::toupper(c)); });
	return value;
}

void validate_grants(IMetadataSession& session, const std::string& account) {
	QueryResult result = session.query("SHOW GRANTS FOR " + account, {});
	std::string grants;
	for (const QueryRow& row : result.rows) {
		if (row.empty() || !row.begin()->second) continue;
		grants += uppercase(*row.begin()->second) + "\n";
	}
	for (const char* required : {
		"SELECT, EXECUTE ON `MYSQL_INNODB_CLUSTER_METADATA`.*",
		"UPDATE ON `MYSQL_INNODB_CLUSTER_METADATA`.`CLUSTERS`",
		"UPDATE ON `MYSQL_INNODB_CLUSTER_METADATA`.`CLUSTERSETS`",
		"INSERT, UPDATE, DELETE ON `MYSQL_INNODB_CLUSTER_METADATA`.`ROUTERS`",
		"UPDATE ON `MYSQL_INNODB_CLUSTER_METADATA`.`V2_AR_CLUSTERS`",
		"UPDATE ON `MYSQL_INNODB_CLUSTER_METADATA`.`V2_CS_CLUSTERSETS`",
		"UPDATE ON `MYSQL_INNODB_CLUSTER_METADATA`.`V2_GR_CLUSTERS`",
		"INSERT, UPDATE, DELETE ON `MYSQL_INNODB_CLUSTER_METADATA`.`V2_ROUTERS`",
		"SELECT ON `PERFORMANCE_SCHEMA`.`REPLICATION_GROUP_MEMBERS`",
		"SELECT ON `PERFORMANCE_SCHEMA`.`REPLICATION_GROUP_MEMBER_STATS`",
		"SELECT ON `PERFORMANCE_SCHEMA`.`GLOBAL_VARIABLES`",
		"AUTHENTICATION_STRING"}) {
		if (grants.find(required) == std::string::npos) {
			throw std::runtime_error("existing metadata account is missing required grants");
		}
	}
}

void apply_grants(IMetadataSession& session, const std::string& account) {
	for (const std::string& statement : {
		"GRANT SELECT, EXECUTE ON mysql_innodb_cluster_metadata.* TO " + account,
		"GRANT UPDATE ON mysql_innodb_cluster_metadata.clusters TO " + account,
		"GRANT UPDATE ON mysql_innodb_cluster_metadata.clustersets TO " + account,
		"GRANT INSERT, UPDATE, DELETE ON mysql_innodb_cluster_metadata.routers TO " + account,
		"GRANT UPDATE ON mysql_innodb_cluster_metadata.v2_ar_clusters TO " + account,
		"GRANT UPDATE ON mysql_innodb_cluster_metadata.v2_cs_clustersets TO " + account,
		"GRANT UPDATE ON mysql_innodb_cluster_metadata.v2_gr_clusters TO " + account,
		"GRANT INSERT, UPDATE, DELETE ON mysql_innodb_cluster_metadata.v2_routers TO " + account,
		"GRANT SELECT ON performance_schema.replication_group_members TO " + account,
		"GRANT SELECT ON performance_schema.replication_group_member_stats TO " + account,
		"GRANT SELECT ON performance_schema.global_variables TO " + account,
		"GRANT SELECT (User,Host,plugin,authentication_string,account_locked,password_expired,ssl_type) ON mysql.user TO " + account}) {
		require_execute(session, statement);
	}
}

void ensure_account(IMetadataSession& session, const BootstrapOptions& options,
	const std::string& username, const std::vector<uint8_t>& password,
	bool have_persisted_secret, bool plugin_owned) {
	QueryResult users = session.query(
		"SELECT User,Host,plugin,authentication_string,account_locked,password_expired,ssl_type "
		"FROM mysql.user WHERE User=? AND Host=?",
		{username, options.account_host});
	if (users.rows.size() > 1) throw std::runtime_error("metadata account lookup is ambiguous");
	const std::string account = account_sql(session, username, options.account_host);
	const std::string password_text(reinterpret_cast<const char*>(password.data()), password.size());
	if (!users.rows.empty()) {
		if (options.account_create == AccountCreatePolicy::always && !plugin_owned) {
			throw std::runtime_error("metadata account already exists under --account-create=always");
		}
		if (users.rows[0].find("plugin") == users.rows[0].end() ||
			!users.rows[0].at("plugin") || *users.rows[0].at("plugin") != "caching_sha2_password") {
			throw std::runtime_error("existing metadata account does not use caching_sha2_password");
		}
		if (plugin_owned && !have_persisted_secret) {
			require_execute(session, "ALTER USER " + account +
				" IDENTIFIED WITH caching_sha2_password BY " + session.quote_sql_string(password_text));
			apply_grants(session, account);
		} else {
			validate_grants(session, account);
		}
		return;
	}
	if (options.account_create == AccountCreatePolicy::never) {
		throw std::runtime_error("metadata account is absent under --account-create=never");
	}
	require_execute(session, "CREATE USER " + account +
		" IDENTIFIED WITH caching_sha2_password BY " + session.quote_sql_string(password_text));
	apply_grants(session, account);
}

} // namespace

MysqlRouterBootstrap::MysqlRouterBootstrap(IMetadataSession& session,
	IBootstrapStore& store, DesiredTopology topology, std::string router_address)
	: session_(session), store_(store), topology_(std::move(topology)),
	  router_address_(std::move(router_address)) {}

BootstrapResult MysqlRouterBootstrap::run(const BootstrapOptions& options) {
	BootstrapResult result;
	result.topology_uuid = topology_.topology_uuid;
	std::optional<BootstrapJournal> progress;
	try {
		if (topology_.topology_uuid.empty()) throw std::runtime_error("discovered topology UUID is empty");
		auto identity = store_.load_identity();
		if (identity && identity->topology_uuid != topology_.topology_uuid && !options.replace_topology) {
			throw std::runtime_error("persisted topology differs; use --replace-topology to continue");
		}
		auto journal = store_.load_journal(topology_.topology_uuid);
		const bool generated_account = options.service_account.empty();
		std::string metadata_user = options.service_account;
		if (metadata_user.empty() && journal) metadata_user = journal->metadata_user;
		const bool registration_has_metadata_user = !metadata_user.empty();

		RouterRegistration registration = register_or_adopt_router(
			session_, topology_, options, router_address_, metadata_user);
		if (metadata_user.empty()) {
			metadata_user = "mysql_router" + std::to_string(registration.router_id) + "_" +
				random_text(12, kSuffixAlphabet);
		}
		progress = BootstrapJournal {topology_.topology_uuid, options.router_name,
			BootstrapPhase::discovered, registration.router_id, metadata_user, {}};
		store_.save_journal(*progress);

		const std::string secret_name = "metadata-" + topology_.topology_uuid;
		auto persisted_secret = store_.get_secret(secret_name);
		std::vector<uint8_t> password = persisted_secret ? *persisted_secret : random_password();
		PasswordWiper wipe(password);
		ensure_account(session_, options, metadata_user, password,
			persisted_secret.has_value(), generated_account);
		progress->phase = BootstrapPhase::account_ready;
		store_.save_journal(*progress);

		if (!registration_has_metadata_user) {
			registration = register_or_adopt_router(
				session_, topology_, options, router_address_, metadata_user);
		}
		progress->phase = BootstrapPhase::registered;
		store_.save_journal(*progress);
		store_.put_secret(secret_name, password);

		uint64_t next_generation = 1;
		if (identity) {
			const uint64_t active_generation = std::max(
				identity->topology_generation, identity->user_generation);
			if (active_generation == static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
				throw std::runtime_error("Router configuration generation is exhausted");
			}
			next_generation = active_generation + 1;
		}
		BootstrapIdentity completed {topology_.topology_uuid, topology_.topology_name,
			registration.router_id, options.router_name, router_address_, metadata_user,
			options.seed.host, options.seed.port};
		completed.topology_generation = store_.publish_topology(
			topology_, options.listeners, next_generation);
		const AccountSnapshot accounts = UserSynchronizer::read(session_, metadata_user);
		if (completed.topology_generation == static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
			throw std::runtime_error("Router user generation is exhausted");
		}
		completed.user_generation = store_.publish_users(topology_, options.listeners,
			accounts, metadata_user, completed.topology_generation + 1);
		store_.save_complete(completed, options.listeners);
		progress->phase = BootstrapPhase::local_configured;
		store_.save_journal(*progress);
		progress->phase = BootstrapPhase::complete;
		store_.save_journal(*progress);
		result.success = true;
		result.router_id = registration.router_id;
		result.metadata_user = metadata_user;
	} catch (const std::exception& error) {
		result.error = error.what();
		if (progress) {
			progress->last_error = result.error;
			try { store_.save_journal(*progress); } catch (...) {}
		}
	}
	return result;
}

#ifdef MYSQL_ROUTER_CONNECTOR_C

#include "sqlite3db.h"

#include <cstdlib>
#include <memory>
#include <set>

namespace {

std::string sqlite_quote(std::string_view value) {
	char* quoted = sqlite3_mprintf("%Q", std::string(value).c_str());
	if (quoted == nullptr) throw std::bad_alloc();
	std::string result(quoted);
	sqlite3_free(quoted);
	return result;
}

BootstrapPhase parse_phase(const char* value) {
	if (value == nullptr) throw std::runtime_error("bootstrap journal phase is NULL");
	const std::string phase(value);
	if (phase == "discovered") return BootstrapPhase::discovered;
	if (phase == "account_ready") return BootstrapPhase::account_ready;
	if (phase == "registered") return BootstrapPhase::registered;
	if (phase == "local_configured") return BootstrapPhase::local_configured;
	if (phase == "complete") return BootstrapPhase::complete;
	throw std::runtime_error("bootstrap journal phase is invalid");
}

int64_t local_int64(const char* value, const char* field) {
	if (value == nullptr || *value == '\0') throw std::runtime_error(std::string(field) + " is NULL");
	char* end = nullptr;
	long long parsed = std::strtoll(value, &end, 10);
	if (end == nullptr || *end != '\0' || parsed <= 0) {
		throw std::runtime_error(std::string(field) + " is invalid");
	}
	return parsed;
}

int64_t local_nonnegative(const char* value, const char* field) {
	if (value == nullptr || *value == '\0') throw std::runtime_error(std::string(field) + " is NULL");
	char* end = nullptr;
	long long parsed = std::strtoll(value, &end, 10);
	if (end == nullptr || *end != '\0' || parsed < 0) {
		throw std::runtime_error(std::string(field) + " is invalid");
	}
	return parsed;
}

int local_integer(const char* value, const char* field) {
	if (value == nullptr || *value == '\0') throw std::runtime_error(std::string(field) + " is NULL");
	char* end = nullptr;
	const long long parsed = std::strtoll(value, &end, 10);
	if (end == nullptr || *end != '\0' || parsed < std::numeric_limits<int>::min() ||
		parsed > std::numeric_limits<int>::max()) {
		throw std::runtime_error(std::string(field) + " is invalid");
	}
	return static_cast<int>(parsed);
}

std::unique_ptr<SQLite3_result> local_query(SQLite3DB& db, const std::string& sql) {
	char* error = nullptr;
	std::unique_ptr<SQLite3_result> result(db.execute_statement(sql.c_str(), &error));
	if (error != nullptr) {
		std::string message(error);
		free(error);
		throw std::runtime_error(message);
	}
	if (!result) throw std::runtime_error("local Router configuration query failed");
	return result;
}

int column_index(const SQLite3_result& result, std::string_view name) {
	for (size_t i = 0; i < result.column_definition.size(); ++i) {
		if (result.column_definition[i] && result.column_definition[i]->name &&
			name == result.column_definition[i]->name) return static_cast<int>(i);
	}
	throw std::runtime_error("runtime snapshot is missing column " + std::string(name));
}

void collect_snapshot_column(const SQLite3_result& result, std::string_view name,
	std::set<int>& destination) {
	const int column = column_index(result, name);
	for (auto* row : result.rows) {
		destination.insert(static_cast<int>(local_int64(row->fields[column], name.data())));
	}
}

void collect_query_column(SQLite3DB& db, const std::string& sql,
	std::set<int>& destination) {
	auto rows = local_query(db, sql);
	for (auto* row : rows->rows) {
		destination.insert(static_cast<int>(local_int64(row->fields[0], "configuration ID")));
	}
}

std::vector<std::string> split_interfaces(std::string_view value) {
	std::vector<std::string> result;
	size_t start = 0;
	while (start <= value.size()) {
		const size_t end = value.find(';', start);
		const std::string item(value.substr(start,
			end == std::string_view::npos ? std::string_view::npos : end - start));
		if (!item.empty()) result.push_back(item);
		if (end == std::string_view::npos) break;
		start = end + 1;
	}
	return result;
}

std::vector<CurrentMysqlUser> current_mysql_users(SQLite3DB& db) {
	auto rows = local_query(db,
		"SELECT u.username,u.password,u.active,u.use_ssl,u.default_hostgroup,u.default_schema,"
		"u.schema_locked,u.transaction_persistent,u.fast_forward,u.frontend,u.backend,"
		"u.max_connections,u.attributes,u.comment,EXISTS(SELECT 1 FROM main.proxysql_plugin_owned_objects o "
		"WHERE o.owner='mysql_router' AND ((o.object_type='mysql_user_v2' AND "
		"(o.object_key='v2:'||u.backend||':'||u.frontend||':'||upper(hex(u.username)) OR "
		"(o.object_key='v2:1:1:'||upper(hex(u.username)) AND u.comment LIKE 'mysql_router:%' AND "
		"((u.backend=1 AND u.frontend=0) OR (u.backend=0 AND u.frontend=1))))) OR "
		"(o.object_type='mysql_user' AND o.object_key=u.username AND u.comment LIKE 'mysql_router:%'))) AS owned "
		"FROM main.mysql_users u ORDER BY u.username,u.backend DESC");
	std::vector<CurrentMysqlUser> result;
	for (auto* source : rows->rows) {
		CurrentMysqlUser row;
		row.username = source->fields[0] ? source->fields[0] : "";
		row.password = source->fields[1] ? source->fields[1] : "";
		row.active = local_nonnegative(source->fields[2], "active") != 0;
		row.use_ssl = local_nonnegative(source->fields[3], "use_ssl") != 0;
		row.default_hostgroup = local_integer(source->fields[4], "default_hostgroup");
		row.default_schema = source->fields[5] ? source->fields[5] : "";
		row.schema_locked = local_nonnegative(source->fields[6], "schema_locked") != 0;
		row.transaction_persistent = local_nonnegative(source->fields[7], "transaction_persistent") != 0;
		row.fast_forward = local_nonnegative(source->fields[8], "fast_forward") != 0;
		row.frontend = local_nonnegative(source->fields[9], "frontend") != 0;
		row.backend = local_nonnegative(source->fields[10], "backend") != 0;
		row.max_connections = static_cast<int>(local_nonnegative(source->fields[11], "max_connections"));
		row.attributes = source->fields[12] ? source->fields[12] : "";
		row.comment = source->fields[13] ? source->fields[13] : "";
		row.owned = local_nonnegative(source->fields[14], "owned") != 0;
		if (row.username.empty()) throw std::runtime_error("current mysql_users contains an empty username");
		result.push_back(std::move(row));
	}
	std::vector<CurrentMysqlUser> canonical;
	for (size_t begin = 0; begin < result.size();) {
		size_t end = begin + 1;
		while (end < result.size() && result[end].username == result[begin].username) ++end;
		if (end - begin == 2 && result[begin].owned && result[begin + 1].owned) {
			const CurrentMysqlUser* backend = nullptr;
			const CurrentMysqlUser* frontend = nullptr;
			for (size_t index = begin; index < end; ++index) {
				if (result[index].backend && !result[index].frontend) backend = &result[index];
				if (!result[index].backend && result[index].frontend) frontend = &result[index];
			}
			const auto managed = [](const CurrentMysqlUser& user) {
				return std::tie(user.username, user.password, user.active, user.use_ssl,
					user.default_hostgroup, user.default_schema, user.schema_locked,
					user.transaction_persistent, user.fast_forward, user.max_connections,
					user.attributes, user.comment, user.owned);
			};
			if (backend != nullptr && frontend != nullptr && managed(*backend) == managed(*frontend)) {
				CurrentMysqlUser combined = *backend;
				combined.backend = true;
				combined.frontend = true;
				canonical.push_back(std::move(combined));
				begin = end;
				continue;
			}
		}
		for (size_t index = begin; index < end; ++index) canonical.push_back(std::move(result[index]));
		begin = end;
	}
	return canonical;
}

std::map<std::string, PersistedManagedUser> persisted_mysql_router_users(SQLite3DB& db) {
	auto rows = local_query(db,
		"SELECT username,source_fingerprint,state,auth_plugin FROM mysql_router_users ORDER BY username");
	std::map<std::string, PersistedManagedUser> result;
	for (auto* row : rows->rows) {
		if (row->fields[0] == nullptr || row->fields[1] == nullptr ||
			row->fields[2] == nullptr || row->fields[3] == nullptr) {
			throw std::runtime_error("mysql_router_users contains a NULL field");
		}
		if (!result.emplace(row->fields[0], PersistedManagedUser {
			row->fields[1], row->fields[2], row->fields[3]}).second) {
			throw std::runtime_error("mysql_router_users contains duplicate usernames");
		}
	}
	return result;
}

void persist_mysql_router_users(SQLite3DB& db, uint64_t generation,
	const std::vector<ManagedUserStatus>& status) {
	if (!db.execute("BEGIN IMMEDIATE")) throw std::runtime_error("failed to begin user-state commit");
	bool ok = db.execute("DELETE FROM main.mysql_router_users") &&
		db.execute("DELETE FROM disk.mysql_router_users");
	for (const auto& row : status) {
		const std::string values = sqlite_quote(row.username) + "," +
			sqlite_quote(row.source_fingerprint) + "," + sqlite_quote(row.auth_plugin) + "," +
			sqlite_quote(row.state) + "," + sqlite_quote(row.last_error) + "," +
			std::to_string(generation);
		ok = ok && db.execute(("INSERT INTO main.mysql_router_users"
			"(username,source_fingerprint,auth_plugin,state,last_error,generation) VALUES(" +
			values + ")").c_str());
		ok = ok && db.execute(("INSERT INTO disk.mysql_router_users"
			"(username,source_fingerprint,auth_plugin,state,last_error,generation) VALUES(" +
			values + ")").c_str());
	}
	if (!ok || !db.execute("COMMIT")) {
		db.execute("ROLLBACK");
		throw std::runtime_error("failed to persist Router user state");
	}
}

class PluginBootstrapStore final : public IBootstrapStore {
public:
	explicit PluginBootstrapStore(ProxySQL_PluginServices& services, IMetadataSession& session)
		: services_(services), session_(session),
		  db_(services.get_configdb ? services.get_configdb() : nullptr) {
		if (services_.apply_mysql_config_v2 == nullptr) {
			throw std::runtime_error("native MySQL configuration services are unavailable");
		}
		if (db_ == nullptr || services_.put_secret == nullptr || services_.get_secret == nullptr) {
			throw std::runtime_error("bootstrap persistence services are unavailable");
		}
	}

	std::optional<BootstrapJournal> load_journal(std::string_view topology_uuid) override {
		const std::string sql = "SELECT topology_uuid,router_name,phase,router_id,metadata_user,last_error "
			"FROM mysql_router_bootstrap_journal WHERE topology_uuid=" + sqlite_quote(topology_uuid);
		char* error = nullptr;
		std::unique_ptr<SQLite3_result> result(db_->execute_statement(sql.c_str(), &error));
		if (error != nullptr) {
			std::string message(error); free(error); throw std::runtime_error(message);
		}
		if (!result || result->rows.empty()) return std::nullopt;
		if (result->rows.size() != 1) throw std::runtime_error("duplicate bootstrap journal rows");
		auto* row = result->rows[0];
		BootstrapJournal journal;
		journal.topology_uuid = row->fields[0] ? row->fields[0] : "";
		journal.router_name = row->fields[1] ? row->fields[1] : "";
		journal.phase = parse_phase(row->fields[2]);
		journal.router_id = row->fields[3] ? local_int64(row->fields[3], "router_id") : 0;
		journal.metadata_user = row->fields[4] ? row->fields[4] : "";
		journal.last_error = row->fields[5] ? row->fields[5] : "";
		return journal;
	}

	std::optional<BootstrapIdentity> load_identity() override {
		char* error = nullptr;
		std::unique_ptr<SQLite3_result> result(db_->execute_statement(
			"SELECT topology_uuid,router_id,router_name,router_address,metadata_user,metadata_host,metadata_port,"
			"topology_generation,user_generation "
			"FROM mysql_router_instance WHERE singleton_id=1", &error));
		if (error != nullptr) {
			std::string message(error); free(error); throw std::runtime_error(message);
		}
		if (!result || result->rows.empty()) return std::nullopt;
		if (result->rows.size() != 1) throw std::runtime_error("duplicate local Router identities");
		auto* row = result->rows[0];
		BootstrapIdentity identity;
		identity.topology_uuid = row->fields[0] ? row->fields[0] : "";
		identity.router_id = local_int64(row->fields[1], "router_id");
		identity.router_name = row->fields[2] ? row->fields[2] : "";
		identity.router_address = row->fields[3] ? row->fields[3] : "";
		identity.metadata_user = row->fields[4] ? row->fields[4] : "";
		identity.metadata_host = row->fields[5] ? row->fields[5] : "";
		identity.metadata_port = static_cast<uint16_t>(local_int64(row->fields[6], "metadata_port"));
		const int64_t topology_generation = local_int64(row->fields[7], "topology_generation");
		const int64_t user_generation = local_int64(row->fields[8], "user_generation");
		if (topology_generation < 0 || user_generation < 0) {
			throw std::runtime_error("persisted Router generation is negative");
		}
		identity.topology_generation = static_cast<uint64_t>(topology_generation);
		identity.user_generation = static_cast<uint64_t>(user_generation);
		return identity;
	}

	void save_journal(const BootstrapJournal& journal) override {
		const std::string sql = "INSERT INTO mysql_router_bootstrap_journal"
			"(topology_uuid,router_name,phase,router_id,metadata_user,updated_at,last_error) VALUES(" +
			sqlite_quote(journal.topology_uuid) + "," + sqlite_quote(journal.router_name) + "," +
			sqlite_quote(phase_name(journal.phase)) + "," + std::to_string(journal.router_id) + "," +
			sqlite_quote(journal.metadata_user) + ",strftime('%s','now')," + sqlite_quote(journal.last_error) + ") "
			"ON CONFLICT(topology_uuid) DO UPDATE SET router_name=excluded.router_name,phase=excluded.phase,"
			"router_id=excluded.router_id,metadata_user=excluded.metadata_user,updated_at=excluded.updated_at,"
			"last_error=excluded.last_error";
		if (!db_->execute(sql.c_str())) throw std::runtime_error("failed to persist bootstrap journal");
	}

	void put_secret(std::string_view name, const std::vector<uint8_t>& value) override {
		auto result = services_.put_secret("mysql_router", std::string(name).c_str(),
			value.data(), value.size());
		if (result != ProxySQL_PluginSecretResult::ok) {
			throw std::runtime_error("failed to persist encrypted metadata credential (secret service result " +
				std::to_string(static_cast<unsigned>(result)) + ")");
		}
	}

	std::optional<std::vector<uint8_t>> get_secret(std::string_view name) override {
		std::vector<uint8_t> value;
		auto result = services_.get_secret("mysql_router", std::string(name).c_str(), value);
		if (result == ProxySQL_PluginSecretResult::not_found) return std::nullopt;
		if (result != ProxySQL_PluginSecretResult::ok) {
			throw std::runtime_error("failed to read encrypted metadata credential (secret service result " +
				std::to_string(static_cast<unsigned>(result)) + ")");
		}
		return value;
	}

	uint64_t publish_topology(const DesiredTopology& topology,
		const ListenerProfile& listeners, uint64_t generation) override;
	uint64_t publish_users(const DesiredTopology& topology,
		const ListenerProfile& listeners, const AccountSnapshot& snapshot,
		std::string_view metadata_user, uint64_t generation) override;
	uint64_t publish_topology_snapshot(const DesiredTopology& topology,
		const EffectiveTopology& effective, const ListenerProfile& listeners,
		uint64_t generation);
	uint64_t publish_users_snapshot(const DesiredTopology& topology,
		const EffectiveTopology& effective, const ListenerProfile& listeners,
		const AccountSnapshot& snapshot, std::string_view metadata_user,
		uint64_t generation);

	void save_complete(const BootstrapIdentity& identity,
		const ListenerProfile& listeners) override {
		if (!db_->execute("BEGIN IMMEDIATE")) throw std::runtime_error("failed to begin local bootstrap commit");
		const std::string instance = "INSERT INTO mysql_router_instance"
			"(singleton_id,topology_type,topology_uuid,cluster_id,clusterset_id,router_id,router_name,router_address,"
			"metadata_user,metadata_host,metadata_port,metadata_schema,advertised_version,topology_generation,user_generation) "
			"VALUES(1,'innodb_cluster'," +
			sqlite_quote(identity.topology_uuid) + "," + sqlite_quote(identity.topology_uuid) + ",NULL," +
			std::to_string(identity.router_id) + "," + sqlite_quote(identity.router_name) + "," +
			sqlite_quote(identity.router_address) + "," + sqlite_quote(identity.metadata_user) + "," +
			sqlite_quote(identity.metadata_host) + "," + std::to_string(identity.metadata_port) +
			",'2.2','8.4.0'," + std::to_string(identity.topology_generation) + "," +
			std::to_string(identity.user_generation) + ") "
			"ON CONFLICT(singleton_id) DO UPDATE SET topology_type=excluded.topology_type,topology_uuid=excluded.topology_uuid,"
			"cluster_id=excluded.cluster_id,clusterset_id=NULL,router_id=excluded.router_id,router_name=excluded.router_name,"
			"router_address=excluded.router_address,metadata_user=excluded.metadata_user,metadata_host=excluded.metadata_host,"
			"metadata_port=excluded.metadata_port,metadata_schema=excluded.metadata_schema,"
			"advertised_version=excluded.advertised_version,topology_generation=excluded.topology_generation,"
			"user_generation=excluded.user_generation";
		bool ok = db_->execute(instance.c_str());
		for (const auto& item : std::array<std::pair<const char*, std::string>, 4>{{
			{"bind_address", listeners.bind_address}, {"rw_port", std::to_string(listeners.rw_port)},
			{"ro_port", std::to_string(listeners.ro_port)},
			{"rw_split_port", std::to_string(listeners.rw_split_port)}}}) {
			const std::string config = "INSERT INTO mysql_router_config(config_key,config_value) VALUES(" +
				sqlite_quote(item.first) + "," + sqlite_quote(item.second) + ") ON CONFLICT(config_key) "
				"DO UPDATE SET config_value=excluded.config_value";
			ok = ok && db_->execute(config.c_str());
		}
		if (!ok || !db_->execute("COMMIT")) {
			db_->execute("ROLLBACK");
			throw std::runtime_error("failed to persist local Router bootstrap state");
		}
	}

private:
	uint64_t publish_generation(const DesiredTopology& topology,
		const EffectiveTopology& effective,
		const ListenerProfile& listeners, uint64_t generation,
		const std::vector<ManagedMysqlUser>& users);
	ProxySQL_PluginServices& services_;
	IMetadataSession& session_;
	SQLite3DB* db_;
	std::optional<EffectiveTopology> last_effective_;
};

uint64_t PluginBootstrapStore::publish_generation(const DesiredTopology& topology,
	const EffectiveTopology& effective, const ListenerProfile& listeners, uint64_t generation,
	const std::vector<ManagedMysqlUser>& users) {
	if (services_.apply_mysql_config_v2 == nullptr || services_.set_listener_gate == nullptr ||
		services_.get_mysql_servers_snapshot == nullptr ||
		services_.get_mysql_group_replication_hostgroups_snapshot == nullptr ||
		services_.get_admindb == nullptr) {
		throw std::runtime_error("native MySQL configuration services are unavailable");
	}
	SQLite3DB* admindb = services_.get_admindb();
	if (admindb == nullptr) throw std::runtime_error("Admin DB is unavailable during bootstrap");

	HostgroupAllocationInput allocation;
	std::unique_ptr<SQLite3_result> servers(services_.get_mysql_servers_snapshot());
	std::unique_ptr<SQLite3_result> gr(services_.get_mysql_group_replication_hostgroups_snapshot());
	if (!servers || !gr) throw std::runtime_error("cannot capture live hostgroup inventory");
	collect_snapshot_column(*servers, "hostgroup_id", allocation.occupied_hostgroups);
	for (const char* column : {"writer_hostgroup", "backup_writer_hostgroup",
		"reader_hostgroup", "offline_hostgroup"}) {
		collect_snapshot_column(*gr, column, allocation.occupied_hostgroups);
	}
	for (const std::string& sql : {
		"SELECT hostgroup_id FROM mysql_servers",
		"SELECT writer_hostgroup FROM mysql_replication_hostgroups UNION SELECT reader_hostgroup FROM mysql_replication_hostgroups",
		"SELECT writer_hostgroup FROM mysql_group_replication_hostgroups UNION SELECT backup_writer_hostgroup FROM mysql_group_replication_hostgroups UNION SELECT reader_hostgroup FROM mysql_group_replication_hostgroups UNION SELECT offline_hostgroup FROM mysql_group_replication_hostgroups",
		"SELECT writer_hostgroup FROM mysql_galera_hostgroups UNION SELECT backup_writer_hostgroup FROM mysql_galera_hostgroups UNION SELECT reader_hostgroup FROM mysql_galera_hostgroups UNION SELECT offline_hostgroup FROM mysql_galera_hostgroups",
		"SELECT writer_hostgroup FROM mysql_aws_aurora_hostgroups UNION SELECT reader_hostgroup FROM mysql_aws_aurora_hostgroups",
		"SELECT writer_hostgroup FROM mysql_aws_rds_bgd_hostgroups UNION SELECT reader_hostgroup FROM mysql_aws_rds_bgd_hostgroups UNION SELECT green_writer_hostgroup FROM mysql_aws_rds_bgd_hostgroups UNION SELECT green_reader_hostgroup FROM mysql_aws_rds_bgd_hostgroups",
	}) {
		collect_query_column(*db_, sql, allocation.occupied_hostgroups);
		collect_query_column(*admindb, sql, allocation.occupied_hostgroups);
	}
	ManagedHostgroups hostgroups = HostgroupAllocator::load_or_allocate(
		*db_, topology.topology_uuid, allocation);

	uint64_t current_generation = 0;
	for (SQLite3DB* database : {db_, admindb}) {
		auto rows = local_query(*database,
			"SELECT generation FROM proxysql_plugin_config_generations WHERE owner='mysql_router'");
		if (!rows->rows.empty()) {
			current_generation = std::max<uint64_t>(current_generation,
				static_cast<uint64_t>(local_int64(rows->rows[0]->fields[0], "active generation")));
		}
	}
	if (current_generation == static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
		throw std::runtime_error("Router topology generation is exhausted");
	}
	const uint64_t publish_generation = current_generation == 0
		? generation : current_generation + 1;
	ConfigCompileInput input;
	input.generation = publish_generation;
	input.listeners = listeners;
	input.users = users;
	collect_query_column(*db_, "SELECT rule_id FROM mysql_query_rules", input.occupied_rule_ids);
	collect_query_column(*admindb, "SELECT rule_id FROM mysql_query_rules", input.occupied_rule_ids);
	auto owned_rules = local_query(*db_,
		"SELECT object_key FROM proxysql_plugin_owned_objects WHERE owner='mysql_router' "
		"AND object_type='mysql_query_rule' ORDER BY CAST(object_key AS INTEGER)");
	if (!owned_rules->rows.empty()) {
		if (owned_rules->rows.size() != mysql_router_rule_intents().size()) {
			throw std::runtime_error("persisted baseline query rule mapping is incomplete");
		}
		for (size_t i = 0; i < owned_rules->rows.size(); ++i) {
			input.owned_rule_ids.emplace(mysql_router_rule_intents()[i],
				static_cast<int>(local_int64(owned_rules->rows[i]->fields[0], "owned rule ID")));
		}
	}
	auto interfaces = local_query(*admindb,
		"SELECT variable_value FROM global_variables WHERE variable_name='mysql-interfaces'");
	if (!interfaces->rows.empty() && interfaces->rows[0]->fields[0]) {
		input.operator_interfaces = split_interfaces(interfaces->rows[0]->fields[0]);
	}

	CompiledMysqlConfig config = ConfigCompiler::compile_topology(
		topology, effective, hostgroups, input);
	for (const std::string& endpoint : config.interfaces) {
		const size_t colon = endpoint.rfind(':');
		if (colon == std::string::npos) throw std::runtime_error("compiled listener endpoint is invalid");
		const std::string address = endpoint.substr(0, colon);
		const uint16_t port = static_cast<uint16_t>(std::stoul(endpoint.substr(colon + 1)));
		const ProxySQL_PluginListenerGate gate {"mysql_router", address.c_str(), port,
			ProxySQL_PluginListenerState::closed, "waiting for initial Router generation"};
		if (!services_.set_listener_gate(gate)) {
			throw std::runtime_error("cannot close Router listener gate before publication");
		}
	}
	const ProxySQL_PluginMysqlConfigResult published = services_.apply_mysql_config_v2(config.plan_v2());
	if (!published.applied || published.generation != publish_generation) {
		throw std::runtime_error(published.message.empty()
			? "initial Router generation publication failed" : published.message);
	}
	return published.generation;
}

uint64_t PluginBootstrapStore::publish_topology(const DesiredTopology& topology,
	const ListenerProfile& listeners, uint64_t generation) {
	ObservedHealth health = GrHealthReader::read(session_);
	last_effective_ = evaluate_innodb_cluster(topology, health);
	return publish_topology_snapshot(topology, *last_effective_, listeners, generation);
}

uint64_t PluginBootstrapStore::publish_topology_snapshot(const DesiredTopology& topology,
	const EffectiveTopology& effective, const ListenerProfile& listeners, uint64_t generation) {
	SQLite3DB* admindb = services_.get_admindb ? services_.get_admindb() : nullptr;
	if (admindb == nullptr) throw std::runtime_error("Admin DB is unavailable during topology publication");
	std::vector<ManagedMysqlUser> preserved;
	for (const CurrentMysqlUser& current : current_mysql_users(*admindb)) {
		if (!current.owned) continue;
		ManagedMysqlUser user;
		static_cast<CurrentMysqlUser&>(user) = current;
		preserved.push_back(std::move(user));
	}
	return publish_generation(topology, effective, listeners, generation, preserved);
}

uint64_t PluginBootstrapStore::publish_users(const DesiredTopology& topology,
	const ListenerProfile& listeners, const AccountSnapshot& snapshot,
	std::string_view, uint64_t generation) {
	if (!last_effective_) {
		ObservedHealth health = GrHealthReader::read(session_);
		last_effective_ = evaluate_innodb_cluster(topology, health);
	}
	return publish_users_snapshot(topology, *last_effective_, listeners, snapshot, {}, generation);
}

uint64_t PluginBootstrapStore::publish_users_snapshot(const DesiredTopology& topology,
	const EffectiveTopology& effective, const ListenerProfile& listeners,
	const AccountSnapshot& snapshot, std::string_view, uint64_t generation) {
	SQLite3DB* admindb = services_.get_admindb ? services_.get_admindb() : nullptr;
	if (admindb == nullptr) throw std::runtime_error("Admin DB is unavailable during user synchronization");
	UserSyncInput input;
	input.topology_uuid = topology.topology_uuid;
	auto writer = local_query(*db_,
		"SELECT hostgroup_id FROM mysql_router_hostgroups WHERE scope_uuid=" +
		sqlite_quote(topology.topology_uuid) + " AND role='route_writer'");
	if (writer->rows.size() != 1) throw std::runtime_error("stable writer hostgroup is unavailable");
	input.route_writer_hostgroup = static_cast<int>(
		local_int64(writer->rows[0]->fields[0], "route writer hostgroup"));
	input.current_users = current_mysql_users(*admindb);
	input.persisted = persisted_mysql_router_users(*db_);
	ManagedUserGeneration normalized = UserSynchronizer::normalize(snapshot, input);
	const uint64_t published = publish_generation(
		topology, effective, listeners, generation, normalized.users);
	persist_mysql_router_users(*admindb, published, normalized.status);
	return published;
}

} // namespace

BootstrapResult run_mysql_router_bootstrap(
	const BootstrapOptions& options, IMetadataSession& session,
	DesiredTopology topology, std::string router_address,
	ProxySQL_PluginServices& services) {
	PluginBootstrapStore store(services, session);
	return MysqlRouterBootstrap(session, store, std::move(topology),
		std::move(router_address)).run(options);
}

uint64_t publish_mysql_router_topology(ProxySQL_PluginServices& services,
	IMetadataSession& session, const DesiredTopology& topology,
	const EffectiveTopology& effective, const ListenerProfile& listeners,
	uint64_t generation) {
	PluginBootstrapStore store(services, session);
	return store.publish_topology_snapshot(topology, effective, listeners, generation);
}

uint64_t publish_mysql_router_users(ProxySQL_PluginServices& services,
	IMetadataSession& session, const DesiredTopology& topology,
	const EffectiveTopology& effective, const ListenerProfile& listeners,
	const AccountSnapshot& snapshot, std::string_view metadata_user,
	uint64_t generation) {
	PluginBootstrapStore store(services, session);
	return store.publish_users_snapshot(
		topology, effective, listeners, snapshot, metadata_user, generation);
}

#endif
