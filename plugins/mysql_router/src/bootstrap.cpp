#include "mysql_router_bootstrap.h"

#include "mysql_router_metadata.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <random>
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

		const std::string secret_name = "metadata:" + topology_.topology_uuid;
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

		BootstrapIdentity completed {topology_.topology_uuid, topology_.topology_name,
			registration.router_id, options.router_name, router_address_, metadata_user,
			options.seed.host, options.seed.port};
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

class PluginBootstrapStore final : public IBootstrapStore {
public:
	explicit PluginBootstrapStore(ProxySQL_PluginServices& services)
		: services_(services), db_(services.get_configdb ? services.get_configdb() : nullptr) {
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
			"SELECT topology_uuid,router_id,router_name,router_address,metadata_user,metadata_host,metadata_port "
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
			throw std::runtime_error("failed to persist encrypted metadata credential");
		}
	}

	std::optional<std::vector<uint8_t>> get_secret(std::string_view name) override {
		std::vector<uint8_t> value;
		auto result = services_.get_secret("mysql_router", std::string(name).c_str(), value);
		if (result == ProxySQL_PluginSecretResult::not_found) return std::nullopt;
		if (result != ProxySQL_PluginSecretResult::ok) {
			throw std::runtime_error("failed to read encrypted metadata credential");
		}
		return value;
	}

	void save_complete(const BootstrapIdentity& identity,
		const ListenerProfile& listeners) override {
		if (!db_->execute("BEGIN IMMEDIATE")) throw std::runtime_error("failed to begin local bootstrap commit");
		const std::string instance = "INSERT INTO mysql_router_instance"
			"(singleton_id,topology_type,topology_uuid,cluster_id,clusterset_id,router_id,router_name,router_address,"
			"metadata_user,metadata_host,metadata_port,metadata_schema,advertised_version) VALUES(1,'innodb_cluster'," +
			sqlite_quote(identity.topology_uuid) + "," + sqlite_quote(identity.topology_uuid) + ",NULL," +
			std::to_string(identity.router_id) + "," + sqlite_quote(identity.router_name) + "," +
			sqlite_quote(identity.router_address) + "," + sqlite_quote(identity.metadata_user) + "," +
			sqlite_quote(identity.metadata_host) + "," + std::to_string(identity.metadata_port) + ",'2.2','8.4.0') "
			"ON CONFLICT(singleton_id) DO UPDATE SET topology_type=excluded.topology_type,topology_uuid=excluded.topology_uuid,"
			"cluster_id=excluded.cluster_id,clusterset_id=NULL,router_id=excluded.router_id,router_name=excluded.router_name,"
			"router_address=excluded.router_address,metadata_user=excluded.metadata_user,metadata_host=excluded.metadata_host,"
			"metadata_port=excluded.metadata_port,metadata_schema=excluded.metadata_schema,advertised_version=excluded.advertised_version";
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
	ProxySQL_PluginServices& services_;
	SQLite3DB* db_;
};

} // namespace

BootstrapResult run_mysql_router_bootstrap(
	const BootstrapOptions& options, IMetadataSession& session,
	DesiredTopology topology, std::string router_address,
	ProxySQL_PluginServices& services) {
	PluginBootstrapStore store(services);
	return MysqlRouterBootstrap(session, store, std::move(topology),
		std::move(router_address)).run(options);
}

#endif
