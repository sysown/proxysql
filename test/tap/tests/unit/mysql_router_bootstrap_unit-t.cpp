#include "tap.h"

#include "mysql_router_bootstrap.h"
#include "mysql_router_metadata.h"
#include "mysql_router_users.h"

#include <algorithm>
#include <optional>
#include <stdexcept>

namespace {

QueryRow row(std::initializer_list<std::pair<const std::string, SqlCell>> cells) {
	return QueryRow(cells);
}

class BootstrapSession final : public IMetadataSession {
public:
	bool router_exists {false};
	bool account_exists {false};
	std::string account_plugin {"caching_sha2_password"};
	bool complete_grants {true};
	unsigned router_inserts {0};
	unsigned account_creates {0};
	unsigned rejected_passwords {0};
	unsigned account_alters {0};
	unsigned registration_updates {0};
	unsigned grants {0};
	std::vector<std::string> mutations;

	QueryResult query(std::string_view sql, const std::vector<SqlValue>&) override {
		if (sql.find("FROM mysql_innodb_cluster_metadata.v2_routers") != std::string_view::npos) {
			return router_exists ? QueryResult{{row({{"router_id", "17"}, {"options", "{\"shell\":true}"}})}} : QueryResult{};
		}
		if (sql.find("LAST_INSERT_ID") != std::string_view::npos) {
			return {{row({{"router_id", "17"}})}};
		}
		if (sql.find("ORDER BY User,Host") != std::string_view::npos) {
			return {{row({{"User", "app"}, {"Host", "%"},
				{"plugin", "caching_sha2_password"}, {"authentication_string", "$A$005$app"},
				{"account_locked", "N"}, {"password_expired", "N"}, {"ssl_type", ""}})}};
		}
		if (sql.find("FROM mysql.user") != std::string_view::npos) {
			return account_exists ? QueryResult{{row({{"User", "mysql_router17_abcdefghijkl"},
				{"Host", "%"}, {"plugin", account_plugin}})}} : QueryResult{};
		}
		if (sql.find("SHOW GRANTS") != std::string_view::npos) {
			QueryResult grants {{
				row({{"grant", "GRANT SELECT, EXECUTE ON `mysql_innodb_cluster_metadata`.*"}}),
				row({{"grant", "GRANT UPDATE ON `mysql_innodb_cluster_metadata`.`clusters`"}}),
				row({{"grant", "GRANT UPDATE ON `mysql_innodb_cluster_metadata`.`clustersets`"}}),
				row({{"grant", "GRANT INSERT, UPDATE, DELETE ON `mysql_innodb_cluster_metadata`.`routers`"}}),
				row({{"grant", "GRANT UPDATE ON `mysql_innodb_cluster_metadata`.`v2_ar_clusters`"}}),
				row({{"grant", "GRANT UPDATE ON `mysql_innodb_cluster_metadata`.`v2_cs_clustersets`"}}),
				row({{"grant", "GRANT UPDATE ON `mysql_innodb_cluster_metadata`.`v2_gr_clusters`"}}),
				row({{"grant", "GRANT INSERT, UPDATE, DELETE ON `mysql_innodb_cluster_metadata`.`v2_routers`"}}),
				row({{"grant", "GRANT SELECT ON `performance_schema`.`replication_group_members`"}}),
				row({{"grant", "GRANT SELECT ON `performance_schema`.`replication_group_member_stats`"}}),
				row({{"grant", "GRANT SELECT ON `performance_schema`.`global_variables`"}}),
				row({{"grant", "GRANT SELECT (USER, HOST, PLUGIN, AUTHENTICATION_STRING, ACCOUNT_LOCKED, PASSWORD_EXPIRED, SSL_TYPE) ON `mysql`.`user`"}})
			}};
			if (!complete_grants) grants.rows.pop_back();
			return grants;
		}
		throw std::runtime_error("unexpected bootstrap query");
	}

	ExecResult execute(std::string_view sql, const std::vector<SqlValue>&) override {
		mutations.emplace_back(sql);
		if (sql.find("INSERT INTO mysql_innodb_cluster_metadata.v2_routers") != std::string_view::npos) {
			router_exists = true;
			++router_inserts;
		} else if (sql.find("UPDATE mysql_innodb_cluster_metadata.v2_routers") != std::string_view::npos) {
			++registration_updates;
		} else if (sql.find("CREATE USER") != std::string_view::npos) {
			++account_creates;
			if (rejected_passwords != 0) {
				--rejected_passwords;
				return {false, 0, "password policy rejected generated password"};
			}
			account_exists = true;
		} else if (sql.find("ALTER USER") != std::string_view::npos) {
			++account_alters;
		} else if (sql.find("GRANT ") != std::string_view::npos) {
			++grants;
		} else if (sql.find("SET TRANSACTION") != std::string_view::npos ||
			   sql.find("START TRANSACTION") != std::string_view::npos || sql == "COMMIT" ||
			   sql == "ROLLBACK") {
		} else {
			return {false, 0, "unexpected bootstrap execute"};
		}
		return {true, 1, {}};
	}

	ServerVersion server_version() const override { return {8, 4, 6}; }
	std::string quote_sql_string(std::string_view value) const override {
		return "'" + std::string(value) + "'";
	}
};

class MemoryBootstrapStore final : public IBootstrapStore {
public:
	std::optional<BootstrapJournal> journal;
	std::optional<BootstrapIdentity> identity;
	std::vector<uint8_t> secret;
	unsigned complete_writes {0};
	unsigned publications {0};
	unsigned user_publications {0};
	bool fail_publication {false};

	std::optional<BootstrapJournal> load_journal(std::string_view topology_uuid) override {
		return journal && journal->topology_uuid == topology_uuid
			? journal : std::nullopt;
	}
	std::optional<BootstrapIdentity> load_identity() override { return identity; }
	void save_journal(const BootstrapJournal& value) override { journal = value; }
	void put_secret(std::string_view, const std::vector<uint8_t>& value) override { secret = value; }
	std::optional<std::vector<uint8_t>> get_secret(std::string_view) override {
		return secret.empty() ? std::nullopt : std::optional<std::vector<uint8_t>>(secret);
	}
	uint64_t publish_topology(const DesiredTopology&, const ListenerProfile&, uint64_t generation) override {
		if (fail_publication) throw std::runtime_error("injected topology publication failure");
		if (generation != publications + user_publications + 1) {
			throw std::runtime_error("unexpected bootstrap generation");
		}
		++publications;
		return publications + user_publications;
	}
	uint64_t publish_users(const DesiredTopology&, const ListenerProfile&,
		const AccountSnapshot& snapshot, std::string_view metadata_user,
		uint64_t generation) override {
		if (snapshot.accounts.size() != 1 || snapshot.accounts[0].username != "app" ||
			metadata_user.empty() || generation != publications + user_publications + 1) {
			throw std::runtime_error("unexpected user publication input");
		}
		++user_publications;
		return publications + user_publications;
	}
	void save_complete(const BootstrapIdentity& value, const ListenerProfile&) override {
		identity = value;
		++complete_writes;
	}
};

DesiredTopology topology(std::string uuid = "cluster-1") {
	DesiredTopology result;
	result.metadata_version = {2, 2, 0};
	result.topology_uuid = std::move(uuid);
	result.topology_name = "production";
	return result;
}

BootstrapOptions options() {
	BootstrapOptions result;
	result.requested = true;
	result.router_name = "proxysql-east";
	result.account_host = "%";
	return result;
}

ProxySQL_PluginMysqlConfigResult available_v1_publisher(
	const ProxySQL_PluginMysqlConfigPlan&) {
	return {true, 1, "V1 publisher should not be called", {}};
}

} // namespace

int main() {
	plan(27);

	BootstrapSession session;
	MemoryBootstrapStore store;
	ProxySQL_PluginServices v1_only_services {};
	v1_only_services.apply_mysql_config = &available_v1_publisher;
	bool v2_required = false;
	std::string v2_error;
	try {
		(void)publish_mysql_router_topology(v1_only_services, session, topology(),
			EffectiveTopology {}, ListenerProfile {}, 1);
	} catch (const std::runtime_error& error) {
		v2_error = error.what();
		v2_required = v2_error ==
			"native MySQL configuration services are unavailable";
	}
	ok(v2_required, "Router publication rejects a service table whose V1 publisher exists but V2 is absent: %s",
		v2_error.c_str());
	MysqlRouterBootstrap bootstrap(session, store, topology(), "proxy.example");
	auto first = bootstrap.run(options());
	ok(first.success && first.router_id == 17, "a first bootstrap completes with the assigned router id");
	ok(session.router_inserts == 1, "the Router registration is inserted exactly once");
	ok(session.grants == 10, "the complete InnoDB Cluster grant set is applied without ClusterSet views");
	ok(first.metadata_user.rfind("mysql_router17_", 0) == 0 && first.metadata_user.size() == 27,
	   "an omitted account name derives from router id plus twelve lowercase characters");
	ok(store.secret.size() == 32, "the generated service password is persisted as 32 bytes");
	ok(store.journal && store.journal->phase == BootstrapPhase::complete,
	   "the resumable journal reaches complete only after local persistence");
	ok(store.identity && store.identity->topology_uuid == "cluster-1" &&
	   store.identity->metadata_user == first.metadata_user,
	   "local identity records topology and metadata account");
	ok(store.publications == 1 && store.user_publications == 1 && store.complete_writes == 1 &&
	   store.identity && store.identity->topology_generation == 1 &&
	   store.identity->user_generation == 2,
	   "topology generation 1 and user generation 2 publish before local identity commit");
	ok(store.identity && store.identity->user_generation > store.identity->topology_generation,
	   "application users publish as a separate complete generation");

	MysqlRouterBootstrap retry(session, store, topology(), "proxy.example");
	auto second = retry.run(options());
	ok(second.success && second.metadata_user == first.metadata_user,
	   "a completed bootstrap is safely resumable with the same account");
	ok(session.router_inserts == 1 && session.account_creates == 1,
	   "retry converges to one registration and one account");
	ok(session.registration_updates == 3,
	   "retry refreshes Shell-visible attributes without adding registrations");
	ok(store.secret.size() == 32 && store.complete_writes == 2 &&
	   store.identity && store.identity->topology_generation == 3 &&
	   store.identity->user_generation == 4,
	   "retry preserves the encrypted credential and idempotently persists local state");

	MemoryBootstrapStore conflicting_store = store;
	BootstrapSession conflicting_session = session;
	MysqlRouterBootstrap conflicting(conflicting_session, conflicting_store,
		topology("cluster-2"), "proxy.example");
	auto rejected = conflicting.run(options());
	ok(!rejected.success && rejected.error.find("replace-topology") != std::string::npos,
	   "a persisted topology mismatch requires --replace-topology");
	ok(conflicting_session.registration_updates == session.registration_updates,
	   "topology mismatch fails before any remote mutation");
	auto replacement_options = options();
	replacement_options.replace_topology = true;
	auto replaced = conflicting.run(replacement_options);
	ok(replaced.success && conflicting_store.identity->topology_uuid == "cluster-2",
	   "explicit topology replacement converges on the new topology");

	BootstrapSession always_session;
	always_session.router_exists = true;
	always_session.account_exists = true;
	MemoryBootstrapStore always_store;
	auto always_options = options();
	always_options.service_account = "existing_router";
	always_options.account_create = AccountCreatePolicy::always;
	auto always = MysqlRouterBootstrap(always_session, always_store, topology(),
		"proxy.example").run(always_options);
	ok(!always.success && always.error.find("already exists") != std::string::npos,
	   "--account-create=always fails if the requested account exists");

	BootstrapSession never_session;
	never_session.router_exists = true;
	MemoryBootstrapStore never_store;
	auto never_options = options();
	never_options.service_account = "missing_router";
	never_options.account_create = AccountCreatePolicy::never;
	auto never = MysqlRouterBootstrap(never_session, never_store, topology(),
		"proxy.example").run(never_options);
	ok(!never.success && never.error.find("account is absent") != std::string::npos,
	   "--account-create=never fails if the requested account is absent");

	BootstrapSession plugin_session;
	plugin_session.router_exists = true;
	plugin_session.account_exists = true;
	plugin_session.account_plugin = "mysql_native_password";
	MemoryBootstrapStore plugin_store;
	auto reuse_options = options();
	reuse_options.service_account = "legacy_router";
	auto wrong_plugin = MysqlRouterBootstrap(plugin_session, plugin_store, topology(),
		"proxy.example").run(reuse_options);
	ok(!wrong_plugin.success && wrong_plugin.error.find("caching_sha2_password") != std::string::npos,
	   "reusing an account with the wrong authentication plugin fails closed");

	BootstrapSession grants_session;
	grants_session.router_exists = true;
	grants_session.account_exists = true;
	grants_session.complete_grants = false;
	MemoryBootstrapStore grants_store;
	grants_store.secret.assign(32, 'x');
	auto missing_grants = MysqlRouterBootstrap(grants_session, grants_store, topology(),
		"proxy.example").run(reuse_options);
	ok(!missing_grants.success && missing_grants.error.find("required grants") != std::string::npos,
	   "reusing an account with incomplete grants fails closed");

	BootstrapSession unnamed_secret_session;
	unnamed_secret_session.router_exists = true;
	unnamed_secret_session.account_exists = true;
	MemoryBootstrapStore unnamed_secret_store;
	auto unnamed_secret = MysqlRouterBootstrap(unnamed_secret_session, unnamed_secret_store,
		topology(), "proxy.example").run(reuse_options);
	ok(!unnamed_secret.success && unnamed_secret.error.find("no persisted credential") !=
	   std::string::npos && unnamed_secret_session.registration_updates == 0,
	   "an existing named account without a persisted credential fails before registration mutation");

	BootstrapSession explicit_session;
	MemoryBootstrapStore explicit_store;
	auto explicit_options = options();
	explicit_options.service_account = "new_router_account";
	auto explicit_result = MysqlRouterBootstrap(explicit_session, explicit_store, topology(),
		"proxy.example").run(explicit_options);
	auto account_mutation = std::find_if(explicit_session.mutations.begin(),
		explicit_session.mutations.end(), [](const std::string& sql) {
			return sql.find("CREATE USER") != std::string::npos;
		});
	auto registration_mutation = std::find_if(explicit_session.mutations.begin(),
		explicit_session.mutations.end(), [](const std::string& sql) {
			return sql.find("INSERT INTO mysql_innodb_cluster_metadata.v2_routers") != std::string::npos;
		});
	ok(explicit_result.success && account_mutation != explicit_session.mutations.end() &&
	   registration_mutation != explicit_session.mutations.end() &&
	   account_mutation < registration_mutation,
	   "an explicit metadata account is created before its Router registration is published");

	BootstrapSession password_policy_session;
	password_policy_session.rejected_passwords = 2;
	MemoryBootstrapStore password_policy_store;
	auto password_policy_options = options();
	password_policy_options.password_retries = 2;
	auto password_policy_result = MysqlRouterBootstrap(password_policy_session,
		password_policy_store, topology(), "proxy.example").run(password_policy_options);
	ok(password_policy_result.success && password_policy_session.account_creates == 3,
	   "password-retries regenerates a rejected service-account password before succeeding");

	BootstrapSession interrupted_session;
	interrupted_session.router_exists = true;
	interrupted_session.account_exists = true;
	MemoryBootstrapStore interrupted_store;
	interrupted_store.journal = BootstrapJournal {"cluster-1", "proxysql-east",
		BootstrapPhase::discovered, 17, "mysql_router17_abcdefghijkl", {}};
	auto resumed = MysqlRouterBootstrap(interrupted_session, interrupted_store, topology(),
		"proxy.example").run(options());
	ok(resumed.success && interrupted_session.account_alters == 1 &&
	   interrupted_session.grants == 10 && interrupted_store.secret.size() == 32,
	   "retry recovers a plugin-generated account interrupted before secret persistence");

	BootstrapSession publication_session;
	MemoryBootstrapStore publication_store;
	publication_store.fail_publication = true;
	auto publication = MysqlRouterBootstrap(publication_session, publication_store, topology(),
		"proxy.example").run(options());
	ok(!publication.success && publication.error.find("publication failure") != std::string::npos,
	   "a generation-1 publisher failure aborts bootstrap");
	ok(publication_store.complete_writes == 0 && publication_store.journal &&
	   publication_store.journal->phase == BootstrapPhase::registered,
	   "publisher failure leaves local configuration uncommitted and the journal resumable");

	return exit_status();
}
