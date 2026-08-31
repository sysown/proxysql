#include "tap.h"

#include "mysql_router_bootstrap.h"
#include "mysql_router_metadata.h"

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
	unsigned account_alters {0};
	unsigned registration_updates {0};
	unsigned grants {0};

	QueryResult query(std::string_view sql, const std::vector<SqlValue>&) override {
		if (sql.find("FROM mysql_innodb_cluster_metadata.v2_routers") != std::string_view::npos) {
			return router_exists ? QueryResult{{row({{"router_id", "17"}, {"options", "{\"shell\":true}"}})}} : QueryResult{};
		}
		if (sql.find("LAST_INSERT_ID") != std::string_view::npos) {
			return {{row({{"router_id", "17"}})}};
		}
		if (sql.find("FROM mysql.user") != std::string_view::npos) {
			return account_exists ? QueryResult{{row({{"User", "mysql_router17_abcdefghijkl"},
				{"Host", "%"}, {"plugin", account_plugin}})}} : QueryResult{};
		}
		if (sql.find("SHOW GRANTS") != std::string_view::npos) {
			QueryResult grants {{
				row({{"grant", "GRANT SELECT, EXECUTE ON `mysql_innodb_cluster_metadata`.*"}}),
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
		if (sql.find("INSERT INTO mysql_innodb_cluster_metadata.v2_routers") != std::string_view::npos) {
			router_exists = true;
			++router_inserts;
		} else if (sql.find("UPDATE mysql_innodb_cluster_metadata.v2_routers") != std::string_view::npos) {
			++registration_updates;
		} else if (sql.find("CREATE USER") != std::string_view::npos) {
			account_exists = true;
			++account_creates;
		} else if (sql.find("ALTER USER") != std::string_view::npos) {
			++account_alters;
		} else if (sql.find("GRANT ") != std::string_view::npos) {
			++grants;
		} else {
			return {false, 0, "unexpected bootstrap execute"};
		}
		return {true, 1, {}};
	}

	ServerVersion server_version() const override { return {8, 4, 6}; }
};

class MemoryBootstrapStore final : public IBootstrapStore {
public:
	std::optional<BootstrapJournal> journal;
	std::optional<BootstrapIdentity> identity;
	std::vector<uint8_t> secret;
	unsigned complete_writes {0};
	unsigned publications {0};
	bool fail_publication {false};

	std::optional<BootstrapJournal> load_journal(std::string_view) override { return journal; }
	std::optional<BootstrapIdentity> load_identity() override { return identity; }
	void save_journal(const BootstrapJournal& value) override { journal = value; }
	void put_secret(std::string_view, const std::vector<uint8_t>& value) override { secret = value; }
	std::optional<std::vector<uint8_t>> get_secret(std::string_view) override {
		return secret.empty() ? std::nullopt : std::optional<std::vector<uint8_t>>(secret);
	}
	uint64_t publish_topology(const DesiredTopology&, const ListenerProfile&, uint64_t generation) override {
		if (fail_publication) throw std::runtime_error("injected topology publication failure");
		if (generation != 1) throw std::runtime_error("unexpected bootstrap generation");
		++publications;
		return publications;
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

} // namespace

int main() {
	plan(23);

	BootstrapSession session;
	MemoryBootstrapStore store;
	MysqlRouterBootstrap bootstrap(session, store, topology(), "proxy.example");
	auto first = bootstrap.run(options());
	ok(first.success && first.router_id == 17, "a first bootstrap completes with the assigned router id");
	ok(session.router_inserts == 1, "the Router registration is inserted exactly once");
	ok(session.account_creates == 1 && session.account_exists, "one metadata service account is created");
	ok(session.grants == 6, "the complete least-privilege grant set is applied");
	ok(first.metadata_user.rfind("mysql_router17_", 0) == 0 && first.metadata_user.size() == 27,
	   "an omitted account name derives from router id plus twelve lowercase characters");
	ok(store.secret.size() == 32, "the generated service password is persisted as 32 bytes");
	ok(store.journal && store.journal->phase == BootstrapPhase::complete,
	   "the resumable journal reaches complete only after local persistence");
	ok(store.identity && store.identity->topology_uuid == "cluster-1" &&
	   store.identity->metadata_user == first.metadata_user,
	   "local identity records topology and metadata account");
	ok(store.publications == 1 && store.complete_writes == 1 &&
	   store.identity && store.identity->topology_generation == 1,
	   "generation 1 publishes before local identity and listener configuration commit");

	MysqlRouterBootstrap retry(session, store, topology(), "proxy.example");
	auto second = retry.run(options());
	ok(second.success && second.metadata_user == first.metadata_user,
	   "a completed bootstrap is safely resumable with the same account");
	ok(session.router_inserts == 1 && session.account_creates == 1,
	   "retry converges to one registration and one account");
	ok(session.registration_updates == 3,
	   "retry refreshes Shell-visible attributes without adding registrations");
	ok(store.secret.size() == 32 && store.complete_writes == 2 &&
	   store.identity && store.identity->topology_generation == 2,
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
	auto missing_grants = MysqlRouterBootstrap(grants_session, grants_store, topology(),
		"proxy.example").run(reuse_options);
	ok(!missing_grants.success && missing_grants.error.find("required grants") != std::string::npos,
	   "reusing an account with incomplete grants fails closed");

	BootstrapSession interrupted_session;
	interrupted_session.router_exists = true;
	interrupted_session.account_exists = true;
	MemoryBootstrapStore interrupted_store;
	interrupted_store.journal = BootstrapJournal {"cluster-1", "proxysql-east",
		BootstrapPhase::discovered, 17, "mysql_router17_abcdefghijkl", {}};
	auto resumed = MysqlRouterBootstrap(interrupted_session, interrupted_store, topology(),
		"proxy.example").run(options());
	ok(resumed.success && interrupted_session.account_alters == 1 &&
	   interrupted_session.grants == 6 && interrupted_store.secret.size() == 32,
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
