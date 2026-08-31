#include "tap.h"

#include "mysql_router_users.h"

#include <algorithm>
#include <stdexcept>

namespace {

AccountVariant account(const char* user, const char* host, const char* plugin,
	const char* verifier, bool locked = false, bool expired = false,
	const char* ssl_type = "") {
	return {user, host, plugin, verifier, locked, expired, ssl_type};
}

CurrentMysqlUser current(const char* user, const char* password, bool owned = true) {
	CurrentMysqlUser row;
	row.username = user;
	row.password = password;
	row.active = true;
	row.default_hostgroup = 8100;
	row.transaction_persistent = true;
	row.frontend = true;
	row.backend = true;
	row.comment = owned ? std::string("mysql_router:cluster-1:") + user : "operator";
	row.owned = owned;
	return row;
}

const ManagedMysqlUser* managed(const ManagedUserGeneration& generation, const char* username) {
	auto found = std::find_if(generation.users.begin(), generation.users.end(),
		[&](const auto& row) { return row.username == username; });
	return found == generation.users.end() ? nullptr : &*found;
}

const ManagedUserStatus* status(const ManagedUserGeneration& generation, const char* username) {
	auto found = std::find_if(generation.status.begin(), generation.status.end(),
		[&](const auto& row) { return row.username == username; });
	return found == generation.status.end() ? nullptr : &*found;
}

class ReadSession final : public IMetadataSession {
public:
	bool incomplete {false};
	std::vector<std::string> calls;
	std::vector<std::vector<SqlValue>> params;

	QueryResult query(std::string_view sql, const std::vector<SqlValue>& values) override {
		calls.emplace_back(sql);
		params.push_back(values);
		QueryRow row {
			{"User", "app"}, {"Host", "%"}, {"plugin", "caching_sha2_password"},
			{"authentication_string", "$A$005$verifier"}, {"account_locked", "N"},
			{"password_expired", "N"}, {"ssl_type", ""},
		};
		if (incomplete) row.erase("ssl_type");
		return {{std::move(row)}};
	}
	ExecResult execute(std::string_view sql, const std::vector<SqlValue>&) override {
		calls.emplace_back(sql);
		return {true, 0, {}};
	}
	ServerVersion server_version() const override { return {8, 4, 6}; }
};

} // namespace

int main() {
	plan(18);

	ReadSession reader;
	auto snapshot = UserSynchronizer::read(reader, "router_metadata");
	ok(snapshot.accounts.size() == 1 && snapshot.accounts[0].username == "app",
	   "one complete repeatable-read account snapshot is decoded");
	ok(reader.calls.size() == 4 && reader.calls[0].find("REPEATABLE READ") != std::string::npos &&
	   reader.calls[1].find("START TRANSACTION") != std::string::npos &&
	   reader.calls[3] == "COMMIT",
	   "account reading uses one explicit repeatable-read transaction");
	ok(reader.params.size() == 1 && reader.params[0] ==
	   std::vector<SqlValue>({std::string("router_metadata")}),
	   "the metadata service account is excluded through a bound value");
	ReadSession incomplete;
	incomplete.incomplete = true;
	bool rejected = false;
	try { (void)UserSynchronizer::read(incomplete, "router_metadata"); }
	catch (const std::exception&) { rejected = true; }
	ok(rejected && !incomplete.calls.empty() && incomplete.calls.back() == "ROLLBACK",
	   "an incomplete account row aborts and rolls back the complete snapshot");

	AccountSnapshot accounts;
	accounts.accounts = {
		account("app", "%", "caching_sha2_password", "$A$005$app"),
		account("app", "localhost", "caching_sha2_password", "$A$005$app"),
		account("native", "%", "mysql_native_password", "*0123456789ABCDEF"),
		account("locked", "%", "caching_sha2_password", "$A$005$locked", true),
		account("expired", "%", "caching_sha2_password", "$A$005$expired", false, true),
		account("conflict", "%", "caching_sha2_password", "$A$005$one"),
		account("conflict", "localhost", "caching_sha2_password", "$A$005$two"),
		account("unsupported", "%", "auth_socket", ""),
		account("operator", "%", "caching_sha2_password", "$A$005$remote"),
		account("previous", "%", "caching_sha2_password", "$A$005$new-one"),
		account("previous", "localhost", "caching_sha2_password", "$A$005$new-two"),
		account("released", "%", "caching_sha2_password", "$A$005$released"),
	};
	UserSyncInput input;
	input.topology_uuid = "cluster-1";
	input.route_writer_hostgroup = 8100;
	CurrentMysqlUser operator_backend = current("operator", "operator-backend", false);
	operator_backend.frontend = false;
	CurrentMysqlUser operator_frontend = current("operator", "operator-frontend", false);
	operator_frontend.backend = false;
	input.current_users = {
		operator_backend,
		operator_frontend,
		current("previous", "$A$005$working"),
		current("gone", "$A$005$gone"),
		current("released", "$A$005$local"),
	};
	input.persisted = {
		{"previous", {"old-fingerprint", "active"}},
		{"gone", {"old-fingerprint", "active"}},
		{"released", {"old-fingerprint", "released"}},
	};
	auto generation = UserSynchronizer::normalize(accounts, input);

	const auto* app = managed(generation, "app");
	ok(app && app->password == "$A$005$app" && app->active,
	   "identical caching SHA-2 variants collapse to one active managed user");
	ok(app && app->default_hostgroup == 8100 && app->transaction_persistent &&
	   app->frontend && app->backend,
	   "managed users default to the stable writer with transaction persistence");
	ok(app && app->comment == "mysql_router:cluster-1:app" && !app->source_fingerprint.empty(),
	   "managed users carry visible ownership and a source fingerprint");
	const auto* native = managed(generation, "native");
	ok(native && native->password == "*0123456789ABCDEF" && native->active,
	   "mysql_native_password uses the existing native hash path");
	const auto* locked = managed(generation, "locked");
	ok(locked && !locked->active && status(generation, "locked") &&
	   status(generation, "locked")->state == "inactive",
	   "locked accounts materialize as inactive");
	const auto* expired = managed(generation, "expired");
	ok(expired && !expired->active && status(generation, "expired") &&
	   status(generation, "expired")->state == "inactive",
	   "password-expired accounts materialize as inactive");
	ok(!managed(generation, "conflict") && status(generation, "conflict") &&
	   status(generation, "conflict")->state == "unresolved",
	   "a new conflicting username is unresolved and not published");
	ok(!managed(generation, "unsupported") && status(generation, "unsupported") &&
	   status(generation, "unsupported")->state == "unresolved",
	   "unsupported authentication plugins remain unresolved");
	ok(!managed(generation, "operator") && status(generation, "operator") &&
	   status(generation, "operator")->state == "collision",
	   "a pre-existing operator username wins and is preserved");
	const auto* previous = managed(generation, "previous");
	ok(previous && previous->password == "$A$005$working" &&
	   status(generation, "previous")->state == "unresolved",
	   "a conflicting refresh retains the previous working managed row");
	ok(!managed(generation, "gone") && status(generation, "gone") == nullptr,
	   "a previously owned username removed remotely is omitted for scoped deletion");
	const auto* released = managed(generation, "released");
	ok(released && released->release && released->password == "$A$005$local" &&
	   status(generation, "released")->state == "released",
	   "release preserves the local row while transferring ownership to the operator");
	ok(generation.users.size() == 6,
	   "the normalized generation contains only active, inactive, retained, and release rows");

	AccountSnapshot split_accounts;
	split_accounts.accounts = {
		account("split", "%", "caching_sha2_password", "$A$005$split"),
	};
	UserSyncInput split_input;
	split_input.topology_uuid = "cluster-1";
	split_input.route_writer_hostgroup = 8100;
	CurrentMysqlUser split_frontend = current("split", "$A$005$split");
	split_frontend.backend = false;
	CurrentMysqlUser split_backend = current("split", "$A$005$split");
	split_backend.frontend = false;
	split_input.current_users = {split_frontend, split_backend};
	bool split_collapsed = false;
	try {
		auto split_generation = UserSynchronizer::normalize(split_accounts, split_input);
		const auto* split_user = managed(split_generation, "split");
		split_collapsed = split_user != nullptr && split_user->frontend && split_user->backend;
	} catch (const std::exception&) {}
	ok(split_collapsed,
	   "an owned complementary frontend/backend split collapses to one canonical managed user");

	return exit_status();
}
