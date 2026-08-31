#include "mysql_router_users.h"

#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>

namespace {

constexpr const char* kAccounts =
	"SELECT User,Host,plugin,authentication_string,account_locked,password_expired,ssl_type "
	"FROM mysql.user WHERE User <> '' "
	"AND User NOT IN ('mysql.infoschema','mysql.session','mysql.sys',?) "
	"ORDER BY User,Host";

const std::string& field(const QueryRow& row, const char* name) {
	auto found = row.find(name);
	if (found == row.end() || !found->second) {
		throw std::runtime_error(std::string("account snapshot column is missing: ") + name);
	}
	return *found->second;
}

bool mysql_boolean(const QueryRow& row, const char* name) {
	const std::string& value = field(row, name);
	if (value == "N" || value == "0" || value == "OFF") return false;
	if (value == "Y" || value == "1" || value == "ON") return true;
	throw std::runtime_error(std::string("account snapshot boolean is invalid: ") + name);
}

void require_execute(IMetadataSession& session, std::string_view sql) {
	ExecResult result = session.execute(sql, {});
	if (!result.ok) throw std::runtime_error(result.error.empty()
		? "account snapshot transaction failed" : result.error);
}

std::string fingerprint(const AccountVariant& account) {
	std::string material;
	for (const std::string* value : {&account.auth_plugin, &account.verifier, &account.ssl_type}) {
		material.append(*value);
		material.push_back('\0');
	}
	material.push_back(account.account_locked ? '1' : '0');
	material.push_back(account.password_expired ? '1' : '0');
	std::array<unsigned char, SHA256_DIGEST_LENGTH> digest {};
	SHA256(reinterpret_cast<const unsigned char*>(material.data()), material.size(), digest.data());
	std::ostringstream output;
	output << std::hex << std::setfill('0');
	for (unsigned char byte : digest) output << std::setw(2) << static_cast<unsigned>(byte);
	return output.str();
}

ManagedMysqlUser imported_user(const AccountVariant& account,
	const UserSyncInput& input, const std::string& source_fingerprint) {
	ManagedMysqlUser user;
	user.username = account.username;
	user.password = account.verifier;
	user.active = !account.account_locked && !account.password_expired;
	user.use_ssl = !account.ssl_type.empty();
	user.default_hostgroup = input.route_writer_hostgroup;
	user.transaction_persistent = true;
	user.frontend = true;
	user.backend = true;
	user.comment = "mysql_router:" + input.topology_uuid + ":" + account.username;
	user.owned = true;
	user.source_fingerprint = source_fingerprint;
	return user;
}

ManagedMysqlUser retained_user(const CurrentMysqlUser& current,
	const std::string& source_fingerprint, bool release) {
	ManagedMysqlUser user;
	static_cast<CurrentMysqlUser&>(user) = current;
	user.source_fingerprint = source_fingerprint;
	user.release = release;
	return user;
}

} // namespace

AccountSnapshot UserSynchronizer::read(IMetadataSession& session,
	std::string_view metadata_username) {
	bool transaction_open = false;
	try {
		require_execute(session, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ");
		require_execute(session, "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY");
		transaction_open = true;
		QueryResult rows = session.query(kAccounts, {std::string(metadata_username)});
		AccountSnapshot snapshot;
		for (const QueryRow& row : rows.rows) {
			AccountVariant account;
			account.username = field(row, "User");
			account.host = field(row, "Host");
			account.auth_plugin = field(row, "plugin");
			account.verifier = field(row, "authentication_string");
			account.account_locked = mysql_boolean(row, "account_locked");
			account.password_expired = mysql_boolean(row, "password_expired");
			account.ssl_type = field(row, "ssl_type");
			if (account.username.empty() || account.host.empty()) {
				throw std::runtime_error("account snapshot identity is empty");
			}
			snapshot.accounts.push_back(std::move(account));
		}
		require_execute(session, "COMMIT");
		transaction_open = false;
		return snapshot;
	} catch (...) {
		if (transaction_open) {
			try { session.execute("ROLLBACK", {}); } catch (...) {}
		}
		throw;
	}
}

ManagedUserGeneration UserSynchronizer::normalize(const AccountSnapshot& snapshot,
	const UserSyncInput& input) {
	if (input.topology_uuid.empty() || input.route_writer_hostgroup <= 0) {
		throw std::invalid_argument("managed user topology or writer hostgroup is invalid");
	}
	std::map<std::string, std::vector<const AccountVariant*>> accounts;
	for (const auto& account : snapshot.accounts) accounts[account.username].push_back(&account);
	std::map<std::string, std::vector<const CurrentMysqlUser*>> current;
	for (const auto& row : input.current_users) {
		current[row.username].push_back(&row);
	}

	ManagedUserGeneration generation;
	for (const auto& entry : accounts) {
		const std::string& username = entry.first;
		auto current_row = current.find(username);
		const CurrentMysqlUser* owned_current = nullptr;
		bool operator_current = false;
		if (current_row != current.end()) {
			for (const CurrentMysqlUser* row : current_row->second) {
				if (!row->owned) operator_current = true;
				else if (owned_current != nullptr) {
					throw std::runtime_error("multiple owned mysql_users variants exist for one username");
				} else owned_current = row;
			}
		}
		auto persisted = input.persisted.find(username);
		if (persisted != input.persisted.end() && persisted->second.state == "released") {
			if (owned_current != nullptr) {
				generation.users.push_back(retained_user(*owned_current,
					persisted->second.source_fingerprint, true));
			}
			generation.status.push_back({username, persisted->second.source_fingerprint,
				persisted->second.auth_plugin, "released", {}});
			continue;
		}
		if (operator_current) {
			generation.status.push_back({username, {}, entry.second.front()->auth_plugin, "collision",
				"an operator-owned mysql_users row already exists"});
			continue;
		}

		std::set<std::string> fingerprints;
		for (const AccountVariant* account : entry.second) fingerprints.insert(fingerprint(*account));
		const AccountVariant& representative = *entry.second.front();
		const bool supported =
			(representative.auth_plugin == "caching_sha2_password" &&
				representative.verifier.rfind("$A$", 0) == 0) ||
			(representative.auth_plugin == "mysql_native_password" &&
				representative.verifier.rfind("*", 0) == 0);
		if (fingerprints.size() != 1 || !supported) {
			const std::string reason = fingerprints.size() != 1
				? "account variants have conflicting authentication policy"
				: "authentication plugin is unsupported";
			if (owned_current != nullptr) {
				const std::string previous = persisted == input.persisted.end()
					? std::string() : persisted->second.source_fingerprint;
				generation.users.push_back(retained_user(*owned_current, previous, false));
			}
			generation.status.push_back({username, {}, representative.auth_plugin,
				"unresolved", reason});
			continue;
		}

		const std::string source = *fingerprints.begin();
		ManagedMysqlUser user = imported_user(representative, input, source);
		generation.status.push_back({username, source, representative.auth_plugin,
			user.active ? "active" : "inactive", {}});
		generation.users.push_back(std::move(user));
	}
	return generation;
}
