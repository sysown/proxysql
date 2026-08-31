#include "ProxySQL_PluginConfig.h"
#include "ProxySQL_PluginConfig_test.h"

#ifdef PROXYSQL40

#include "sqlite3db.h"
#include <json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <exception>
#include <limits>
#include <set>
#include <tuple>
#include <unordered_set>

namespace {

proxysql_plugin_config_test::sql_hook_t transaction_sql_hook = nullptr;
proxysql_plugin_config_test::before_copy_hook_t before_copy_hook = nullptr;
void* test_hook_opaque = nullptr;

bool execute_transaction_sql(SQLite3DB& db, const char* sql) {
	if (transaction_sql_hook != nullptr &&
		transaction_sql_hook(test_hook_opaque, sql) == proxysql_plugin_config_test::sql_action::fail) {
		return false;
	}
	return db.execute(sql);
}

std::string copied(const char* value) {
	return value == nullptr ? std::string() : std::string(value);
}

struct Server {
	int hostgroup_id;
	std::string hostname;
	uint16_t port;
	uint16_t gtid_port;
	int status;
	int weight;
	int compression;
	int max_connections;
	int max_replication_lag;
	bool use_ssl;
	unsigned int max_latency_ms;
	std::string comment;
};

struct User {
	std::string username;
	std::string password;
	bool active;
	bool use_ssl;
	int default_hostgroup;
	std::string default_schema;
	bool schema_locked;
	bool transaction_persistent;
	bool fast_forward;
	bool frontend;
	bool backend;
	int max_connections;
	std::string attributes;
	std::string comment;
	bool release_ownership {false};
};

struct Rule {
	int rule_id;
	bool active;
	int proxy_port;
	std::string match_digest;
	std::string match_pattern;
	bool negate_match_pattern;
	std::string re_modifiers;
	int destination_hostgroup;
	bool apply;
	std::string comment;
};

struct Replication {
	int writer_hostgroup;
	int reader_hostgroup;
	std::string check_type;
	std::string comment;
};

struct GroupReplication {
	int writer_hostgroup;
	int backup_writer_hostgroup;
	int reader_hostgroup;
	int offline_hostgroup;
	bool active;
	int max_writers;
	int writer_is_also_reader;
	int max_transactions_behind;
	std::string comment;
};

struct Attributes {
	int hostgroup_id;
	int max_num_online_servers;
	int autocommit;
	int free_connections_pct;
	std::string init_connect;
	bool multiplex;
	bool connection_warming;
	int throttle_connections_per_sec;
	std::string ignore_session_variables;
	std::string hostgroup_settings;
	std::string servers_defaults;
	std::string comment;
};

struct OwnedPlan {
	std::string owner;
	uint64_t generation {0};
	std::vector<int> hostgroups;
	std::vector<Server> servers;
	std::vector<Replication> replication;
	std::vector<GroupReplication> group_replication;
	std::vector<Attributes> attributes;
	std::vector<User> users;
	std::vector<Rule> rules;
	std::vector<std::string> interfaces;
};

bool decode_release_user_comment(const std::string& encoded, std::string& original,
	bool& release, std::string& error) {
	static constexpr std::string_view prefix = "@proxysql:release-user:";
	release = encoded.compare(0, prefix.size(), prefix) == 0;
	if (!release) {
		original = encoded;
		return true;
	}
	const std::string_view payload(encoded.data() + prefix.size(), encoded.size() - prefix.size());
	if (payload.size() % 2 != 0) {
		error = "user ownership-release comment has invalid hex length";
		return false;
	}
	auto nibble = [](char ch) -> int {
		if (ch >= '0' && ch <= '9') return ch - '0';
		if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
		return -1;
	};
	original.clear();
	original.reserve(payload.size() / 2);
	for (size_t i = 0; i < payload.size(); i += 2) {
		const int high = nibble(payload[i]);
		const int low = nibble(payload[i + 1]);
		if (high < 0 || low < 0) {
			error = "user ownership-release comment contains invalid hex";
			return false;
		}
		original.push_back(static_cast<char>((high << 4) | low));
	}
	return true;
}

template <typename T>
bool present_for_count(const T* values, size_t count, const char* name, std::string& error) {
	if (count != 0 && values == nullptr) {
		error = std::string(name) + " is null while its count is non-zero";
		return false;
	}
	return true;
}

bool copy_plan(const ProxySQL_PluginMysqlConfigPlan& source, OwnedPlan& target, std::string& error) {
	if (!present_for_count(source.owned_hostgroups, source.owned_hostgroup_count, "owned_hostgroups", error) ||
		!present_for_count(source.servers, source.server_count, "servers", error) ||
		!present_for_count(source.replication_hostgroups, source.replication_hostgroup_count, "replication_hostgroups", error) ||
		!present_for_count(source.group_replication_hostgroups, source.group_replication_hostgroup_count, "group_replication_hostgroups", error) ||
		!present_for_count(source.hostgroup_attributes, source.hostgroup_attribute_count, "hostgroup_attributes", error) ||
		!present_for_count(source.users, source.user_count, "users", error) ||
		!present_for_count(source.rules, source.rule_count, "rules", error) ||
		!present_for_count(source.interfaces, source.interface_count, "interfaces", error)) return false;

	target.owner = copied(source.owner);
	target.generation = source.generation;
	target.hostgroups.assign(source.owned_hostgroups, source.owned_hostgroups + source.owned_hostgroup_count);
	target.servers.reserve(source.server_count);
	for (size_t i = 0; i < source.server_count; ++i) {
		const auto& row = source.servers[i];
		target.servers.push_back({row.hostgroup_id, copied(row.hostname), row.port, row.gtid_port,
			row.status, row.weight, row.compression, row.max_connections, row.max_replication_lag,
			row.use_ssl, row.max_latency_ms, copied(row.comment)});
	}
	target.replication.reserve(source.replication_hostgroup_count);
	for (size_t i = 0; i < source.replication_hostgroup_count; ++i) {
		const auto& row = source.replication_hostgroups[i];
		target.replication.push_back({row.writer_hostgroup, row.reader_hostgroup,
			copied(row.check_type), copied(row.comment)});
	}
	target.group_replication.reserve(source.group_replication_hostgroup_count);
	for (size_t i = 0; i < source.group_replication_hostgroup_count; ++i) {
		const auto& row = source.group_replication_hostgroups[i];
		target.group_replication.push_back({row.writer_hostgroup, row.backup_writer_hostgroup,
			row.reader_hostgroup, row.offline_hostgroup, row.active, row.max_writers,
			row.writer_is_also_reader, row.max_transactions_behind, copied(row.comment)});
	}
	target.attributes.reserve(source.hostgroup_attribute_count);
	for (size_t i = 0; i < source.hostgroup_attribute_count; ++i) {
		const auto& row = source.hostgroup_attributes[i];
		target.attributes.push_back({row.hostgroup_id, row.max_num_online_servers, row.autocommit,
			row.free_connections_pct, copied(row.init_connect), row.multiplex, row.connection_warming,
			row.throttle_connections_per_sec, copied(row.ignore_session_variables),
			copied(row.hostgroup_settings), copied(row.servers_defaults), copied(row.comment)});
	}
	target.users.reserve(source.user_count);
	for (size_t i = 0; i < source.user_count; ++i) {
		const auto& row = source.users[i];
		std::string comment;
		bool release_ownership = false;
		if (!decode_release_user_comment(copied(row.comment), comment,
			release_ownership, error)) return false;
		target.users.push_back({copied(row.username), copied(row.password), row.active, row.use_ssl,
			row.default_hostgroup, copied(row.default_schema), row.schema_locked,
			row.transaction_persistent, row.fast_forward, row.frontend, row.backend,
			row.max_connections, copied(row.attributes), std::move(comment), release_ownership});
	}
	target.rules.reserve(source.rule_count);
	for (size_t i = 0; i < source.rule_count; ++i) {
		const auto& row = source.rules[i];
		target.rules.push_back({row.rule_id, row.active, row.proxy_port, copied(row.match_digest),
			copied(row.match_pattern), row.negate_match_pattern, copied(row.re_modifiers),
			row.destination_hostgroup, row.apply, copied(row.comment)});
	}
	target.interfaces.reserve(source.interface_count);
	for (size_t i = 0; i < source.interface_count; ++i) target.interfaces.push_back(copied(source.interfaces[i]));
	return true;
}

bool valid_owner(const std::string& owner) {
	if (owner.empty()) return false;
	for (unsigned char ch : owner) {
		if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_')) return false;
	}
	return true;
}

std::string trim(std::string value) {
	while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
	while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
	return value;
}

bool normalize_interface(const std::string& source, std::string& normalized, int& port) {
	const std::string value = trim(source);
	const size_t colon = value.rfind(':');
	if (colon == std::string::npos || colon == 0 || colon + 1 == value.size()) return false;
	const std::string address = trim(value.substr(0, colon));
	const std::string port_text = value.substr(colon + 1);
	if (address.empty() || port_text.empty() ||
		!std::all_of(port_text.begin(), port_text.end(), [](unsigned char ch) { return ch >= '0' && ch <= '9'; })) return false;
	char* end = nullptr;
	const long parsed = std::strtol(port_text.c_str(), &end, 10);
	if (end == nullptr || *end != '\0' || parsed < 1 || parsed > 65535) return false;
	port = static_cast<int>(parsed);
	normalized = address + ":" + std::to_string(port);
	return true;
}

bool in_owned(const std::unordered_set<int>& owned, int hostgroup) {
	return owned.find(hostgroup) != owned.end();
}

bool valid_json_or_empty(const std::string& value) {
	if (value.empty()) return true;
	return !nlohmann::json::parse(value, nullptr, false).is_discarded();
}

bool valid_rule_modifiers(const std::string& value) {
	if (value.empty()) return true;
	std::set<std::string> seen;
	size_t start = 0;
	while (start <= value.size()) {
		const size_t end = value.find(',', start);
		const std::string token = trim(value.substr(start,
			end == std::string::npos ? std::string::npos : end - start));
		if ((token != "CASELESS" && token != "GLOBAL") || !seen.insert(token).second) return false;
		if (end == std::string::npos) break;
		start = end + 1;
	}
	return true;
}

bool validate(OwnedPlan& plan, std::string& error) {
	if (!valid_owner(plan.owner)) { error = "owner must match [A-Za-z0-9_]+"; return false; }
	if (plan.generation == 0 || plan.generation > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
		error = "generation must be within 1..INT64_MAX"; return false;
	}
	std::unordered_set<int> owned;
	for (int hostgroup : plan.hostgroups) {
		if (hostgroup < 1 || hostgroup > 999999) { error = "owned hostgroup is outside 1..999999"; return false; }
		if (!owned.insert(hostgroup).second) { error = "duplicate owned hostgroup"; return false; }
	}
	std::set<std::tuple<int, std::string, uint16_t>> server_keys;
	for (const auto& row : plan.servers) {
		if (!in_owned(owned, row.hostgroup_id)) { error = "server is outside the owned hostgroup set"; return false; }
		if (row.hostname.empty() || row.port == 0 || (row.gtid_port != 0 && row.gtid_port == row.port) ||
			row.status < 0 || row.status > 3 || row.weight < 0 || row.weight > 10000000 ||
			row.compression < 0 || row.compression > 1 || row.max_connections < 0 ||
			row.max_replication_lag < 0 || row.max_replication_lag > 126144000) {
			error = "invalid mysql_servers row"; return false;
		}
		if (!server_keys.emplace(row.hostgroup_id, row.hostname, row.port).second) {
			error = "duplicate server key"; return false;
		}
	}
	std::set<int> repl_writers, repl_readers;
	const std::set<std::string> check_types {"read_only", "innodb_read_only", "super_read_only",
		"read_only|innodb_read_only", "read_only&innodb_read_only"};
	for (const auto& row : plan.replication) {
		if (!in_owned(owned, row.writer_hostgroup) || !in_owned(owned, row.reader_hostgroup) ||
			row.writer_hostgroup == row.reader_hostgroup || !repl_writers.insert(row.writer_hostgroup).second ||
			!repl_readers.insert(row.reader_hostgroup).second || check_types.count(row.check_type) == 0) {
			error = "invalid or duplicate replication hostgroup mapping"; return false;
		}
	}
	std::set<int> gr_all;
	for (const auto& row : plan.group_replication) {
		const int ids[] {row.writer_hostgroup, row.backup_writer_hostgroup, row.reader_hostgroup, row.offline_hostgroup};
		std::set<int> within_row;
		for (int id : ids) {
			if (!in_owned(owned, id) || !within_row.insert(id).second) {
				error = "group replication mapping escapes or aliases owned hostgroups"; return false;
			}
		}
		for (int id : ids) {
			if (!gr_all.insert(id).second) {
				error = "group replication hostgroups must be globally unique across roles"; return false;
			}
		}
		if (row.max_writers < 0 ||
			row.writer_is_also_reader < 0 || row.writer_is_also_reader > 2 || row.max_transactions_behind < 0) {
			error = "invalid group replication hostgroup mapping"; return false;
		}
	}
	std::set<int> attribute_keys;
	for (const auto& row : plan.attributes) {
		if (!in_owned(owned, row.hostgroup_id) || !attribute_keys.insert(row.hostgroup_id).second ||
			row.max_num_online_servers < 0 || row.max_num_online_servers > 1000000 ||
			row.autocommit < -1 || row.autocommit > 1 || row.free_connections_pct < 0 ||
			row.free_connections_pct > 100 || row.throttle_connections_per_sec < 1 ||
			row.throttle_connections_per_sec > 1000000 ||
			!valid_json_or_empty(row.ignore_session_variables) ||
			!valid_json_or_empty(row.hostgroup_settings) || !valid_json_or_empty(row.servers_defaults)) {
			error = "hostgroup attributes escape or duplicate the owned set"; return false;
		}
	}
	std::set<std::string> usernames;
	for (const auto& row : plan.users) {
		if (row.username.empty() || !usernames.insert(row.username).second || (!row.frontend && !row.backend) ||
			row.default_hostgroup < 0 || row.max_connections < 0 || !valid_json_or_empty(row.attributes)) {
			error = "invalid or duplicate mysql user"; return false;
		}
	}
	const std::string tag = plan.owner + ":";
	std::set<int> rule_ids;
	for (const auto& row : plan.rules) {
		if (row.rule_id <= 0 || !rule_ids.insert(row.rule_id).second || row.proxy_port < 1 || row.proxy_port > 65535 ||
			!in_owned(owned, row.destination_hostgroup) || row.comment.compare(0, tag.size(), tag) != 0 ||
			!valid_rule_modifiers(row.re_modifiers)) {
			error = "invalid, duplicate, or untagged mysql query rule"; return false;
		}
	}
	std::set<std::string> interface_keys;
	for (std::string& interface : plan.interfaces) {
		int port = 0;
		std::string normalized;
		if (!normalize_interface(interface, normalized, port) || port == 6032 || port == 6033 ||
			!interface_keys.insert(normalized).second) {
			error = "invalid, duplicate, or reserved mysql interface"; return false;
		}
		interface = std::move(normalized);
	}
	return true;
}

uint64_t active_generation(SQLite3DB& db, const std::string& schema,
	const std::string& owner, bool& ok) {
	sqlite3_stmt* statement = nullptr;
	const std::string sql = "SELECT generation FROM " + schema +
		".proxysql_plugin_config_generations WHERE owner=?1";
	ok = sqlite3_prepare_v2(db.get_db(), sql.c_str(), -1, &statement, nullptr) == SQLITE_OK;
	if (!ok) return 0;
	sqlite3_bind_text(statement, 1, owner.c_str(), -1, SQLITE_TRANSIENT);
	const int rc = sqlite3_step(statement);
	uint64_t generation = 0;
	if (rc == SQLITE_ROW) {
		const sqlite3_int64 stored = sqlite3_column_int64(statement, 0);
		if (stored < 0) ok = false;
		else generation = static_cast<uint64_t>(stored);
	}
	else if (rc != SQLITE_DONE) ok = false;
	sqlite3_finalize(statement);
	return generation;
}

bool run_statement(SQLite3DB& db, const std::string& sql,
	const std::vector<std::string>& texts, const std::vector<long long>& integers,
	std::string& error) {
	sqlite3_stmt* statement = nullptr;
	if (sqlite3_prepare_v2(db.get_db(), sql.c_str(), -1, &statement, nullptr) != SQLITE_OK) {
		error = sqlite3_errmsg(db.get_db());
		return false;
	}
	int index = 1;
	for (const auto& value : texts) sqlite3_bind_text(statement, index++, value.c_str(), -1, SQLITE_TRANSIENT);
	for (long long value : integers) sqlite3_bind_int64(statement, index++, value);
	const int rc = sqlite3_step(statement);
	if (rc != SQLITE_DONE) error = sqlite3_errmsg(db.get_db());
	sqlite3_finalize(statement);
	return rc == SQLITE_DONE;
}

bool query_exists(SQLite3DB& db, const std::string& sql,
	const std::vector<std::string>& texts, const std::vector<long long>& integers,
	bool& exists, std::string& error) {
	sqlite3_stmt* statement = nullptr;
	if (sqlite3_prepare_v2(db.get_db(), sql.c_str(), -1, &statement, nullptr) != SQLITE_OK) {
		error = sqlite3_errmsg(db.get_db());
		return false;
	}
	int index = 1;
	for (const auto& value : texts) sqlite3_bind_text(statement, index++, value.c_str(), -1, SQLITE_TRANSIENT);
	for (long long value : integers) sqlite3_bind_int64(statement, index++, value);
	const int rc = sqlite3_step(statement);
	exists = rc == SQLITE_ROW;
	if (rc != SQLITE_ROW && rc != SQLITE_DONE) error = sqlite3_errmsg(db.get_db());
	sqlite3_finalize(statement);
	return rc == SQLITE_ROW || rc == SQLITE_DONE;
}

bool ledger_keys(SQLite3DB& db, const std::string& schema, const std::string& owner, const std::string& type,
	std::set<std::string>& keys, std::string& error) {
	sqlite3_stmt* statement = nullptr;
	const std::string sql = "SELECT object_key FROM " + schema +
		".proxysql_plugin_owned_objects WHERE owner=?1 AND object_type=?2 ORDER BY object_key";
	if (sqlite3_prepare_v2(db.get_db(), sql.c_str(), -1, &statement, nullptr) != SQLITE_OK) {
		error = sqlite3_errmsg(db.get_db());
		return false;
	}
	sqlite3_bind_text(statement, 1, owner.c_str(), -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(statement, 2, type.c_str(), -1, SQLITE_TRANSIENT);
	int rc = SQLITE_ROW;
	while ((rc = sqlite3_step(statement)) == SQLITE_ROW) {
		const unsigned char* value = sqlite3_column_text(statement, 0);
		if (value != nullptr) keys.emplace(reinterpret_cast<const char*>(value));
	}
	if (rc != SQLITE_DONE) error = sqlite3_errmsg(db.get_db());
	sqlite3_finalize(statement);
	return rc == SQLITE_DONE;
}

struct Preflight {
	std::set<std::string> old_hostgroups;
	struct UserIdentity {
		std::string username;
		bool backend {false};
		bool frontend {false};

		bool operator<(const UserIdentity& other) const {
			return std::tie(username, backend, frontend) <
				std::tie(other.username, other.backend, other.frontend);
		}
	};
	std::set<UserIdentity> old_users;
	std::set<std::string> old_rules;
	std::set<std::string> old_interfaces;
	std::set<std::string> user_collisions;
	std::set<int> rule_collisions;
	std::vector<std::string> collisions;
};

std::string user_identity_key(const Preflight::UserIdentity& identity) {
	static constexpr char hex[] = "0123456789ABCDEF";
	std::string key = std::string("v2:") + (identity.backend ? "1:" : "0:") +
		(identity.frontend ? "1:" : "0:");
	key.reserve(key.size() + identity.username.size() * 2);
	for (unsigned char ch : identity.username) {
		key.push_back(hex[ch >> 4]);
		key.push_back(hex[ch & 0x0F]);
	}
	return key;
}

std::string user_identity_key(const User& user) {
	return user_identity_key({user.username, user.backend, user.frontend});
}

enum class UserKeyKind { legacy, exact, invalid };

int hex_nibble(char ch) {
	if (ch >= '0' && ch <= '9') return ch - '0';
	if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
	return -1;
}

UserKeyKind parse_user_identity_key(const std::string& key, Preflight::UserIdentity& identity) {
	if (key.compare(0, 3, "v2:") != 0) return UserKeyKind::legacy;
	if (key.size() < 7 || (key[3] != '0' && key[3] != '1') || key[4] != ':' ||
		(key[5] != '0' && key[5] != '1') || key[6] != ':' || (key.size() - 7) % 2 != 0) {
		return UserKeyKind::invalid;
	}
	identity = {{}, key[3] == '1', key[5] == '1'};
	identity.username.reserve((key.size() - 7) / 2);
	for (size_t offset = 7; offset < key.size(); offset += 2) {
		const int high = hex_nibble(key[offset]);
		const int low = hex_nibble(key[offset + 1]);
		if (high < 0 || low < 0 || (high == 0 && low == 0)) return UserKeyKind::invalid;
		identity.username.push_back(static_cast<char>((high << 4) | low));
	}
	if (identity.username.empty() || user_identity_key(identity) != key) return UserKeyKind::invalid;
	return UserKeyKind::exact;
}

struct ExistingUserVariant {
	Preflight::UserIdentity identity;
	std::string password;
	bool active {false};
	bool use_ssl {false};
	int default_hostgroup {0};
	std::string default_schema;
	bool schema_locked {false};
	bool transaction_persistent {false};
	bool fast_forward {false};
	int max_connections {0};
	std::string attributes;
	std::string comment;
};

bool same_managed_user(const ExistingUserVariant& left, const ExistingUserVariant& right) {
	return std::tie(left.password, left.active, left.use_ssl, left.default_hostgroup,
		left.default_schema, left.schema_locked, left.transaction_persistent,
		left.fast_forward, left.max_connections, left.attributes, left.comment) ==
		std::tie(right.password, right.active, right.use_ssl, right.default_hostgroup,
		right.default_schema, right.schema_locked, right.transaction_persistent,
		right.fast_forward, right.max_connections, right.attributes, right.comment);
}

bool query_user_variants(SQLite3DB& db, const std::string& schema, const std::string& username,
	std::vector<ExistingUserVariant>& variants, std::string& error) {
	sqlite3_stmt* statement = nullptr;
	const std::string sql = "SELECT backend,frontend,password,active,use_ssl,default_hostgroup,"
		"default_schema,schema_locked,transaction_persistent,fast_forward,max_connections,"
		"attributes,comment FROM " + schema +
		".mysql_users WHERE username=?1 ORDER BY backend DESC,frontend DESC";
	if (sqlite3_prepare_v2(db.get_db(), sql.c_str(), -1, &statement, nullptr) != SQLITE_OK) {
		error = sqlite3_errmsg(db.get_db());
		return false;
	}
	sqlite3_bind_text(statement, 1, username.c_str(), -1, SQLITE_TRANSIENT);
	int rc = SQLITE_ROW;
	while ((rc = sqlite3_step(statement)) == SQLITE_ROW) {
		auto text_column = [statement](int column) {
			const unsigned char* value = sqlite3_column_text(statement, column);
			return value == nullptr ? std::string() : reinterpret_cast<const char*>(value);
		};
		variants.push_back({{username, sqlite3_column_int(statement, 0) != 0,
			sqlite3_column_int(statement, 1) != 0},
			text_column(2), sqlite3_column_int(statement, 3) != 0,
			sqlite3_column_int(statement, 4) != 0, sqlite3_column_int(statement, 5),
			text_column(6), sqlite3_column_int(statement, 7) != 0,
			sqlite3_column_int(statement, 8) != 0, sqlite3_column_int(statement, 9) != 0,
			sqlite3_column_int(statement, 10), text_column(11), text_column(12)});
	}
	if (rc != SQLITE_DONE) error = sqlite3_errmsg(db.get_db());
	sqlite3_finalize(statement);
	return rc == SQLITE_DONE;
}

bool load_owned_user_identities(SQLite3DB& db, const std::string& schema,
	const std::string& owner, std::set<Preflight::UserIdentity>& identities, std::string& error) {
	std::set<std::string> exact_keys;
	if (!ledger_keys(db, schema, owner, "mysql_user_v2", exact_keys, error)) return false;
	for (const std::string& key : exact_keys) {
		Preflight::UserIdentity identity;
		if (parse_user_identity_key(key, identity) != UserKeyKind::exact) {
			error = "invalid mysql_user_v2 ownership key: " + key;
			return false;
		}
		if (identity.backend && identity.frontend) {
			std::vector<ExistingUserVariant> variants;
			if (!query_user_variants(db, schema, identity.username, variants, error)) return false;
			const auto exact = std::find_if(variants.begin(), variants.end(), [&identity](const auto& variant) {
				return variant.identity.backend == identity.backend &&
					variant.identity.frontend == identity.frontend;
			});
			if (exact == variants.end() && !variants.empty()) {
				if (variants.size() == 2) {
					const std::string marker = owner + ":";
					const auto backend = std::find_if(variants.begin(), variants.end(), [](const auto& variant) {
						return variant.identity.backend && !variant.identity.frontend;
					});
					const auto frontend = std::find_if(variants.begin(), variants.end(), [](const auto& variant) {
						return !variant.identity.backend && variant.identity.frontend;
					});
					if (backend != variants.end() && frontend != variants.end() &&
						backend->comment.compare(0, marker.size(), marker) == 0 &&
						frontend->comment.compare(0, marker.size(), marker) == 0 &&
						same_managed_user(*backend, *frontend)) {
						if (!identities.insert(backend->identity).second ||
							!identities.insert(frontend->identity).second) {
							error = "duplicate exact mysql_user ownership identity";
							return false;
						}
						continue;
					}
				}
				error = "ambiguous owned mysql_user split representation for: " + identity.username;
				return false;
			}
		}
		if (!identities.insert(identity).second) {
			error = "duplicate exact mysql_user ownership identity";
			return false;
		}
	}

	std::set<std::string> keys;
	if (!ledger_keys(db, schema, owner, "mysql_user", keys, error)) return false;
	const std::string marker = owner + ":";
	for (const std::string& key : keys) {
		std::vector<ExistingUserVariant> literal_variants;
		if (!query_user_variants(db, schema, key, literal_variants, error)) return false;
		std::vector<Preflight::UserIdentity> candidates;
		for (const auto& variant : literal_variants) {
			if (variant.comment.compare(0, marker.size(), marker) == 0) {
				candidates.push_back(variant.identity);
			}
		}

		Preflight::UserIdentity decoded_identity;
		const UserKeyKind kind = parse_user_identity_key(key, decoded_identity);
		if (kind == UserKeyKind::exact) {
			std::vector<ExistingUserVariant> decoded_variants;
			if (!query_user_variants(db, schema, decoded_identity.username, decoded_variants, error)) return false;
			for (const auto& variant : decoded_variants) {
				if (variant.identity.username == decoded_identity.username &&
					variant.identity.backend == decoded_identity.backend &&
					variant.identity.frontend == decoded_identity.frontend &&
					variant.comment.compare(0, marker.size(), marker) == 0) {
					candidates.push_back(variant.identity);
				}
			}
		} else if (kind == UserKeyKind::legacy && literal_variants.empty()) {
			continue;
		}

		if (candidates.size() != 1) {
			error = "ambiguous legacy mysql_user ownership for key: " + key;
			return false;
		}
		if (!identities.insert(candidates.front()).second) {
			error = "duplicate exact mysql_user ownership identity";
			return false;
		}
	}
	return true;
}

bool preflight_collisions(SQLite3DB& db, const std::string& schema,
	const OwnedPlan& plan, Preflight& state, std::string& error) {
	if (!ledger_keys(db, schema, plan.owner, "hostgroup", state.old_hostgroups, error) ||
		!load_owned_user_identities(db, schema, plan.owner, state.old_users, error) ||
		!ledger_keys(db, schema, plan.owner, "mysql_query_rule", state.old_rules, error) ||
		!ledger_keys(db, schema, plan.owner, "mysql_interface", state.old_interfaces, error)) return false;
	for (const auto& user : plan.users) {
		const Preflight::UserIdentity identity {user.username, user.backend, user.frontend};
		if (user.release_ownership && state.old_users.count(identity) == 0) {
			error = "cannot release an unowned mysql_user identity: " + user.username;
			return false;
		}
		std::vector<ExistingUserVariant> variants;
		if (!query_user_variants(db, schema, user.username, variants, error)) return false;
		bool collision = false;
		for (const auto& variant : variants) {
			if (state.old_users.count(variant.identity) != 0) continue;
			if (variant.identity.backend == user.backend || variant.identity.frontend == user.frontend) {
				collision = true;
				break;
			}
		}
		if (collision) {
			state.user_collisions.insert(user.username);
			state.collisions.push_back("mysql_user:" + user.username);
		}
	}
	const std::string tag = plan.owner + ":";
	for (const auto& rule : plan.rules) {
		const std::string key = std::to_string(rule.rule_id);
		bool collision = false;
		if (state.old_rules.count(key) == 0) {
			if (!query_exists(db, "SELECT 1 FROM " + schema + ".mysql_query_rules WHERE rule_id=?1 LIMIT 1",
				{}, {rule.rule_id}, collision, error)) return false;
		} else {
			if (!query_exists(db,
				"SELECT 1 FROM " + schema + ".mysql_query_rules WHERE rule_id=?2 "
				"AND (comment IS NULL OR comment NOT LIKE ?1) LIMIT 1",
				{tag + "%"}, {rule.rule_id}, collision, error)) return false;
		}
		if (collision) {
			state.rule_collisions.insert(rule.rule_id);
			state.collisions.push_back("mysql_query_rule:" + key);
		}
	}
	return true;
}

std::string hostgroup_predicate(const std::set<int>& ids, const std::vector<std::string>& columns) {
	if (ids.empty()) return "0";
	std::string values;
	for (int id : ids) {
		if (!values.empty()) values += ',';
		values += std::to_string(id);
	}
	std::string predicate;
	for (const auto& column : columns) {
		if (!predicate.empty()) predicate += " OR ";
		predicate += column + " IN (" + values + ")";
	}
	return predicate;
}

bool has_hybrid_mapping(SQLite3DB& db, const std::string& schema,
	const OwnedPlan& plan, const Preflight& preflight, bool& hybrid, std::string& error) {
	std::set<int> affected;
	for (int id : plan.hostgroups) affected.insert(id);
	for (const std::string& id : preflight.old_hostgroups) affected.insert(std::atoi(id.c_str()));
	if (affected.empty()) { hybrid = false; return true; }
	const std::string repl_any = hostgroup_predicate(affected, {"writer_hostgroup", "reader_hostgroup"});
	std::string ids;
	for (int id : affected) {
		if (!ids.empty()) ids += ',';
		ids += std::to_string(id);
	}
	const std::string repl_all = "writer_hostgroup IN (" + ids + ") AND reader_hostgroup IN (" + ids + ")";
	if (!query_exists(db, "SELECT 1 FROM " + schema + ".mysql_replication_hostgroups WHERE (" +
		repl_any + ") AND NOT (" + repl_all + ") LIMIT 1", {}, {}, hybrid, error) || hybrid) return !error.size();
	const std::vector<std::string> gr_columns {"writer_hostgroup", "backup_writer_hostgroup",
		"reader_hostgroup", "offline_hostgroup"};
	const std::string gr_any = hostgroup_predicate(affected, gr_columns);
	std::string gr_all;
	for (const std::string& column : gr_columns) {
		if (!gr_all.empty()) gr_all += " AND ";
		gr_all += column + " IN (" + ids + ")";
	}
	return query_exists(db, "SELECT 1 FROM " + schema +
		".mysql_group_replication_hostgroups WHERE (" + gr_any + ") AND NOT (" + gr_all +
		") LIMIT 1", {}, {}, hybrid, error);
}

const char* server_status(int status) {
	static const char* values[] {"ONLINE", "SHUNNED", "OFFLINE_SOFT", "OFFLINE_HARD"};
	return values[status];
}

bool insert_server_explicit(SQLite3DB& db, const std::string& schema, const Server& row, std::string& error) {
	sqlite3_stmt* statement = nullptr;
	const std::string sql = "INSERT INTO " + schema + ".mysql_servers "
		"(hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) "
		"VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)";
	if (sqlite3_prepare_v2(db.get_db(), sql.c_str(), -1, &statement, nullptr) != SQLITE_OK) { error = sqlite3_errmsg(db.get_db()); return false; }
	sqlite3_bind_int(statement, 1, row.hostgroup_id);
	sqlite3_bind_text(statement, 2, row.hostname.c_str(), -1, SQLITE_TRANSIENT);
	sqlite3_bind_int(statement, 3, row.port);
	sqlite3_bind_int(statement, 4, row.gtid_port);
	sqlite3_bind_text(statement, 5, server_status(row.status), -1, SQLITE_STATIC);
	sqlite3_bind_int(statement, 6, row.weight);
	sqlite3_bind_int(statement, 7, row.compression);
	sqlite3_bind_int(statement, 8, row.max_connections);
	sqlite3_bind_int(statement, 9, row.max_replication_lag);
	sqlite3_bind_int(statement, 10, row.use_ssl ? 1 : 0);
	sqlite3_bind_int64(statement, 11, row.max_latency_ms);
	sqlite3_bind_text(statement, 12, row.comment.c_str(), -1, SQLITE_TRANSIENT);
	const int rc = sqlite3_step(statement);
	if (rc != SQLITE_DONE) error = sqlite3_errmsg(db.get_db());
	sqlite3_finalize(statement);
	return rc == SQLITE_DONE;
}

std::string current_interfaces(SQLite3DB& db, const std::string& schema, std::string& error) {
	sqlite3_stmt* statement = nullptr;
	const std::string sql = "SELECT variable_value FROM " + schema +
		".global_variables WHERE variable_name='mysql-interfaces'";
	if (sqlite3_prepare_v2(db.get_db(), sql.c_str(), -1, &statement, nullptr) != SQLITE_OK) { error = sqlite3_errmsg(db.get_db()); return {}; }
	const int rc = sqlite3_step(statement);
	std::string value;
	if (rc == SQLITE_ROW && sqlite3_column_text(statement, 0)) value = reinterpret_cast<const char*>(sqlite3_column_text(statement, 0));
	else if (rc != SQLITE_DONE) error = sqlite3_errmsg(db.get_db());
	sqlite3_finalize(statement);
	return value;
}

std::vector<std::string> split_interfaces(const std::string& value) {
	std::vector<std::string> output;
	size_t start = 0;
	while (start <= value.size()) {
		const size_t end = value.find(';', start);
		std::string part = trim(value.substr(start, end == std::string::npos ? std::string::npos : end - start));
		if (!part.empty()) output.push_back(std::move(part));
		if (end == std::string::npos) break;
		start = end + 1;
	}
	return output;
}

bool stage_schema(SQLite3DB& db, const std::string& schema, const OwnedPlan& plan,
	const Preflight& preflight, std::string& error) {
	std::set<int> affected;
	for (int id : plan.hostgroups) affected.insert(id);
	for (const auto& id : preflight.old_hostgroups) affected.insert(std::atoi(id.c_str()));
	if (!db.execute(("DELETE FROM " + schema + ".mysql_servers WHERE " +
		hostgroup_predicate(affected, {"hostgroup_id"})).c_str()) ||
		!db.execute(("DELETE FROM " + schema + ".mysql_replication_hostgroups WHERE " +
		hostgroup_predicate(affected, {"writer_hostgroup","reader_hostgroup"})).c_str()) ||
		!db.execute(("DELETE FROM " + schema + ".mysql_group_replication_hostgroups WHERE " +
		hostgroup_predicate(affected, {"writer_hostgroup","backup_writer_hostgroup","reader_hostgroup","offline_hostgroup"})).c_str()) ||
		!db.execute(("DELETE FROM " + schema + ".mysql_hostgroup_attributes WHERE " +
		hostgroup_predicate(affected, {"hostgroup_id"})).c_str())) {
		error = sqlite3_errmsg(db.get_db()); return false;
	}
	for (const auto& row : plan.servers) if (!insert_server_explicit(db, schema, row, error)) return false;
	for (const auto& row : plan.replication) {
		if (!run_statement(db, "INSERT INTO " + schema + ".mysql_replication_hostgroups "
			"(writer_hostgroup,reader_hostgroup,check_type,comment) VALUES (?3,?4,?1,?2)",
			{row.check_type,row.comment}, {row.writer_hostgroup,row.reader_hostgroup}, error)) return false;
	}
	for (const auto& row : plan.group_replication) {
		if (!run_statement(db, "INSERT INTO " + schema + ".mysql_group_replication_hostgroups "
			"(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) "
			"VALUES (?2,?3,?4,?5,?6,?7,?8,?9,?1)", {row.comment},
			{row.writer_hostgroup,row.backup_writer_hostgroup,row.reader_hostgroup,row.offline_hostgroup,row.active,row.max_writers,row.writer_is_also_reader,row.max_transactions_behind}, error)) return false;
	}
	for (const auto& row : plan.attributes) {
		sqlite3_stmt* statement = nullptr;
		const std::string sql = "INSERT INTO " + schema + ".mysql_hostgroup_attributes "
			"(hostgroup_id,max_num_online_servers,autocommit,free_connections_pct,init_connect,multiplex,connection_warming,throttle_connections_per_sec,ignore_session_variables,hostgroup_settings,servers_defaults,comment) "
			"VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)";
		if (sqlite3_prepare_v2(db.get_db(), sql.c_str(), -1, &statement, nullptr) != SQLITE_OK) { error=sqlite3_errmsg(db.get_db()); return false; }
		const int ints[] {row.hostgroup_id,row.max_num_online_servers,row.autocommit,row.free_connections_pct};
		for (int i=0;i<4;++i) sqlite3_bind_int(statement,i+1,ints[i]);
		sqlite3_bind_text(statement,5,row.init_connect.c_str(),-1,SQLITE_TRANSIENT);
		sqlite3_bind_int(statement,6,row.multiplex); sqlite3_bind_int(statement,7,row.connection_warming);
		sqlite3_bind_int(statement,8,row.throttle_connections_per_sec);
		sqlite3_bind_text(statement,9,row.ignore_session_variables.c_str(),-1,SQLITE_TRANSIENT);
		sqlite3_bind_text(statement,10,row.hostgroup_settings.c_str(),-1,SQLITE_TRANSIENT);
		sqlite3_bind_text(statement,11,row.servers_defaults.c_str(),-1,SQLITE_TRANSIENT);
		sqlite3_bind_text(statement,12,row.comment.c_str(),-1,SQLITE_TRANSIENT);
		const int rc=sqlite3_step(statement); if(rc!=SQLITE_DONE) error=sqlite3_errmsg(db.get_db()); sqlite3_finalize(statement); if(rc!=SQLITE_DONE) return false;
	}
	for (const auto& identity : preflight.old_users) {
		if (!run_statement(db, "DELETE FROM " + schema +
			".mysql_users WHERE username=?1 AND backend=?2 AND frontend=?3",
			{identity.username}, {identity.backend ? 1 : 0, identity.frontend ? 1 : 0}, error)) return false;
	}
	for (const auto& row : plan.users) {
		if (preflight.user_collisions.count(row.username)) continue;
		sqlite3_stmt* statement=nullptr;
		const std::string sql="INSERT INTO "+schema+".mysql_users (username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)";
		if(sqlite3_prepare_v2(db.get_db(),sql.c_str(),-1,&statement,nullptr)!=SQLITE_OK){error=sqlite3_errmsg(db.get_db());return false;}
		const std::string* texts[]={&row.username,&row.password}; for(int i=0;i<2;++i) sqlite3_bind_text(statement,i+1,texts[i]->c_str(),-1,SQLITE_TRANSIENT);
		sqlite3_bind_int(statement,3,row.active); sqlite3_bind_int(statement,4,row.use_ssl); sqlite3_bind_int(statement,5,row.default_hostgroup);
		sqlite3_bind_text(statement,6,row.default_schema.c_str(),-1,SQLITE_TRANSIENT); sqlite3_bind_int(statement,7,row.schema_locked); sqlite3_bind_int(statement,8,row.transaction_persistent); sqlite3_bind_int(statement,9,row.fast_forward); sqlite3_bind_int(statement,10,row.backend); sqlite3_bind_int(statement,11,row.frontend); sqlite3_bind_int(statement,12,row.max_connections); sqlite3_bind_text(statement,13,row.attributes.c_str(),-1,SQLITE_TRANSIENT); sqlite3_bind_text(statement,14,row.comment.c_str(),-1,SQLITE_TRANSIENT);
		const int rc=sqlite3_step(statement); if(rc!=SQLITE_DONE)error=sqlite3_errmsg(db.get_db());sqlite3_finalize(statement);if(rc!=SQLITE_DONE)return false;
	}
	const std::string tag=plan.owner+":";
	for(const auto& key:preflight.old_rules){
		if(!run_statement(db,"DELETE FROM "+schema+".mysql_query_rules WHERE rule_id=?2 AND comment LIKE ?1",{tag+"%"},{std::atoll(key.c_str())},error))return false;
	}
	for(const auto& row:plan.rules){
		if(preflight.rule_collisions.count(row.rule_id))continue;
		if(!run_statement(db,"INSERT INTO "+schema+".mysql_query_rules (rule_id,active,flagIN,proxy_port,match_digest,match_pattern,negate_match_pattern,re_modifiers,destination_hostgroup,apply,attributes,comment) VALUES (?5,?6,0,?7,NULLIF(?1,''),NULLIF(?2,''),?8,NULLIF(?3,''),?9,?10,'',?4)",
			{row.match_digest,row.match_pattern,row.re_modifiers,row.comment},{row.rule_id,row.active,row.proxy_port,row.negate_match_pattern,row.destination_hostgroup,row.apply},error))return false;
	}
	std::vector<std::string> merged;
	for(const auto& value:split_interfaces(current_interfaces(db,schema,error))) if(!preflight.old_interfaces.count(value)) merged.push_back(value);
	for(const auto& value:plan.interfaces) if(std::find(merged.begin(),merged.end(),value)==merged.end()) merged.push_back(value);
	std::string joined; for(const auto& value:merged){if(!joined.empty())joined+=';';joined+=value;}
	if(!run_statement(db,"INSERT OR REPLACE INTO "+schema+".global_variables(variable_name,variable_value) VALUES ('mysql-interfaces',?1)",{joined},{},error))return false;
	if(!run_statement(db,"DELETE FROM "+schema+".proxysql_plugin_owned_objects WHERE owner=?1",{plan.owner},{},error))return false;
	auto add_ledger=[&](const std::string&type,const std::string&key){return run_statement(db,"INSERT INTO "+schema+".proxysql_plugin_owned_objects(owner,object_type,object_key,generation) VALUES (?1,?2,?3,?4)",{plan.owner,type,key},{static_cast<long long>(plan.generation)},error);};
	for(int id:plan.hostgroups)if(!add_ledger("hostgroup",std::to_string(id)))return false;
	for(const auto& row:plan.users)if(!row.release_ownership&&
		!preflight.user_collisions.count(row.username)&&
		!add_ledger("mysql_user_v2",user_identity_key(row)))return false;
	for(const auto& row:plan.rules)if(!preflight.rule_collisions.count(row.rule_id)&&!add_ledger("mysql_query_rule",std::to_string(row.rule_id)))return false;
	for(const auto& value:plan.interfaces)if(!add_ledger("mysql_interface",value))return false;
	if(!run_statement(db,"INSERT OR REPLACE INTO "+schema+".proxysql_plugin_config_generations(owner,generation) VALUES (?1,?2)",{plan.owner},{static_cast<long long>(plan.generation)},error))return false;
	return true;
}

} // namespace

namespace proxysql_plugin_config_test {

scoped_hooks::scoped_hooks(sql_hook_t sql_hook, before_copy_hook_t copy_hook, void* opaque) {
	test_hook_opaque = opaque;
	transaction_sql_hook = sql_hook;
	before_copy_hook = copy_hook;
}

scoped_hooks::~scoped_hooks() {
	transaction_sql_hook = nullptr;
	before_copy_hook = nullptr;
	test_hook_opaque = nullptr;
}

} // namespace proxysql_plugin_config_test

ProxySQL_PluginMysqlRuntimeSnapshot::~ProxySQL_PluginMysqlRuntimeSnapshot() {
	delete servers;
	delete replication_hostgroups;
	delete group_replication_hostgroups;
	delete hostgroup_attributes;
	delete users;
	delete rules;
	delete fast_routing_rules;
}

bool proxysql_ensure_plugin_mysql_config_schema(SQLite3DB& db, const char* schema) {
	std::string prefix = schema == nullptr ? "main" : schema;
	if (prefix != "main" && prefix != "disk") return false;
	auto qualified = [&prefix](const char* ddl, const char* table) {
		std::string sql(ddl);
		const std::string needle = std::string("proxysql_plugin_") + table;
		const size_t pos = sql.find(needle);
		if (pos != std::string::npos) sql.insert(pos, prefix + ".");
		return sql;
	};
	return db.execute(qualified(PROXYSQL_PLUGIN_OWNED_OBJECTS_DDL, "owned_objects").c_str()) &&
		db.execute(qualified(PROXYSQL_PLUGIN_CONFIG_GENERATIONS_DDL, "config_generations").c_str());
}

static ProxySQL_PluginMysqlConfigResult apply_plugin_mysql_config_impl(
	SQLite3DB& admindb,
	const ProxySQL_PluginMysqlConfigPlan& source,
	const ProxySQL_PluginConfigRuntimeHooks& runtime) {
	OwnedPlan plan;
	std::string error;
	if (!copy_plan(source, plan, error) || !validate(plan, error)) return {false, 0, error, {}};
	if (runtime.lock == nullptr || runtime.unlock == nullptr || runtime.capture == nullptr ||
		runtime.publish == nullptr || runtime.restore == nullptr || runtime.checkpoint == nullptr) {
		return {false, 0, "runtime publication hooks are incomplete", {}};
	}

	std::vector<ProxySQL_PluginConfigLock> locks;
	std::vector<ProxySQL_PluginConfigStage> published;
	ProxySQL_PluginMysqlRuntimeSnapshot snapshot;
	bool transaction_open = false;
	uint64_t locked_current = 0;
	std::vector<std::string> collisions;
	auto append_error = [](std::string& message, const std::string& extra) {
		if (extra.empty()) return;
		if (!message.empty()) message += "; ";
		message += extra;
	};
	auto unlock_all = [&](std::string& cleanup_error) {
		for (auto it = locks.rbegin(); it != locks.rend(); ++it) {
			try {
				runtime.unlock(runtime.opaque, *it);
			} catch (const std::exception& e) {
				append_error(cleanup_error, std::string("unlock failed: ") + e.what());
			} catch (...) {
				append_error(cleanup_error, "unlock failed: unknown exception");
			}
		}
		locks.clear();
	};
	auto fail = [&](std::string message) {
		for (auto it = published.rbegin(); it != published.rend(); ++it) {
			std::string restore_error;
			try {
				if (!runtime.restore(runtime.opaque, *it, snapshot, restore_error)) {
					append_error(message, "restore failed: " + restore_error);
				}
			} catch (const std::exception& e) {
				append_error(message, std::string("restore failed: ") + e.what());
			} catch (...) {
				append_error(message, "restore failed: unknown exception");
			}
		}
		published.clear();
		if (transaction_open && admindb.get_db() != nullptr) {
			if (sqlite3_get_autocommit(admindb.get_db()) != 0) {
				append_error(message, "rollback not required: transaction already closed");
			} else {
				for (int attempt = 0; attempt < 3 && admindb.get_db() != nullptr &&
					sqlite3_get_autocommit(admindb.get_db()) == 0; ++attempt) {
					try {
						if (!execute_transaction_sql(admindb, "ROLLBACK")) {
							append_error(message, std::string("rollback failed: ") +
								sqlite3_errmsg(admindb.get_db()));
						}
					} catch (const std::exception& e) {
						append_error(message, std::string("rollback failed: ") + e.what());
					} catch (...) {
						append_error(message, "rollback failed: unknown exception");
					}
				}
				if (admindb.get_db() != nullptr && sqlite3_get_autocommit(admindb.get_db()) == 0) {
					if (admindb.quarantine()) {
						append_error(message, "fatal rollback cleanup failure: Admin connection quarantined");
					} else {
						append_error(message, "fatal rollback cleanup failure: Admin connection quarantine failed");
					}
				}
			}
			transaction_open = false;
		}
		unlock_all(message);
		return ProxySQL_PluginMysqlConfigResult{false, locked_current, std::move(message), collisions};
	};

	try {
		for (ProxySQL_PluginConfigLock lock : {
			ProxySQL_PluginConfigLock::admin,
			ProxySQL_PluginConfigLock::hostgroups,
			ProxySQL_PluginConfigLock::auth,
			ProxySQL_PluginConfigLock::query_processor,
			ProxySQL_PluginConfigLock::mysql_threads}) {
			locks.push_back(lock);
			error.clear();
			bool acquired = false;
			try {
				acquired = runtime.lock(runtime.opaque, lock, error);
			} catch (...) {
				locks.pop_back();
				throw;
			}
			if (!acquired) {
				locks.pop_back();
				return fail("cannot acquire publication locks: " + error);
			}
		}
		error.clear();
		if (!runtime.capture(runtime.opaque, snapshot, error)) {
			return fail("cannot capture runtime state: " + error);
		}

		bool main_ok = false;
		bool disk_ok = false;
		const uint64_t main_current = active_generation(admindb, "main", plan.owner, main_ok);
		const uint64_t disk_current = active_generation(admindb, "disk", plan.owner, disk_ok);
		locked_current = std::max(main_current, disk_current);
		if (!main_ok || !disk_ok) return fail("cannot read active plugin generations");
		if (plan.generation <= locked_current) return fail("generation must be strictly newer");

		Preflight main_preflight;
		Preflight disk_preflight;
		error.clear();
		if (!preflight_collisions(admindb, "main", plan, main_preflight, error) ||
			!preflight_collisions(admindb, "disk", plan, disk_preflight, error)) {
			return fail("cannot preflight plugin ownership: " + error);
		}
		std::set<std::string> user_collisions = main_preflight.user_collisions;
		user_collisions.insert(disk_preflight.user_collisions.begin(), disk_preflight.user_collisions.end());
		std::set<int> rule_collisions = main_preflight.rule_collisions;
		rule_collisions.insert(disk_preflight.rule_collisions.begin(), disk_preflight.rule_collisions.end());
		main_preflight.user_collisions = disk_preflight.user_collisions = user_collisions;
		main_preflight.rule_collisions = disk_preflight.rule_collisions = rule_collisions;
		for (const std::string& username : user_collisions) collisions.push_back("mysql_user:" + username);
		for (int rule_id : rule_collisions) collisions.push_back("mysql_query_rule:" + std::to_string(rule_id));

		bool hybrid = false;
		error.clear();
		if (!has_hybrid_mapping(admindb, "main", plan, main_preflight, hybrid, error) ||
			(!hybrid && !has_hybrid_mapping(admindb, "disk", plan, disk_preflight, hybrid, error))) {
			return fail("cannot validate hostgroup ownership boundary: " + error);
		}
		if (hybrid) return fail("hostgroup mapping crosses the plugin ownership boundary");

		// A deferred transaction keeps main+disk staging atomic without reserving
		// write locks on unrelated DEBUG-only databases attached to Admin (notably
		// the shared in-memory HGM database). Runtime publication updates those
		// databases through their owning connections while this transaction is open.
		if (!execute_transaction_sql(admindb, "BEGIN")) {
			return fail(std::string("cannot start publication transaction: ") + sqlite3_errmsg(admindb.get_db()));
		}
		transaction_open = true;
		error.clear();
		if (!stage_schema(admindb, "main", plan, main_preflight, error) ||
			!stage_schema(admindb, "disk", plan, disk_preflight, error)) {
			return fail("cannot stage plugin configuration: " + error);
		}
		if (!runtime.checkpoint(runtime.opaque, ProxySQL_PluginConfigStage::admin_staging, error)) return fail(error);
		for (ProxySQL_PluginConfigStage stage : {
			ProxySQL_PluginConfigStage::servers,
			ProxySQL_PluginConfigStage::users,
			ProxySQL_PluginConfigStage::rules,
			ProxySQL_PluginConfigStage::interfaces}) {
			published.push_back(stage);
			error.clear();
			if (!runtime.publish(runtime.opaque, stage, admindb, plan.generation, error)) return fail(error);
		}
		error.clear();
		if (!runtime.checkpoint(runtime.opaque, ProxySQL_PluginConfigStage::commit, error)) return fail(error);
		if (!execute_transaction_sql(admindb, "COMMIT")) {
			return fail(std::string("cannot commit plugin configuration: ") + sqlite3_errmsg(admindb.get_db()));
		}
		transaction_open = false;
		published.clear();
		std::string unlock_error;
		unlock_all(unlock_error);
		std::string message = "plugin configuration published";
		append_error(message, unlock_error);
		return {true, plan.generation, std::move(message), collisions};
	} catch (const std::exception& e) {
		return fail(std::string("plugin publication exception: ") + e.what());
	} catch (...) {
		return fail("plugin publication exception: unknown exception");
	}
}

ProxySQL_PluginMysqlConfigResult proxysql_apply_plugin_mysql_config(
	SQLite3DB& admindb,
	const ProxySQL_PluginMysqlConfigPlan& source,
	const ProxySQL_PluginConfigRuntimeHooks& runtime) {
	try {
		if (before_copy_hook != nullptr) before_copy_hook(test_hook_opaque);
		return apply_plugin_mysql_config_impl(admindb, source, runtime);
	} catch (...) {
		return {false, 0, "plugin publication failed before lock acquisition", {}};
	}
}

#endif /* PROXYSQL40 */
