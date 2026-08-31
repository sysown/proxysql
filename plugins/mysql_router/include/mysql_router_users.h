#ifndef PROXYSQL_MYSQL_ROUTER_USERS_H
#define PROXYSQL_MYSQL_ROUTER_USERS_H

#include "mysql_router_metadata.h"

#include <map>
#include <string>
#include <vector>

struct AccountVariant {
	std::string username;
	std::string host;
	std::string auth_plugin;
	std::string verifier;
	bool account_locked {false};
	bool password_expired {false};
	std::string ssl_type;
};

struct AccountSnapshot {
	std::vector<AccountVariant> accounts;
};

struct CurrentMysqlUser {
	std::string username;
	std::string password;
	bool active {true};
	bool use_ssl {false};
	int default_hostgroup {0};
	std::string default_schema;
	bool schema_locked {false};
	bool transaction_persistent {true};
	bool fast_forward {false};
	bool frontend {true};
	bool backend {true};
	int max_connections {1000};
	std::string attributes {"{}"};
	std::string comment;
	bool owned {false};
};

struct PersistedManagedUser {
	std::string source_fingerprint;
	std::string state;
	std::string auth_plugin;
};

struct UserSyncInput {
	std::string topology_uuid;
	int route_writer_hostgroup {0};
	std::vector<CurrentMysqlUser> current_users;
	std::map<std::string, PersistedManagedUser> persisted;
};

struct ManagedMysqlUser : CurrentMysqlUser {
	std::string source_fingerprint;
	bool release {false};
};

struct ManagedUserStatus {
	std::string username;
	std::string source_fingerprint;
	std::string auth_plugin;
	std::string state;
	std::string last_error;
};

struct ManagedUserGeneration {
	std::vector<ManagedMysqlUser> users;
	std::vector<ManagedUserStatus> status;
};

class UserSynchronizer {
public:
	static AccountSnapshot read(IMetadataSession& session,
		std::string_view metadata_username);
	static ManagedUserGeneration normalize(const AccountSnapshot& snapshot,
		const UserSyncInput& input);
};

#endif
