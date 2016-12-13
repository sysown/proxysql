#ifndef PROXYSQL_AUTH_H_
#define PROXYSQL_AUTH_H_

#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

#include "proxysql.h"

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define MYSQL_AUTHENTICATION_VERSION "0.2.0902" DEB

namespace proxysql { namespace auth {

enum GroupType {
	BACKEND,
	FRONTEND,
	__MAX,
};

static constexpr GroupType GroupTypeMax() {
	return GroupType::__MAX;
}

struct AccountDetails {
	std::string username;
	std::string password;
	std::vector<uint8_t> sha1_pass;
	std::string default_schema;
	int default_hostgroup;
	int max_connections;
	int num_connections_used;
	bool use_ssl:1;
	bool schema_locked:1;
	bool transaction_persistent:1;
	bool fast_forward:1;
	bool __active:1;
	AccountDetails();
};

class Group {
public:
	Group(GroupType t);
	void add(std::shared_ptr<AccountDetails>);
	void del(const std::string& username);
	std::shared_ptr<const AccountDetails> lookup(const std::string& username);
	void set_SHA1(const std::string& username, void *sha_pass);
	int increase_connections(const std::string& username, int *mc=NULL);
	void decrease_connections(const std::string& username);
	void set_all_inactive();
	void remove_inactives();
	std::vector<std::pair<GroupType, std::shared_ptr<const AccountDetails>>> dump();
private:
	rwlock_t lock_;
	std::unordered_map<std::string, std::shared_ptr<AccountDetails>> creds_;
	GroupType t_;
};

class Auth {
public:
	Auth();
	template<GroupType t> std::shared_ptr<Group> get_group() {
		static_assert(GroupTypeMax() > t, "GroupType::__MAX is special value and shouldn't be used directly");
		return groups_[t];
	};
	std::vector<std::pair<GroupType, std::shared_ptr<const AccountDetails>>> dump_all_users();
	void print_version();
private:
	std::array<std::shared_ptr<Group>, GroupTypeMax()> groups_;
};

}}

#endif // PROXYSQL_AUTH_H_
