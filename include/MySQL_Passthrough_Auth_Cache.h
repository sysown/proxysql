#ifndef PROXYSQL_MYSQL_PASSTHROUGH_AUTH_CACHE_H
#define PROXYSQL_MYSQL_PASSTHROUGH_AUTH_CACHE_H

#include <pthread.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef DEBUG
#define MYSQL_PASSTHROUGH_AUTH_CACHE_DEB "_DEBUG"
#else
#define MYSQL_PASSTHROUGH_AUTH_CACHE_DEB ""
#endif
#define MYSQL_PASSTHROUGH_AUTH_CACHE_VERSION "0.1.0000" MYSQL_PASSTHROUGH_AUTH_CACHE_DEB

struct passthrough_entry_view {
	std::string username;
	uint64_t learned_at_us;
	int hostgroup_probed;
};

class MySQL_Passthrough_Auth_Cache {
	private:
		struct entry_t {
			std::string cleartext_password;
			uint64_t learned_at_us;
			int hostgroup_probed;
		};
		mutable pthread_rwlock_t lock;
		std::unordered_map<std::string, entry_t> entries;

	public:
		MySQL_Passthrough_Auth_Cache();
		~MySQL_Passthrough_Auth_Cache();

		// Look up a cached credential. Returns true on hit (and populates
		// out_cleartext); false on miss. If ttl_s > 0 and the entry is older
		// than ttl_s, the entry is evicted and a miss is returned.
		bool lookup(const std::string& username, std::string& out_cleartext, uint32_t ttl_s);

		// Insert or replace a cached credential.
		void insert(const std::string& username, const std::string& cleartext, int hostgroup_probed);

		// Evict a single entry. Returns true if the entry was present.
		bool evict(const std::string& username);

		// Remove every entry.
		void clear();

		// Number of entries currently held.
		size_t size() const;

		// Snapshot of entries (without password) for stats / observability.
		std::vector<passthrough_entry_view> snapshot() const;

		void print_version();
};

#endif // PROXYSQL_MYSQL_PASSTHROUGH_AUTH_CACHE_H
