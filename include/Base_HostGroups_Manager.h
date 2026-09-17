template <typename HGC> class BaseSrvList;
template <typename HGC> class BaseHGC;
template <typename HGC> class Base_HostGroups_Manager;

class MyHGC;
class PgSQL_HGC;
class MySrvC;
class PgSQL_SrvC;
class MySrvList;
class PgSQL_SrvList;

// Forward declaration for WebUI monitoring metrics collector
namespace ProxySQL {
namespace Monitoring {
class MetricsCollector;
}
}

#include "proxysql.h"
#include "cpp.h"
#include "GTID_Server_Data.h"
#ifdef PROXYSQL31
#include "HostgroupPoolStats.h"
#endif


#include <atomic>
#include <thread>
#include <iostream>
#include <mutex>

// Headers for declaring Prometheus counters
#include "prometheus/counter.h"
#include "prometheus/gauge.h"

#include "thread.h"
#include "wqueue.h"

#include "ev.h"

#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#ifndef PROXYJSON
#define PROXYJSON
#include "../deps/json/json_fwd.hpp"
#endif // PROXYJSON

#include <variant>

#ifndef CLASS_BASE_HOSTGROUPS_MANAGER_H
#define CLASS_BASE_HOSTGROUPS_MANAGER_H

#ifdef DEBUG
/* */
//	Enabling STRESSTEST_POOL ProxySQL will do a lot of loops in the connection pool
//	This is for internal testing ONLY!!!!
//#define STRESSTEST_POOL
#endif // DEBUG


template <typename HGC>
class BaseSrvList {	// MySQL Server List
	private:
	HGC *myhgc;
	using TypeSrvC = typename std::conditional<
		 std::is_same_v<HGC, MyHGC>, MySrvC, PgSQL_SrvC
	>::type;
	int find_idx(TypeSrvC *);
	public:
	PtrArray *servers;
	unsigned int cnt() { return servers->len; }
	BaseSrvList(HGC *);
	~BaseSrvList();
	void add(TypeSrvC *);
	void remove(TypeSrvC *);
	TypeSrvC * idx(unsigned int i) {return (TypeSrvC *)servers->index(i); }

	friend class PgSQL_SrvList;
	friend class PgSQL_HGC;

};


template <typename HGC>
class BaseHGC {	// MySQL Host Group Container
	public:
	unsigned int hid;
#ifdef PROXYSQL31
	HostgroupPoolStats pool_stats;
#endif
	std::atomic<uint32_t> num_online_servers;
	time_t last_log_time_num_online_servers;
	unsigned long long current_time_now;
	uint32_t new_connections_now;
	using TypeSrvList = typename std::conditional<
		std::is_same_v<HGC, MyHGC>, MySrvList, PgSQL_SrvList
	>::type;
	BaseSrvList<HGC> *mysrvs;
	struct { // this is a series of attributes specific for each hostgroup
		char * init_connect;
		char * comment;
		char * ignore_session_variables_text; // this is the original version (text format) of ignore_session_variables
		uint32_t max_num_online_servers;
		uint32_t throttle_connections_per_sec;
		int32_t monitor_slave_lag_when_null;
		int32_t default_query_timeout;
		int8_t autocommit;
		int8_t free_connections_pct;
		int8_t handle_warnings;
		bool multiplex;
		bool connection_warming;
		bool configured; // this variable controls if attributes are configured or not. If not configured, they do not apply
		bool initialized; // this variable controls if attributes were ever configured or not. Used by reset_attributes()
		nlohmann::json * ignore_session_variables_json = nullptr; // the JSON format of ignore_session_variables
	} attributes;
	struct {
		int64_t weight;
		int64_t max_connections;
		int32_t use_ssl;
	} servers_defaults;
	void reset_attributes();
	inline
	bool handle_warnings_enabled() const {
		return attributes.configured == true && attributes.handle_warnings != -1 ? attributes.handle_warnings : mysql_thread___handle_warnings;
	}
	inline
	int32_t get_monitor_slave_lag_when_null() const {
		return attributes.configured == true && attributes.monitor_slave_lag_when_null != -1 ? attributes.monitor_slave_lag_when_null : mysql_thread___monitor_slave_lag_when_null;
	}
	BaseHGC(int);
	virtual ~BaseHGC();
	using TypeSrvC = typename std::conditional<
		 std::is_same_v<HGC, MyHGC>, MySrvC, PgSQL_SrvC
	>::type;
	using TypeSess = typename std::conditional<
		 std::is_same_v<HGC, MyHGC>, MySQL_Session, PgSQL_Session
	>::type;
	TypeSess *get_random_MySrvC(char * gtid_uuid, uint64_t gtid_trxid, int max_lag_ms, TypeSess *sess);
	void refresh_online_server_count();
	void log_num_online_server_count_error();
	inline
	bool online_servers_within_threshold() const {
		if (num_online_servers.load(std::memory_order_relaxed) <= attributes.max_num_online_servers) return true;
		return false;
	}
};


template <typename HGC>
class Base_HostGroups_Manager {
	private:
	SQLite3DB	*admindb;
	SQLite3DB	*mydb;
	pthread_mutex_t readonly_mutex;
	std::set<std::string> read_only_set1;
	std::set<std::string> read_only_set2;
	pthread_mutex_t lock;

	PtrArray *MyHostGroups;
	std::unordered_map<unsigned int, HGC *>MyHostGroups_map;

	HGC * MyHGC_create(unsigned int);

	public:
	Base_HostGroups_Manager();
	HGC * MyHGC_find(unsigned int);
	HGC * MyHGC_lookup(unsigned int);
	SQLite3_result * execute_query(char *query, char **error);
	SQLite3_result * execute_query_under_lock(const char *query, char **error);
#ifdef PROXYSQL31
	HostgroupPoolStats * get_hostgroup_pool_stats(unsigned int hid);
	SQLite3_result * SQL3_Hostgroup_Connection_Pool(bool reset);
#endif

	void wrlock();
	void wrunlock();
#ifdef DEBUG
	bool is_locked = false;
#endif

	friend class MySQL_HostGroups_Manager;
	friend class PgSQL_HostGroups_Manager;
	friend class ProxySQL::Monitoring::MetricsCollector;

};

#endif // CLASS_BASE_HOSTGROUPS_MANAGER_H
