#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "Base_HostGroups_Manager.h"


template BaseHGC<MyHGC>::BaseHGC(int);
template BaseHGC<MyHGC>::~BaseHGC();
template void BaseHGC<MyHGC>::log_num_online_server_count_error();
template void BaseHGC<MyHGC>::reset_attributes();
template void BaseHGC<MyHGC>::refresh_online_server_count();
template BaseHGC<PgSQL_HGC>::BaseHGC(int);
template BaseHGC<PgSQL_HGC>::~BaseHGC();
template void BaseHGC<PgSQL_HGC>::log_num_online_server_count_error();
template void BaseHGC<PgSQL_HGC>::reset_attributes();
template void BaseHGC<PgSQL_HGC>::refresh_online_server_count();

template<typename HGC>
using TypeSrvC = typename std::conditional<
    std::is_same_v<HGC, MyHGC>, MySrvC, PgSQL_SrvC
>::type;

template<typename HGC>
using TypeSess = typename std::conditional<
	std::is_same_v<HGC, MyHGC>, MySQL_Session, PgSQL_Session
>::type;


#include "MySQL_HostGroups_Manager.h"


#ifdef TEST_AURORA
if constexpr (std::is_same_v<HGC, MyHGC>) {
static unsigned long long array_mysrvc_total = 0;
static unsigned long long array_mysrvc_cands = 0;
}
#endif // TEST_AURORA

extern MySQL_Threads_Handler *GloMTH;


template<typename HGC>
BaseHGC<HGC>::BaseHGC(int _hid) {
	hid=_hid;
	if constexpr (std::is_same_v<HGC, MyHGC>) {
		mysrvs=new MySrvList(static_cast<HGC*>(this));
	} else if constexpr (std::is_same_v<HGC, PgSQL_HGC>) {
		mysrvs=new PgSQL_SrvList(static_cast<HGC*>(this));
	} else {
		assert(0);
	}
	current_time_now = 0;
	new_connections_now = 0;
	attributes.initialized = false;
	reset_attributes();
	// Uninitialized server defaults. Should later be initialized via 'mysql_hostgroup_attributes'.
	servers_defaults.weight = -1;
	servers_defaults.max_connections = -1;
	servers_defaults.use_ssl = -1;
	num_online_servers.store(0, std::memory_order_relaxed);;
	last_log_time_num_online_servers = 0;
}


template<typename HGC>
void BaseHGC<HGC>::reset_attributes() {
	if (attributes.initialized == false) {
		attributes.init_connect = NULL;
		attributes.comment = NULL;
		attributes.ignore_session_variables_text = NULL;
	}
	attributes.initialized = true;
	attributes.configured = false;
	attributes.max_num_online_servers = 1000000;
	attributes.throttle_connections_per_sec = 1000000;
	attributes.autocommit = -1;
	attributes.free_connections_pct = 10;
	attributes.handle_warnings = -1;
	attributes.monitor_slave_lag_when_null = -1;
	attributes.multiplex = true;
	attributes.connection_warming = false;
	free(attributes.init_connect);
	attributes.init_connect = NULL;
	free(attributes.comment);
	attributes.comment = NULL;
	free(attributes.ignore_session_variables_text);
	attributes.ignore_session_variables_text = NULL;
	if (attributes.ignore_session_variables_json) {
		delete attributes.ignore_session_variables_json;
		attributes.ignore_session_variables_json = NULL;
	}
}

template<typename HGC>
BaseHGC<HGC>::~BaseHGC() {
	reset_attributes(); // free all memory
	delete mysrvs;
}

template<typename HGC>
void BaseHGC<HGC>::refresh_online_server_count() {
	if (__sync_fetch_and_add(&glovars.shutdown, 0) != 0)
		return;
#ifdef DEBUG
	assert(MyHGM->is_locked);
#endif
	unsigned int online_servers_count = 0;
	if constexpr (std::is_same_v<HGC, MyHGC>) { // FIXME: this logic for now is enabled only for MySQL
	for (unsigned int i = 0; i < mysrvs->servers->len; i++) {
		TypeSrvC* mysrvc = (TypeSrvC*)mysrvs->servers->index(i);
		if (mysrvc->get_status() == MYSQL_SERVER_STATUS_ONLINE) {
			online_servers_count++;
		}
	}
	}
	num_online_servers.store(online_servers_count, std::memory_order_relaxed);
}

template<typename HGC>
void BaseHGC<HGC>::log_num_online_server_count_error() {
	const time_t curtime = time(NULL);
	// if this is the first time the method is called or if more than 10 seconds have passed since the last log
	if (last_log_time_num_online_servers == 0 ||
		((curtime - last_log_time_num_online_servers) > 10)) {
		last_log_time_num_online_servers = curtime;
		proxy_error(
			"Number of online servers detected in a hostgroup exceeds the configured maximum online servers. hostgroup:%u, num_online_servers:%u, max_online_servers:%u\n",
			hid, num_online_servers.load(std::memory_order_relaxed), attributes.max_num_online_servers);
	}
}
