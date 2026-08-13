/*
	RECENT CHANGELOG
	1.2.0723
		* almost completely rewritten
		* use of blocking call for new connections
    * use of Thread Pool instead of a thread per check type
	0.2.0902
		* original implementation
*/

#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <future>
#include <sstream>
#include <random>
#include "prometheus/counter.h"
#include "MySQL_Protocol.h"
#include "MySQL_HostGroups_Manager.h"
#include "MySQL_Monitor.hpp"
#include "ProxySQL_Cluster.hpp"
#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Resolution.h"
#include "proxysql_utils.h"

#include "thread.h"
#include "wqueue.h"

#include <fcntl.h>

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define MYSQL_MONITOR_VERSION "2.0.1226" DEB

#define SERVER_VERSION_READYSET "readyset"

#ifdef DEBUG
//#define VALGRIND_ENABLE_ERROR_REPORTING
//#define VALGRIND_DISABLE_ERROR_REPORTING
#include "valgrind.h"
#else
#define VALGRIND_ENABLE_ERROR_REPORTING
#define VALGRIND_DISABLE_ERROR_REPORTING
#endif // DEBUG

extern ProxySQL_Admin *GloAdmin;
extern MySQL_Threads_Handler *GloMTH;
extern ProxySQL_Cluster* GloProxyCluster;

static MySQL_Monitor *GloMyMon;

struct ServerInfo {
	std::string ipAddress;
	int port;

	// Default constructor (important for some operations)
	ServerInfo() : ipAddress(""), port(0) {}

	ServerInfo(const std::string& ip, int p) : ipAddress(ip), port(p) {}

	// Overload the < operator for std::set to compare ServerInfo objects
	bool operator<(const ServerInfo& other) const {
		if (ipAddress < other.ipAddress) {
			return true;
		} else if (ipAddress == other.ipAddress) {
			return port < other.port;
		} else {
			return false;
		}
	}
};

static std::set<ServerInfo> ReadySet_Servers;

#define SAFE_SQLITE3_STEP(_stmt) do {\
	do {\
		rc=(*proxy_sqlite3_step)(_stmt);\
		if (rc!=SQLITE_DONE) {\
			assert(rc==SQLITE_LOCKED);\
			usleep(100);\
		}\
	} while (rc!=SQLITE_DONE);\
} while (0)

#define MYSQL_OPENSSL_ERROR_CLEAR(_mysql) if (_mysql->options.use_ssl == 1) {\
	ERR_clear_error();\
}

using std::string;
using std::set;
using std::vector;
using std::unique_ptr;

template<typename T, bool check_monitor_enabled_flag = true>
class ConsumerThread : public Thread {
	wqueue<WorkItem<T>*>& m_queue;
	int thrn;
	char thr_name[16];
	public:
	ConsumerThread(wqueue<WorkItem<T>*>& queue, int _n, const char *thread_name=NULL) : m_queue(queue) {
		thrn=_n;
		if (thread_name && thread_name[0]) {
			snprintf(thr_name, sizeof(thr_name), "%.15s", thread_name);
		} else {
			snprintf(thr_name, sizeof(thr_name), "%.12s%03d", typeid(T).name(), thrn);
		}
	}
	void* run() {
		set_thread_name(thr_name, GloVars.set_thread_name);
		// Remove 1 item at a time and process it. Blocks if no items are
		// available to process.
		for (int i = 0; (thrn ? i < thrn : 1); i++) {
			//VALGRIND_DISABLE_ERROR_REPORTING;
			WorkItem<T>* item = static_cast<WorkItem<T>*>(m_queue.remove());
			//VALGRIND_ENABLE_ERROR_REPORTING;
			if (item == NULL) {
				if (thrn) {
					// we took a NULL item that wasn't meant to reach here! Add it again
					WorkItem<T>* item = NULL;
					m_queue.add(item);
				}
				// this is intentional to EXIT immediately
				goto cleanup;
			}


			if (item->start_routine) { // NULL is allowed, do nothing for it
				bool me = true;

				if (check_monitor_enabled_flag) {
					pthread_mutex_lock(&GloMyMon->mon_en_mutex);
					me = GloMyMon->monitor_enabled;
					pthread_mutex_unlock(&GloMyMon->mon_en_mutex);
				}

				if (me) {
					item->start_routine(item->data);
				}
			}
			for (auto ptr : item->data) {
				delete ptr;
			}
			item->data.clear();
			delete item;
		}
cleanup:
		// De-initializes per-thread structures. Required in all auxiliary threads using MySQL and SSL.
		mysql_thread_end();
		return NULL;
	}
};

using DNSResolverThread = ConsumerThread<DNS_Resolve_Data, false>;

static int wait_for_mysql(MYSQL *mysql, int status) {
	struct pollfd pfd;
	int timeout, res;

	pfd.fd = mysql_get_socket(mysql);
	pfd.events =
		(status & MYSQL_WAIT_READ ? POLLIN : 0) |
		(status & MYSQL_WAIT_WRITE ? POLLOUT : 0) |
		(status & MYSQL_WAIT_EXCEPT ? POLLPRI : 0);
	timeout = 10;
	res = poll(&pfd, 1, timeout);
	if (res == 0)
		return MYSQL_WAIT_TIMEOUT | status;
	else if (res < 0)
		return MYSQL_WAIT_TIMEOUT;
	else {
		int status = 0;
		if (pfd.revents & POLLIN) status |= MYSQL_WAIT_READ;
		if (pfd.revents & POLLOUT) status |= MYSQL_WAIT_WRITE;
		if (pfd.revents & POLLPRI) status |= MYSQL_WAIT_EXCEPT;
		return status;
	}
}

static void close_mysql(MYSQL *my) {
	if (my->net.pvio && !my->options.use_ssl) {
		char buff[5];
		mysql_hdr myhdr;
		myhdr.pkt_id=0;
		myhdr.pkt_length=1;
		memcpy(buff, &myhdr, sizeof(mysql_hdr));
		buff[4]=0x01;
		int fd=my->net.fd;
#ifdef __APPLE__
		int arg_on=1;
		setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (char *) &arg_on, sizeof(int));
		int wb=send(fd, buff, 5, 0);
#else
		int wb=send(fd, buff, 5, MSG_NOSIGNAL);
#endif
		fd+=wb; // dummy, to make compiler happy
		fd-=wb; // dummy, to make compiler happy
	}
	mysql_close_no_command(my);
}

class MonMySrvC {
	public:
	char *address;
	uint16_t port;
	std::unique_ptr<PtrArray> conns;
	MonMySrvC(char *a, uint16_t p) {
		address = strdup(a);
		port = p;
		conns = std::unique_ptr<PtrArray>(new PtrArray());
	};
	~MonMySrvC() {
		free(address);
		if (conns) {
			while (conns->len) {
				MYSQL* mysql = static_cast<MYSQL*>(conns->index(0));
				if (mysql) {
					mysql_close(mysql); mysql=NULL;
				}
				conns->remove_index_fast(0);
			}
		}
	}
};

class MySQL_Monitor_Connection_Pool {
private:
	std::mutex mutex;
#ifdef DEBUG
	pthread_mutex_t m2;
	PtrArray *conns;
#endif // DEBUG
//	std::map<std::pair<std::string, int>, std::vector<MYSQL*> > my_connections;
	std::unique_ptr<PtrArray> servers;
public:
	MYSQL * get_connection(char *hostname, int port, MySQL_Monitor_State_Data *mmsd);
	void put_connection(char *hostname, MySQL_Monitor_State_Data* mmsd);
	void purge_some_connections();
	/**
	 * @brief Purge idle monitor connections for a server.
	 *
	 * @details Removes the idle monitor connection pool entry matching the supplied hostname and port.
	 *   Active monitor tasks are not affected.
	 *
	 * @param hostname Server hostname to match.
	 * @param port Server port to match.
	 */
	void purge_connections(const char* hostname, int port);
	void purge_all_connections();
	void destroy_mysql_connection(MySQL_Monitor_State_Data* mmsd);
	MySQL_Monitor_Connection_Pool() {
		servers = std::unique_ptr<PtrArray>(new PtrArray());
#ifdef DEBUG
		conns = new PtrArray();
		pthread_mutex_init(&m2, NULL);
#endif // DEBUG
	};
	~MySQL_Monitor_Connection_Pool() {
		purge_all_connections();
#ifdef DEBUG
		pthread_mutex_destroy(&m2);
#endif // DEBUG
	}

	void conn_register(MySQL_Monitor_State_Data *mmsd) {
#ifdef DEBUG
		std::lock_guard<std::mutex> lock(mutex);
		pthread_mutex_lock(&m2);
		MYSQL* my = mmsd->mysql;
		for (unsigned int i=0; i<conns->len; i++) {
			MYSQL *my1 = (MYSQL *)conns->index(i);
			// 'my1' can be NULL due to connection cleanup
			if (my1 == nullptr) continue;
			assert(my!=my1);
		}
		proxy_debug(PROXY_DEBUG_MONITOR, 7,
			"Registering MYSQL with FD %d from mmsd %p and MYSQL %p\n", my->net.fd, mmsd, mmsd->mysql);
		conns->add(my);
		pthread_mutex_unlock(&m2);
#endif // DEBUG
		return;
	};
	/**
	 * @brief Unregister the conn from the supplied 'mmsd'.
	 * @details DEBUG only helper function useful for checking the get/put connection flow
	 *  for 'MySQL_Monitor_Connection_Pool'. This function should be called whenever a monitoring action does
	 *  no longer require the conn of it's 'MMSD' and the conn has been considered 'non-suited' for being
	 *  returned to the conn pool. This can be due to a failure in the data querying from the server itself,
	 *  or due to unexpected data retrieved from the server. Due to this, the flow for calling this function
	 *  during 'async' monitoring actions is:
	 *   - If an error has taken place during the fetching itself, this function shall be called as soon as
	 *     the failure is detected by the async state machine.
	 *   - In case no error has taken place (TASK_RESULT_SUCCESS), this function should be called by the
	 *     task-handler if it determines that the retrieved data is malformed. See handle_mmsd_mysql_conn.
	 * @param mmsd The 'mmsd' which conn should be unregistered.
	 */
	void conn_unregister(MySQL_Monitor_State_Data *mmsd, bool to_assert = true) {
#ifdef DEBUG
		std::lock_guard<std::mutex> lock(mutex);
		pthread_mutex_lock(&m2);
		MYSQL *my = mmsd->mysql;
		for (unsigned int i=0; i<conns->len; i++) {
			MYSQL *my1 = (MYSQL *)conns->index(i);
			if (my1 == my) {
				conns->remove_index_fast(i);
				proxy_debug(PROXY_DEBUG_MONITOR, 7,
					"Un-registering MYSQL with FD %d from mmsd %p and MYSQL %p\n", my->net.fd, mmsd, mmsd->mysql);
				pthread_mutex_unlock(&m2);
				return;
			}
		}
		// LCOV_EXCL_START
		if (to_assert) assert(0);
		// LCOV_EXCL_STOP
#endif // DEBUG
		// LCOV_EXCL_START
		return;
		// LCOV_EXCL_STOP
	};
};

void MySQL_Monitor_Connection_Pool::purge_all_connections() {
	std::lock_guard<std::mutex> lock(mutex);
#ifdef DEBUG
	pthread_mutex_lock(&m2);
#endif
	if (servers) {
		while (servers->len) {
			MonMySrvC* srv = static_cast<MonMySrvC*>(servers->index(0));
			if (srv) {
				delete srv;
			}
			servers->remove_index_fast(0);
		}
	}
#ifdef DEBUG
	conns->reset();
	pthread_mutex_unlock(&m2);
#endif
}

/**
 * @brief Purge idle monitor connections for a server.
 *
 * @details Removes the idle monitor connection pool entry matching the supplied hostname and port.
 *   Active monitor tasks are not affected.
 *
 * @param hostname Server hostname to match.
 * @param port Server port to match.
 */
void MySQL_Monitor_Connection_Pool::purge_connections(const char* hostname, int port) {
	std::lock_guard<std::mutex> lock(mutex);
#ifdef DEBUG
	pthread_mutex_lock(&m2);
#endif
	if (servers) {
		for (unsigned int i = 0; i < servers->len; i++) {
			MonMySrvC* srv = static_cast<MonMySrvC*>(servers->index(i));
			if (srv && srv->port == port && strcmp(hostname, srv->address) == 0) {
				proxy_debug(PROXY_DEBUG_MONITOR, 7,
					"Purging %u idle monitor connections for server %s:%d\n",
					srv->conns->len, hostname, port);
				delete srv;
				servers->remove_index_fast(i);
				break;
			}
		}
	}
#ifdef DEBUG
	pthread_mutex_unlock(&m2);
#endif
}

void MySQL_Monitor_Connection_Pool::destroy_mysql_connection(MySQL_Monitor_State_Data* mmsd) {
	if (mmsd->mysql) {
#ifdef DEBUG
		conn_unregister(mmsd);
#endif
		proxy_debug(PROXY_DEBUG_MONITOR, 7,
			"Destroying MYSQL with FD %d from mmsd %p and MYSQL %p\n", mmsd->mysql->net.fd, mmsd, mmsd->mysql);
		close_mysql(mmsd->mysql);
		mmsd->mysql=NULL;
	}
}

MYSQL * MySQL_Monitor_Connection_Pool::get_connection(char *hostname, int port, MySQL_Monitor_State_Data *mmsd) {
	std::lock_guard<std::mutex> lock(mutex);
#ifdef DEBUG
	pthread_mutex_lock(&m2);
#endif // DEBUG
	MYSQL *my = NULL;
	unsigned long long now = monotonic_time();
	for (unsigned int i=0; i<servers->len; i++) {
		MonMySrvC *srv = (MonMySrvC *)servers->index(i);
		if (srv->port == port && strcmp(hostname,srv->address)==0) {
			if (srv->conns->len) {
#ifdef DEBUG
				for (unsigned int j=0; j<srv->conns->len; j++) {
					MYSQL *my1 = (MYSQL *)srv->conns->index(j);
					for (unsigned int k=0; k<srv->conns->len; k++) {
						if (k!=j) {
							MYSQL *my2 = (MYSQL *)srv->conns->index(k);
							assert(my1!=my2);
						}
					}
				}
#endif // DEBUG
				std::vector<MYSQL*> skipped_conn;
				while (srv->conns->len) {
					unsigned int idx = rand() % srv->conns->len;
					MYSQL* mysql = (MYSQL*)srv->conns->remove_index_fast(idx);

					if (!mysql) continue;

					// close connection if not used for a while
					unsigned long long then = *(unsigned long long*)mysql->net.buff;
					if (now > (then + mysql_thread___monitor_ping_interval * 1000 * 10)) {
						MySQL_Monitor_State_Data* mmsd = new MySQL_Monitor_State_Data(MON_CLOSE_CONNECTION, (char*)"", 0, false);
						mmsd->mysql = mysql;
						GloMyMon->queue->add(new WorkItem<MySQL_Monitor_State_Data>(mmsd, NULL));
						continue;
					}

					// The pool is grouped by hostname and port, but the same server can
					// be monitored over plaintext and TLS. Keep connections that may
					// match another monitor task and continue searching for this one.
					bool connection_uses_ssl = mysql->options.use_ssl != 0;
					if (mmsd && connection_uses_ssl != mmsd->use_ssl) {
						skipped_conn.push_back(mysql);
						continue;
					}

					my = mysql;
					break;
				}

				// Return skipped connections to the pool
				for (MYSQL* mysql : skipped_conn) {
					srv->conns->add(mysql);
				}
#ifdef DEBUG
				// 'my' can be NULL due to connection cleanup, and can cause crash
				if (my) {
					for (unsigned int j=0; j<conns->len; j++) {
						MYSQL *my1 = (MYSQL *)conns->index(j);
						// 'my1' can be NULL due to connection cleanup
						if (!my1) continue;

						assert(my!=my1);
					}
					proxy_debug(PROXY_DEBUG_MONITOR, 7,
						"Registering MYSQL with FD %d from mmsd %p and MYSQL %p\n", my->net.fd, mmsd, my);
					conns->add(my);
				}
#endif // DEBUG
			}
#ifdef DEBUG
			pthread_mutex_unlock(&m2);
#endif // DEBUG
			return my;
		}
	}
#ifdef DEBUG
	pthread_mutex_unlock(&m2);
#endif // DEBUG
	return my;
}

void MySQL_Monitor_Connection_Pool::put_connection(char* hostname, MySQL_Monitor_State_Data* mmsd) {
	
	if (!mmsd->mysql) return;
	
	unsigned long long now = monotonic_time();
	int port = mmsd->port;
	MYSQL* my = mmsd->mysql;

	std::lock_guard<std::mutex> lock(mutex);

#ifdef DEBUG
	pthread_mutex_lock(&m2);
#endif
	* reinterpret_cast<unsigned long long*>(my->net.buff) = now;
	MonMySrvC* targetSrv = nullptr;

	for (unsigned int i = 0; i < servers->len; ++i) {
		auto* srv = static_cast<MonMySrvC*>(servers->index(i));
		if (srv->port == port && strcmp(hostname, srv->address) == 0) {
			targetSrv = srv;
			break;
		}
	}

	if (!targetSrv) {
		targetSrv = new MonMySrvC(hostname, port);
		servers->add(targetSrv);
	}

	targetSrv->conns->add(my);

#ifdef DEBUG
	// Remove connection from global debug list
	for (unsigned int j = 0; j < conns->len; ++j) {
		auto* registered = static_cast<MYSQL*>(conns->index(j));
		if (registered == my) {
			conns->remove_index_fast(j);
			proxy_debug(PROXY_DEBUG_MONITOR, 7,
				"Un-registering MYSQL with FD %d from mmsd %p and MYSQL %p\n", my->net.fd, mmsd, mmsd->mysql);
			pthread_mutex_unlock(&m2);
			mmsd->mysql = NULL;
			return;
		}
	}

	// LCOV_EXCL_START
	// Should never happen: connection must have been registered
	assert(false && "MYSQL connection not found in debug registry");
	// LCOV_EXCL_STOP
#endif
	mmsd->mysql = NULL;
}

void MySQL_Monitor_Connection_Pool::purge_some_connections() {
	unsigned long long now = monotonic_time();
	std::lock_guard<std::mutex> lock(mutex);
#ifdef DEBUG
	pthread_mutex_lock(&m2);
#endif // DEBUG
	for (unsigned int i=0; i<servers->len; i++) {
		MonMySrvC *srv = (MonMySrvC *)servers->index(i);
		while (srv->conns->len > 4) {
			MYSQL *my = (MYSQL *)srv->conns->remove_index_fast(0);
			MySQL_Monitor_State_Data *mmsd= new MySQL_Monitor_State_Data(MON_CLOSE_CONNECTION, (char *)"",0,false);
			mmsd->mysql=my;
			GloMyMon->queue->add(new WorkItem<MySQL_Monitor_State_Data>(mmsd,NULL));
		}
		for (unsigned int j=0 ; j<srv->conns->len ; j++) {
			MYSQL *my = (MYSQL *)srv->conns->index(j);
			unsigned long long then = *(unsigned long long*)my->net.buff;
			if (now > (then + mysql_thread___monitor_ping_interval*1000 * 10)) {
				srv->conns->remove_index_fast(j);
				MySQL_Monitor_State_Data *mmsd= new MySQL_Monitor_State_Data(MON_CLOSE_CONNECTION, (char *)"",0,false);
				mmsd->mysql=my;
				GloMyMon->queue->add(new WorkItem<MySQL_Monitor_State_Data>(mmsd,NULL));
			}
		}
	}
#ifdef DEBUG
	pthread_mutex_unlock(&m2);
#endif // DEBUG
}

/*
void MySQL_Monitor_Connection_Pool::purge_idle_connections() {
	unsigned long long now = monotonic_time();
	std::lock_guard<std::mutex> lock(mutex);
	for(auto it = my_connections.begin(); it != my_connections.end();) {
		auto& lst = it->second;
		for(auto it3 = lst.begin(); it3 != lst.end();) {
			MYSQL *my = *it3;
			unsigned long long then = *(unsigned long long*)my->net.buff;
			if (now > (then + mysql_thread___monitor_ping_interval*1000 * 3)) {
				MySQL_Monitor_State_Data *mmsd= new MySQL_Monitor_State_Data((char *)"",0,NULL,false);
				mmsd->mysql=my;
				GloMyMon->queue.add(new WorkItem(mmsd,NULL));
				std::swap(*it3, lst.back());
				if(it3 == lst.end() - 1)
					it3 = lst.erase(it3);
				else
					lst.pop_back();
			} else
				++it3;
		}
		if (lst.size()) {
			++it;
		} else {
			it = my_connections.erase(it);
		}
	}
}
*/

/*
MYSQL * MySQL_Monitor_Connection_Pool::get_connection(char *hostname, int port) {
	std::lock_guard<std::mutex> lock(mutex);
	auto it = my_connections.find(std::make_pair(hostname, port));
	if (it == my_connections.end() || !it->second.size())
		return NULL;
	MYSQL *my = it->second.back();
	it->second.pop_back();
	*(unsigned long long*)my->net.buff = 0;
	return my;
}

void MySQL_Monitor_Connection_Pool::put_connection(char *hostname, int port, MYSQL *my) {
	unsigned long long now = monotonic_time();
	std::lock_guard<std::mutex> lock(mutex);
	*(unsigned long long*)my->net.buff = now;
	//this doesn't work on old compilers
//	auto it = my_connections.emplace(std::piecewise_construct,
//		std::forward_as_tuple(hostname, port), std::forward_as_tuple()).first;
//	it->second.push_back(my);
	// code for old compilers (gcc 4.7 in debian7)
	auto it = my_connections.find(std::make_pair(string(hostname), port));
	if (it != my_connections.end()) {
		it->second.push_back(my);
	} else {
		my_connections[std::make_pair(hostname,port)].push_back(my);
	}
}
*/

/**
 * @brief MySQL 8 status query for Group Replication members.
 * @details Since 'MySQL 8' we rely on 'COUNT_TRANSACTIONS_REMOTE_IN_APPLIER_QUEUE', deprecating the previously
 *  required 'sys.gr_member_routing_candidate_status' view. Another additions:
 *  - A new field 'members' has been added to the query, containing the current cluster members as seen by the
 *  queried node. This field is used for auto discovery.
 *  - Server state 'RECOVERING' is now also considered when detecting if a member is a 'viable' candidate.
 */
const char MYSQL_8_GR_QUERY[] {
	"SELECT (SELECT IF ("
			"MEMBER_STATE='ONLINE' AND ("
				"(SELECT COUNT(*) FROM performance_schema.replication_group_members WHERE MEMBER_STATE NOT IN ('ONLINE', 'RECOVERING')) >="
					" ((SELECT COUNT(*) FROM performance_schema.replication_group_members)/2) = 0)"
			", 'YES', 'NO')) AS viable_candidate,"
		" (SELECT IF (@@read_only, 'YES', 'NO')) as read_only,"
		" COUNT_TRANSACTIONS_REMOTE_IN_APPLIER_QUEUE AS transactions_behind, "
		" (SELECT GROUP_CONCAT(CONCAT(member_host, ':', member_port)) FROM performance_schema.replication_group_members) AS members "
	"FROM "
		"performance_schema.replication_group_members "
		"JOIN performance_schema.replication_group_member_stats rgms USING(member_id) "
	"WHERE rgms.MEMBER_ID=@@SERVER_UUID"
};

MySQL_Monitor_State_Data::MySQL_Monitor_State_Data(MySQL_Monitor_State_Data_Task_Type task_type, char* h, int p, bool _use_ssl, int g) {
	task_id_ = task_type;
	task_handler_ = NULL;
	use_percona_heartbeat = false;
	task_result_ = MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_UNKNOWN;
	mysql = NULL;
	result = NULL;
	mysql_error_msg = NULL;
	mondb = NULL;
	hostname = strdup(h);
	port = p;
	use_ssl = _use_ssl;
	hostgroup_id = g;
	interr = 0;
	task_timeout_ = 0;
	task_expiry_time_ = 0;
	async_state_machine_ = ASYNC_IDLE;
	writer_hostgroup = 0;
	writer_is_also_reader = 0;
	max_transactions_behind = 0;
	max_transactions_behind_count = 0;
	aws_aurora_max_lag_ms = 0;
	aws_aurora_check_timeout_ms = 0;
	aws_aurora_add_lag_ms = 0;
	aws_aurora_min_lag_ms = 0;
	aws_aurora_lag_num_checks = 0;
	t1 = 0;
	t2 = 0;
}

MySQL_Monitor_State_Data::~MySQL_Monitor_State_Data() {
	if (hostname) {
		free(hostname);
	}
	
	if (result) {
		mysql_free_result(result);
	}
	
	if (mysql) {
		close_mysql(mysql);
	}

	if (mysql_error_msg) {
		free(mysql_error_msg);
	}
}

void MySQL_Monitor_State_Data::init_async() {
	assert(mysql);

	switch (task_id_) {
	case MON_PING:
		async_state_machine_ = ASYNC_PING_START;
		task_timeout_ = mysql_thread___monitor_ping_timeout;
		task_handler_ = &MySQL_Monitor_State_Data::ping_handler;
		break;
#if !defined(TEST_READONLY) && !defined(TEST_RDS_BGD)
	case MON_READ_ONLY:
		query_ = "SELECT @@global.read_only read_only";
		async_state_machine_ = ASYNC_QUERY_START;
		task_timeout_ = mysql_thread___monitor_read_only_timeout;
		task_handler_ = &MySQL_Monitor_State_Data::read_only_handler;
		break;
	case MON_INNODB_READ_ONLY:
		query_ = "SELECT @@global.innodb_read_only read_only";
		async_state_machine_ = ASYNC_QUERY_START;
		task_timeout_ = mysql_thread___monitor_read_only_timeout;
		task_handler_ = &MySQL_Monitor_State_Data::read_only_handler;
		break;
	case MON_SUPER_READ_ONLY:
		query_ = "SELECT @@global.super_read_only read_only";
		async_state_machine_ = ASYNC_QUERY_START;
		task_timeout_ = mysql_thread___monitor_read_only_timeout;
		task_handler_ = &MySQL_Monitor_State_Data::read_only_handler;
		break;
	case MON_READ_ONLY__AND__INNODB_READ_ONLY:
		query_ = "SELECT @@global.read_only&@@global.innodb_read_only read_only";
		async_state_machine_ = ASYNC_QUERY_START;
		task_timeout_ = mysql_thread___monitor_read_only_timeout;
		task_handler_ = &MySQL_Monitor_State_Data::read_only_handler;
		break;
	case MON_READ_ONLY__OR__INNODB_READ_ONLY:
		query_ = "SELECT @@global.read_only|@@global.innodb_read_only read_only";
		async_state_machine_ = ASYNC_QUERY_START;
		task_timeout_ = mysql_thread___monitor_read_only_timeout;
		task_handler_ = &MySQL_Monitor_State_Data::read_only_handler;
		break;
#else // TEST_READONLY || TEST_RDS_BGD
	case MON_READ_ONLY:
	case MON_INNODB_READ_ONLY:
	case MON_SUPER_READ_ONLY:
	case MON_READ_ONLY__AND__INNODB_READ_ONLY:
	case MON_READ_ONLY__OR__INNODB_READ_ONLY:
		query_ = "SELECT @@global.read_only read_only ";
		query_ += std::string(hostname) + ":" + std::to_string(port);
		async_state_machine_ = ASYNC_QUERY_START;
		task_timeout_ = mysql_thread___monitor_read_only_timeout;
		task_handler_ = &MySQL_Monitor_State_Data::read_only_handler;
		break;
#endif // TEST_READONLY || TEST_RDS_BGD
	case MON_AWS_RDS_TOPOLOGY_DISCOVERY:
		query_ = QUERY_AWS_RDS_TOPOLOGY_DISCOVERY;
		async_state_machine_ = ASYNC_QUERY_START;
		task_timeout_ = mysql_thread___monitor_read_only_timeout;
		task_handler_ = &MySQL_Monitor_State_Data::read_only_handler;
		break;
	case MON_GROUP_REPLICATION:
		async_state_machine_ = ASYNC_QUERY_START;
#ifdef TEST_GROUPREP
		{
			query_ = "SELECT viable_candidate,read_only,transactions_behind,members FROM GR_MEMBER_ROUTING_CANDIDATE_STATUS ";
			query_ += std::string(hostname) + ":" + std::to_string(port);
		}
#else
		// From MySQL-8: Query dependent on 'COUNT_TRANSACTIONS_REMOTE_IN_APPLIER_QUEUE'; deprecating the previously
		// used `sys.gr_member_routing_candidate_status` view.
		if (mysql_get_server_version(mysql) >= 80000) {
			query_ = MYSQL_8_GR_QUERY;
		} else {
			// If not MySQL 8 we default back to the old check
			query_ = "SELECT viable_candidate,read_only,transactions_behind FROM sys.gr_member_routing_candidate_status";
		}
#endif
		task_timeout_ = mysql_thread___monitor_groupreplication_healthcheck_timeout;
		task_handler_ = &MySQL_Monitor_State_Data::group_replication_handler;
		break;
	case MON_REPLICATION_LAG:
		async_state_machine_ = ASYNC_QUERY_START;
#ifdef TEST_REPLICATIONLAG
		// Simulator syntax allows 'SELECT <REPLICA|SLAVE> STATUS'
		{
			const std::string REPLICA { mysql_get_server_version(mysql) < 80023 ? "SLAVE" : "REPLICA" };
			query_ = "SELECT " + REPLICA + " STATUS ";
			query_ += std::string(hostname) + ":" + std::to_string(port);
		}
#else
		if (mysql_thread___monitor_replication_lag_use_percona_heartbeat && 
			mysql_thread___monitor_replication_lag_use_percona_heartbeat[0] != '\0') {
			use_percona_heartbeat = true;
			query_ = "SELECT MAX(ROUND(TIMESTAMPDIFF(MICROSECOND, ts, SYSDATE(6))/1000000)) AS Seconds_Behind_Master FROM ";
			query_ += mysql_thread___monitor_replication_lag_use_percona_heartbeat;
		} else {
			if (mysql_get_server_version(mysql) < 80023) {
				query_ = "SHOW SLAVE STATUS";
			} else {
				query_ = "SHOW REPLICA STATUS";
			}
		}
		if (strcasestr(mysql->server_version, (const char *)SERVER_VERSION_READYSET) != NULL) {
			query_ = "SHOW READYSET STATUS";
		}
#endif
		task_timeout_ = mysql_thread___monitor_replication_lag_timeout;
		task_handler_ = &MySQL_Monitor_State_Data::replication_lag_handler;
		break;
	case MON_GALERA:
		async_state_machine_ = ASYNC_QUERY_START;
#ifdef TEST_GALERA
		query_ = "SELECT wsrep_local_state , read_only , wsrep_local_recv_queue , wsrep_desync , wsrep_reject_queries , wsrep_sst_donor_rejects_queries , "
			" wsrep_cluster_status, pxc_maint_mode FROM HOST_STATUS_GALERA WHERE hostgroup_id=";
		query_ += std::to_string(writer_hostgroup) + " AND hostname='" + std::string(hostname) + "' AND port=" + std::to_string(port);
#else
		{
			// performance_schema.global_status is a MySQL-only table (added in 5.7).
			// INFORMATION_SCHEMA.GLOBAL_STATUS was deprecated in MySQL 8.0 and
			// removed in MySQL 8.4, so MySQL >= 5.7 must use performance_schema
			// (otherwise the monitor query fails on MySQL 8.4+/9.x). MariaDB never
			// implemented the performance_schema status tables and keeps
			// GLOBAL_STATUS in information_schema across all versions, so it must
			// be excluded explicitly (atoi("10.x-MariaDB") >= 8 would otherwise
			// route it to the performance_schema branch).
			// (The enclosing braces are required: this is a `switch` case body
			// and the variable declarations below are jumped over by sibling
			// `case` labels — without a scope, GCC errors with "jump to case
			// label" / "crosses initialization".)
			const char *sv = mysql->server_version;
			bool is_mariadb = (sv != NULL && strstr(sv, "MariaDB") != NULL);
			int sv_major = (sv != NULL) ? atoi(sv) : 0;
			bool use_perf_schema = !is_mariadb &&
				(sv_major >= 8 || (sv_major == 5 && sv != NULL && strncmp(sv, "5.7", 3) == 0));
			if (use_perf_schema) {
				query_ = "SELECT (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='WSREP_LOCAL_STATE') "
					"wsrep_local_state, @@read_only read_only, (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='WSREP_LOCAL_RECV_QUEUE') wsrep_local_recv_queue , "
					"@@wsrep_desync wsrep_desync, @@wsrep_reject_queries wsrep_reject_queries, @@wsrep_sst_donor_rejects_queries wsrep_sst_donor_rejects_queries, "
					"(SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='WSREP_CLUSTER_STATUS') wsrep_cluster_status , "
					"(SELECT COALESCE(MAX(VARIABLE_VALUE),'DISABLED') FROM performance_schema.global_variables WHERE variable_name='pxc_maint_mode') pxc_maint_mode ";
			} else {
				// MariaDB Galera (any version) and legacy MySQL/PXC < 5.7
				query_ = "SELECT (SELECT VARIABLE_VALUE FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME='WSREP_LOCAL_STATE') "
					"wsrep_local_state, @@read_only read_only, (SELECT VARIABLE_VALUE FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME='WSREP_LOCAL_RECV_QUEUE') wsrep_local_recv_queue , "
					"@@wsrep_desync wsrep_desync, @@wsrep_reject_queries wsrep_reject_queries, @@wsrep_sst_donor_rejects_queries wsrep_sst_donor_rejects_queries, "
					"(SELECT VARIABLE_VALUE FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME='WSREP_CLUSTER_STATUS') wsrep_cluster_status , (SELECT 'DISABLED') pxc_maint_mode";
			}
		}
#endif // TEST_GALERA
		task_timeout_ = mysql_thread___monitor_galera_healthcheck_timeout;
		task_handler_ = &MySQL_Monitor_State_Data::galera_handler;
		break;
	case MON_CLOSE_CONNECTION:
		break;
	case MON_CONNECT:
		break;
	case MON_AWS_AURORA:
		break;
	case MON_AWS_RDS_BGD:
		break;
	}
}

void MySQL_Monitor_State_Data::mark_task_as_timeout(unsigned long long time) {
	
	const bool stale_ip_timeout = GloMyMon && GloMyMon->timeout_validate_ip_change(this);
	task_result_ = stale_ip_timeout
		? MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT_STALE_IP
		: MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT;
	t2 = time;
	
	if (mysql_error_msg)
		free(mysql_error_msg);

	if (task_id_ == MON_PING) {
		async_state_machine_ = ASYNC_PING_TIMEOUT;
		mysql_error_msg = strdup(stale_ip_timeout ? "resolved IP no longer valid" : "timeout during ping");
	} else {
		async_state_machine_ = (async_state_machine_ == ASYNC_QUERY_CONT) ? ASYNC_QUERY_TIMEOUT : ASYNC_STORE_RESULT_TIMEOUT;
		mysql_error_msg = strdup(stale_ip_timeout ? "resolved IP no longer valid" : "timeout check");
	}
	if (stale_ip_timeout) {
		proxy_debug(PROXY_DEBUG_MONITOR, 5,
			"Ignoring monitor timeout for %s:%d because resolved IP is no longer valid\n",
			hostname, port);
	}
}

void * monitor_connect_pthread(void *arg) {
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	set_thread_name("MonitorConnect", GloVars.set_thread_name);
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	GloMyMon->monitor_connect();
	return NULL;
}

void * monitor_ping_pthread(void *arg) {
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	set_thread_name("MonitorPing", GloVars.set_thread_name);
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	GloMyMon->monitor_ping();
	return NULL;
}

void * monitor_read_only_pthread(void *arg) {
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	set_thread_name("MonitorReadOnly", GloVars.set_thread_name);
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	GloMyMon->monitor_read_only();
	return NULL;
}

void * monitor_group_replication_pthread(void *arg) {
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	set_thread_name("MonitorGR", GloVars.set_thread_name);
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	// GloMyMon->monitor_group_replication();
	GloMyMon->monitor_group_replication_2();
	return NULL;
}

void * monitor_galera_pthread(void *arg) {
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	set_thread_name("MonitorGalera", GloVars.set_thread_name);
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	GloMyMon->monitor_galera();
	return NULL;
}

void * monitor_aws_aurora_pthread(void *arg) {
//#ifndef NOJEM
//	bool cache=false;
//	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
//#endif
	set_thread_name("MonitorAurora", GloVars.set_thread_name);
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	GloMyMon->monitor_aws_aurora();
	return NULL;
}

void * monitor_aws_rds_bgd_pthread(void *arg) {
	set_thread_name("MonitorRdsBgd", GloVars.set_thread_name);

	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth())
		return NULL;

	GloMyMon->monitor_aws_rds_bgd();
	return NULL;
}

void * monitor_replication_lag_pthread(void *arg) {
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	set_thread_name("MonitReplicLag", GloVars.set_thread_name);
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	GloMyMon->monitor_replication_lag();
	return NULL;
}

void* monitor_dns_cache_pthread(void* arg) {
#ifndef NOJEM
	bool cache = false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	set_thread_name("MonitorDNSCache", GloVars.set_thread_name);
	while (GloMTH == NULL) {
		usleep(50000);
	}
	usleep(100000);
	GloMyMon->monitor_dns_cache();
	return NULL;
}

using metric_name = std::string;
using metric_help = std::string;
using metric_tags = std::map<std::string, std::string>;

using mon_counter_tuple =
	std::tuple<
		p_mon_counter::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using mon_gauge_tuple =
	std::tuple<
		p_mon_gauge::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using mon_counter_vector = std::vector<mon_counter_tuple>;
using mon_gauge_vector = std::vector<mon_gauge_tuple>;

/**
 * @brief Metrics map holding the metrics for the 'MySQL_Monitor' module.
 *
 * @note Some metrics in this map, share a common "id name", because
 *  they differ only by label, because of this, HELP is shared between
 *  them. For better visual identification of this groups they are
 *  sepparated using a line separator comment.
 */
const std::tuple<mon_counter_vector, mon_gauge_vector>
mon_metrics_map = std::make_tuple(
	mon_counter_vector {
		std::make_tuple (
			p_mon_counter::mysql_monitor_workers_started,
			"proxysql_mysql_monitor_workers_started_total",
			"Number of MySQL Monitor workers started.",
			metric_tags {}
		),

		// ====================================================================
		std::make_tuple (
			p_mon_counter::mysql_monitor_connect_check_ok,
			"proxysql_mysql_monitor_connect_check_total",
			"Number of (succeed|failed) 'connect checks' from 'monitor_connect_thread'.",
			metric_tags {
				{ "status", "ok" }
			}
		),
		std::make_tuple (
			p_mon_counter::mysql_monitor_connect_check_err,
			"proxysql_mysql_monitor_connect_check_total",
			"Number of (succeed|failed) 'connect checks' from 'monitor_connect_thread'.",
			metric_tags {
				{ "status", "err" }
			}
		),
		// ====================================================================

		// ====================================================================
		std::make_tuple (
			p_mon_counter::mysql_monitor_ping_check_ok,
			"proxysql_mysql_monitor_ping_check_total",
			"Number of (succeed|failed) 'ping checks' from 'monitor_ping_thread'.",
			metric_tags {
				{ "status", "ok" }
			}
		),
		std::make_tuple (
			p_mon_counter::mysql_monitor_ping_check_err,
			"proxysql_mysql_monitor_ping_check_total",
			"Number of (succeed|failed) 'ping checks' from 'monitor_ping_thread'.",
			metric_tags {
				{ "status", "err" }
			}
		),
		// ====================================================================

		// ====================================================================
		std::make_tuple (
			p_mon_counter::mysql_monitor_read_only_check_ok,
			"proxysql_mysql_monitor_read_only_check_total",
			"Number of (succeed|failed) 'read only checks' from 'monitor_read_only_thread'.",
			metric_tags {
				{ "status", "ok" }
			}
		),
		std::make_tuple (
			p_mon_counter::mysql_monitor_read_only_check_err,
			"proxysql_mysql_monitor_read_only_check_total",
			"Number of (succeed|failed) 'read only checks' from 'monitor_read_only_thread'.",
			metric_tags {
				{ "status", "err" }
			}
		),
		// ====================================================================

		// ====================================================================
		std::make_tuple (
			p_mon_counter::mysql_monitor_replication_lag_check_ok,
			"proxysql_mysql_monitor_replication_lag_check_total",
			"Number of (succeed|failed)'replication lag checks' from 'monitor_replication_lag_thread'.",
			metric_tags {
				{ "status", "ok" }
			}
		),
		std::make_tuple (
			p_mon_counter::mysql_monitor_replication_lag_check_err,
			"proxysql_mysql_monitor_replication_lag_check_total",
			"Number of (succeed|failed)'replication lag checks' from 'monitor_replication_lag_thread'.",
			metric_tags {
				{ "status", "err" }
			}
		),
		// ====================================================================

		// ====================================================================
		std::make_tuple(
			p_mon_counter::mysql_monitor_dns_cache_queried,
			"proxysql_mysql_monitor_dns_cache_queried",
			"Number of dns queried 'dns_cache_queried' from 'monitor_dns_resolver_thread'.",
			metric_tags {}
		),
		std::make_tuple(
			p_mon_counter::mysql_monitor_dns_cache_lookup_success,
			"proxysql_mysql_monitor_dns_cache_lookup_success",
			"Number of dns queried 'dns_cache_lookup_success' from 'monitor_dns_resolver_thread'.",
			metric_tags {}
		),
			std::make_tuple(
			p_mon_counter::mysql_monitor_dns_cache_record_updated,
			"proxysql_mysql_monitor_dns_cache_record_updated",
			"Number of dns queried 'dns_cache_record_updated' from 'monitor_dns_resolver_thread'.",
			metric_tags {}
		)
		// ====================================================================
	},
	mon_gauge_vector {
		std::make_tuple (
			p_mon_gauge::mysql_monitor_workers,
			"proxysql_mysql_monitor_workers",
			"Number of monitor workers threads.",
			metric_tags {}
		),
		std::make_tuple (
			p_mon_gauge::mysql_monitor_workers_aux,
			"proxysql_mysql_monitor_workers_aux",
			"Number of auxiliary monitor threads.",
			metric_tags {}
		)
	}
);

MySQL_Monitor::MySQL_Monitor() {
	dns_cache = std::make_shared<DNS_Cache>();
	dns_cache->set_counters(&dns_cache_queried, &dns_cache_lookup_success, &dns_cache_record_updated);
	GloMyMon = this;

	My_Conn_Pool=new MySQL_Monitor_Connection_Pool();

	queue = std::unique_ptr<wqueue<WorkItem<MySQL_Monitor_State_Data>*>>(new wqueue<WorkItem<MySQL_Monitor_State_Data>*>());

	pthread_mutex_init(&group_replication_mutex,NULL);
	Group_Replication_Hosts_resultset=NULL;

	pthread_mutex_init(&galera_mutex,NULL);
	Galera_Hosts_resultset=NULL;

	pthread_mutex_init(&aws_aurora_mutex,NULL);
	pthread_mutex_init(&aws_rds_bgd_mutex,NULL);
	pthread_mutex_init(&aws_rds_bgd_hosts_mutex,NULL);
	pthread_mutex_init(&mysql_servers_mutex,NULL);
	pthread_mutex_init(&proxysql_servers_mutex, NULL);
	AWS_Aurora_Hosts_resultset=NULL;
	AWS_Aurora_Hosts_resultset_checksum = 0;
	AWS_RDS_BGD_Hosts_resultset.reset();
	AWS_RDS_BGD_Hosts_checksum = 0;
	AWS_RDS_BGD_Cluster_checksum.clear();
	shutdown=false;
	monitor_enabled=true;	// default
	// create new SQLite datatabase
	monitordb = new SQLite3DB();
	monitordb->open((char *)"file:mem_monitordb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	// create 'monitor_internal_db' database and attach it to 'monitor'
	monitor_internal_db = new SQLite3DB();
	monitor_internal_db->open((char *)"file:mem_monitor_internal_db?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	monitordb->execute("ATTACH DATABASE 'file:mem_monitor_internal_db?mode=memory&cache=shared' AS 'monitor_internal'");
	// create 'admindb' and attach both 'monitor' and 'monitor_internal'
	admindb=new SQLite3DB();
	admindb->open((char *)"file:mem_admindb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	admindb->execute("ATTACH DATABASE 'file:mem_monitordb?mode=memory&cache=shared' AS 'monitor'");
	admindb->execute("ATTACH DATABASE 'file:mem_monitor_internal_db?mode=memory&cache=shared' AS 'monitor_internal'");
	// define monitoring tables
	tables_defs_monitor=new std::vector<table_def_t *>;
	tables_defs_monitor_internal=new std::vector<table_def_t *>;
	//insert_into_tables_defs(tables_defs_monitor,"mysql_server_connect", MONITOR_SQLITE_TABLE_MYSQL_SERVER_CONNECT);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_connect_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_CONNECT_LOG);
	//insert_into_tables_defs(tables_defs_monitor,"mysql_server_ping", MONITOR_SQLITE_TABLE_MYSQL_SERVER_PING);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_ping_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_PING_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_read_only_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_READ_ONLY_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_replication_lag_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_REPLICATION_LAG_LOG);
	insert_into_tables_defs(tables_defs_monitor,"readyset_status_log", MONITOR_SQLITE_TABLE_READYSET_STATUS_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_group_replication_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_GROUP_REPLICATION_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_galera_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_GALERA_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_aws_aurora_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_aws_aurora_check_status", MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_CHECK_STATUS);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_aws_aurora_failovers", MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_FAILOVERS);
	insert_into_tables_defs(tables_defs_monitor_internal,"mysql_servers", MONITOR_SQLITE_TABLE_MYSQL_SERVERS);
	insert_into_tables_defs(tables_defs_monitor_internal, "proxysql_servers", MONITOR_SQLITE_TABLE_PROXYSQL_SERVERS);
	// create monitoring tables
	check_and_build_standard_tables(monitordb, tables_defs_monitor);
	check_and_build_standard_tables(monitor_internal_db, tables_defs_monitor_internal);
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_connect_log_time_start ON mysql_server_connect_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_ping_log_time_start ON mysql_server_ping_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_read_only_log_time_start ON mysql_server_read_only_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_replication_lag_log_time_start ON mysql_server_replication_lag_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS readyset_status_log_time_start ON readyset_status_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_group_replication_log_time_start ON mysql_server_group_replication_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_galera_log_time_start ON mysql_server_galera_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_aws_aurora_log_time_start ON mysql_server_aws_aurora_log (time_start_us)");

	num_threads=2;
	aux_threads=0;
	started_threads=0;
	
	connect_check_OK = 0;
	connect_check_ERR = 0;
	ping_check_OK = 0;
	ping_check_ERR = 0;
	read_only_check_OK = 0;
	read_only_check_ERR = 0;
	replication_lag_check_OK = 0;
	replication_lag_check_ERR = 0;
	dns_cache_queried = 0;
	dns_cache_lookup_success = 0;
	dns_cache_record_updated = 0;
	force_dns_cache_update = false;

#ifdef DEBUG
	proxytest_forced_timeout = false;
#endif
/*
	if (GloMTH) {
		if (GloMTH->num_threads) {
			num_threads=GloMTH->num_threads*2;
		}
	}
	if (num_threads>16) {
		num_threads=16;	// limit to 16
	}
*/

	// Initialize prometheus metrics
	init_prometheus_counter_array<mon_metrics_map_idx, p_mon_counter>(mon_metrics_map, this->metrics.p_counter_array);
	init_prometheus_gauge_array<mon_metrics_map_idx, p_mon_gauge>(mon_metrics_map, this->metrics.p_gauge_array);
};

MySQL_Monitor::~MySQL_Monitor() {
	drop_tables_defs(tables_defs_monitor);
	delete tables_defs_monitor;
	drop_tables_defs(tables_defs_monitor_internal);
	delete tables_defs_monitor_internal;
	delete monitordb;
	delete monitor_internal_db;
	delete admindb;
	delete My_Conn_Pool;
	if (Group_Replication_Hosts_resultset) {
		delete Group_Replication_Hosts_resultset;
		Group_Replication_Hosts_resultset=NULL;
	}
	if (Galera_Hosts_resultset) {
		delete Galera_Hosts_resultset;
		Galera_Hosts_resultset=NULL;
	}
	if (AWS_Aurora_Hosts_resultset) {
		delete AWS_Aurora_Hosts_resultset;
		AWS_Aurora_Hosts_resultset=NULL;
	}
	AWS_RDS_BGD_Hosts_resultset.reset();
	AWS_RDS_BGD_Cluster_checksum.clear();
	pthread_mutex_destroy(&aws_rds_bgd_hosts_mutex);
	std::map<std::string, AWS_Aurora_monitor_node *>::iterator it2;
	AWS_Aurora_monitor_node *node=NULL;
	for (it2 = AWS_Aurora_Hosts_Map.begin(); it2 != AWS_Aurora_Hosts_Map.end(); ++it2) {
		node = it2->second;
		delete node;
	}
	AWS_Aurora_Hosts_Map.clear();
};

void MySQL_Monitor::p_update_metrics() {
	if (GloMyMon) {
		this->metrics.p_gauge_array[p_mon_gauge::mysql_monitor_workers]->Set(GloMyMon->num_threads);
		this->metrics.p_gauge_array[p_mon_gauge::mysql_monitor_workers_aux]->Set(GloMyMon->aux_threads);

		p_update_counter(this->metrics.p_counter_array[p_mon_counter::mysql_monitor_workers_started], GloMyMon->started_threads);
		p_update_counter(this->metrics.p_counter_array[p_mon_counter::mysql_monitor_connect_check_ok], GloMyMon->connect_check_OK);
		p_update_counter(this->metrics.p_counter_array[p_mon_counter::mysql_monitor_connect_check_err], GloMyMon->connect_check_ERR);
		p_update_counter(this->metrics.p_counter_array[p_mon_counter::mysql_monitor_ping_check_ok], GloMyMon->ping_check_OK);
		p_update_counter(this->metrics.p_counter_array[p_mon_counter::mysql_monitor_ping_check_err], GloMyMon->ping_check_ERR );
		p_update_counter(this->metrics.p_counter_array[p_mon_counter::mysql_monitor_read_only_check_ok], GloMyMon->read_only_check_OK);
		p_update_counter(this->metrics.p_counter_array[p_mon_counter::mysql_monitor_read_only_check_err], GloMyMon->read_only_check_ERR);
		p_update_counter(this->metrics.p_counter_array[p_mon_counter::mysql_monitor_replication_lag_check_ok], GloMyMon->replication_lag_check_OK);
		p_update_counter(this->metrics.p_counter_array[p_mon_counter::mysql_monitor_replication_lag_check_err], GloMyMon->replication_lag_check_ERR);
		p_update_counter(this->metrics.p_counter_array[p_mon_counter::mysql_monitor_dns_cache_queried], GloMyMon->dns_cache_queried.load());
		p_update_counter(this->metrics.p_counter_array[p_mon_counter::mysql_monitor_dns_cache_lookup_success], GloMyMon->dns_cache_lookup_success.load());
		p_update_counter(this->metrics.p_counter_array[p_mon_counter::mysql_monitor_dns_cache_record_updated], GloMyMon->dns_cache_record_updated.load());
	}
}

void MySQL_Monitor::print_version() {
	fprintf(stderr,"Standard MySQL Monitor (StdMyMon) rev. %s -- %s -- %s\n", MYSQL_MONITOR_VERSION, __FILE__, __TIMESTAMP__);
};

// This function is copied from ProxySQL_Admin
void MySQL_Monitor::insert_into_tables_defs(std::vector<table_def_t *> *tables_defs, const char *table_name, const char *table_def) {
	table_def_t *td = new table_def_t;
	td->table_name=strdup(table_name);
	td->table_def=strdup(table_def);
	tables_defs->push_back(td);
};

// This function is copied from ProxySQL_Admin
void MySQL_Monitor::drop_tables_defs(std::vector<table_def_t *> *tables_defs) {
	table_def_t *td;
	while (!tables_defs->empty()) {
		td=tables_defs->back();
		free(td->table_name);
		td->table_name=NULL;
		free(td->table_def);
		td->table_def=NULL;
		tables_defs->pop_back();
		delete td;
	}
};

// This function is copied from ProxySQL_Admin
void MySQL_Monitor::check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs) {
	table_def_t *td;
	db->execute("PRAGMA foreign_keys = OFF");
	for (std::vector<table_def_t *>::iterator it=tables_defs->begin(); it!=tables_defs->end(); ++it) {
		td=*it;
		db->check_and_build_table(td->table_name, td->table_def);
	}
	db->execute("PRAGMA foreign_keys = ON");
};

void MySQL_Monitor::update_monitor_mysql_servers(SQLite3_result* resultset) {
	pthread_mutex_lock(&GloMyMon->mysql_servers_mutex);

	if (resultset != nullptr) {
		int rc = 0;

		monitordb->execute("DELETE FROM monitor_internal.mysql_servers");

		std::string query32s = "INSERT INTO monitor_internal.mysql_servers VALUES " + generate_multi_rows_query(32,4);
		char* query1 = const_cast<char*>("INSERT INTO monitor_internal.mysql_servers VALUES (?1,?2,?3,?4)");
		char* query32 = (char *)query32s.c_str();

		auto [rc1, statement1_unique] = monitordb->prepare_v2(query1);
		ASSERT_SQLITE_OK(rc1, monitordb);
		auto [rc2, statement32_unique] = monitordb->prepare_v2(query32);
		ASSERT_SQLITE_OK(rc2, monitordb);
		sqlite3_stmt *statement1 = statement1_unique.get();
		sqlite3_stmt *statement32 = statement32_unique.get();

		int row_idx=0;
		int max_bulk_row_idx=resultset->rows_count/32;
		max_bulk_row_idx=max_bulk_row_idx*32;

		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row *r1=*it;
			int idx=row_idx%32;

			if (row_idx < max_bulk_row_idx) { // bulk
				rc=(*proxy_sqlite3_bind_text)(statement32, (idx*4)+1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*4)+2, atoi(r1->fields[1])); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*4)+3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*4)+4, atoi(r1->fields[3])); ASSERT_SQLITE_OK(rc, monitordb);

				if (idx==31) {
					SAFE_SQLITE3_STEP2(statement32);
					rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, monitordb);
					rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, monitordb);
				}
			} else { // single row
				rc=(*proxy_sqlite3_bind_text)(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoi(r1->fields[1])); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 4, atoi(r1->fields[3])); ASSERT_SQLITE_OK(rc, monitordb);

				SAFE_SQLITE3_STEP2(statement1);
				rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, monitordb);
			}
			row_idx++;
		}
	}

	pthread_mutex_unlock(&GloMyMon->mysql_servers_mutex);
}

void MySQL_Monitor::update_monitor_proxysql_servers(SQLite3_result* resultset) {
	pthread_mutex_lock(&GloMyMon->proxysql_servers_mutex);

	if (resultset != nullptr) {
		int rc = 0;

		monitordb->execute("DELETE FROM monitor_internal.proxysql_servers");

		std::string query32s = "INSERT INTO monitor_internal.proxysql_servers VALUES " + generate_multi_rows_query(32, 4);
		char* query1 = const_cast<char*>("INSERT INTO monitor_internal.proxysql_servers VALUES (?1,?2,?3,?4)");
		char* query32 = (char*)query32s.c_str();

		auto [rc1, statement1_unique] = monitordb->prepare_v2(query1);
		ASSERT_SQLITE_OK(rc1, monitordb);
		auto [rc2, statement32_unique] = monitordb->prepare_v2(query32);
		ASSERT_SQLITE_OK(rc2, monitordb);
		sqlite3_stmt* statement1 = statement1_unique.get();
		sqlite3_stmt* statement32 = statement32_unique.get();

		int row_idx = 0;
		int max_bulk_row_idx = resultset->rows_count / 32;
		max_bulk_row_idx = max_bulk_row_idx * 32;

		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r1 = *it;
			int idx = row_idx % 32;

			if (row_idx < max_bulk_row_idx) { // bulk
				rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 4) + 1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 4) + 2, atoi(r1->fields[1])); ASSERT_SQLITE_OK(rc, monitordb);
				rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 4) + 3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, monitordb);
				rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 4) + 4, r1->fields[3], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);

				if (idx == 31) {
					SAFE_SQLITE3_STEP2(statement32);
					rc = (*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, monitordb);
					rc = (*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, monitordb);
				}
			}
			else { // single row
				rc = (*proxy_sqlite3_bind_text)(statement1, 1, r1->fields[0], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				rc = (*proxy_sqlite3_bind_int64)(statement1, 2, atoi(r1->fields[1])); ASSERT_SQLITE_OK(rc, monitordb);
				rc = (*proxy_sqlite3_bind_int64)(statement1, 3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, monitordb);
				rc = (*proxy_sqlite3_bind_text)(statement1, 4, r1->fields[3], - 1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);

				SAFE_SQLITE3_STEP2(statement1);
				rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, monitordb);
				rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, monitordb);
			}
			row_idx++;
		}
	}

	pthread_mutex_unlock(&GloMyMon->proxysql_servers_mutex);
}

void * monitor_connect_thread(const std::vector<MySQL_Monitor_State_Data*>& mmsds) {
	assert(!mmsds.empty());
	mysql_close(mysql_init(NULL));
	MySQL_Monitor_State_Data *mmsd = mmsds.front();
	// Wait for GloMTH to be initialized
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	mysql_thr->refresh_variables();

	bool connect_success = false;
	mmsd->create_new_connection();

	unsigned long long start_time=mysql_thr->curtime;
	mmsd->t1=start_time;
	mmsd->t2=monotonic_time();

	char *query=NULL;
	query=(char *)"INSERT OR REPLACE INTO mysql_server_connect_log VALUES (?1 , ?2 , ?3 , ?4 , ?5)";
	auto [rc1, statement_unique] = mmsd->mondb->prepare_v2(query);
	ASSERT_SQLITE_OK(rc1, mmsd->mondb);
	sqlite3_stmt *statement = statement_unique.get();
	int rc;
	rc=(*proxy_sqlite3_bind_text)(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
	rc=(*proxy_sqlite3_bind_int)(statement, 2, mmsd->port); ASSERT_SQLITE_OK(rc, mmsd->mondb);
	unsigned long long time_now=realtime_time();
	time_now=time_now-(mmsd->t2 - start_time);
	rc=(*proxy_sqlite3_bind_int64)(statement, 3, time_now); ASSERT_SQLITE_OK(rc, mmsd->mondb);
	rc=(*proxy_sqlite3_bind_int64)(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1)); ASSERT_SQLITE_OK(rc, mmsd->mondb);
	rc=(*proxy_sqlite3_bind_text)(statement, 5, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
	SAFE_SQLITE3_STEP2(statement);
	rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);
	rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);
	if (mmsd->mysql_error_msg) {
		if (
			(strncmp(mmsd->mysql_error_msg,"Access denied for user",strlen("Access denied for user"))==0)
			||
			(strncmp(mmsd->mysql_error_msg,"ProxySQL Error: Access denied for user",strlen("ProxySQL Error: Access denied for user"))==0)
		) {
			proxy_error("Server %s:%d is returning \"Access denied\" for monitoring user\n", mmsd->hostname, mmsd->port);
		}
		else if (strncmp(mmsd->mysql_error_msg,"Your password has expired.",strlen("Your password has expired."))==0)
		{
			proxy_error("Server %s:%d is returning \"Your password has expired.\" for monitoring user\n", mmsd->hostname, mmsd->port);
		}
		MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
	} else {
		connect_success = true;
	}
	if (mmsd->mysql) {
		mysql_close(mmsd->mysql);
		mmsd->mysql=NULL;
	}
	if (connect_success) {
		__sync_fetch_and_add(&GloMyMon->connect_check_OK,1);
	} else {
		__sync_fetch_and_add(&GloMyMon->connect_check_ERR,1);
	}
	delete mysql_thr;
	return NULL;
}

void * monitor_ping_thread(const std::vector<MySQL_Monitor_State_Data*>& mmsds) {
	assert(!mmsds.empty());
	mysql_close(mysql_init(NULL));
	MySQL_Monitor_State_Data *mmsd = mmsds.front();
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	mysql_thr->refresh_variables();

	bool ping_success = false;
	mmsd->mysql=GloMyMon->My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port, mmsd);
	unsigned long long start_time=mysql_thr->curtime;

	mmsd->t1=start_time;
	bool crc=false;
	if (mmsd->mysql==NULL) { // we don't have a connection, let's create it
		bool rc;
		rc=mmsd->create_new_connection();
		if (mmsd->mysql) {
			GloMyMon->My_Conn_Pool->conn_register(mmsd);
		}
		crc=true;
		if (rc==false) {
			goto __exit_monitor_ping_thread;
		}
	} else {
		//GloMyMon->My_Conn_Pool->conn_register(mmsd);
	}

	mmsd->t1=monotonic_time();
	//async_exit_status=mysql_change_user_start(&ret_bool, mysql,"msandbox2","msandbox2","information_schema");
	mmsd->interr=0; // reset the value
	mmsd->async_exit_status=mysql_ping_start(&mmsd->interr,mmsd->mysql);
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
#ifdef DEBUG
		const unsigned long long now = (GloMyMon->proxytest_forced_timeout == false) ? monotonic_time() : ULLONG_MAX;
#else
		const unsigned long long now = monotonic_time();
#endif
		if (now > mmsd->t1 + mysql_thread___monitor_ping_timeout * 1000) {
			mmsd->mysql_error_msg=strdup("timeout during ping");
			goto __exit_monitor_ping_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_ping_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_ping_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) { // ping failed
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
		MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
		//proxy_warning("Got error. mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
	} else {
		if (crc==false) {
			GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
		}
	}

__exit_monitor_ping_thread:
	mmsd->t2=monotonic_time();
	{
		char *query=NULL;
		query=(char *)"INSERT OR REPLACE INTO mysql_server_ping_log VALUES (?1 , ?2 , ?3 , ?4 , ?5)";
		auto [rc1, statement_unique] = mmsd->mondb->prepare_v2(query);
		ASSERT_SQLITE_OK(rc1, mmsd->mondb);
		sqlite3_stmt *statement = statement_unique.get();
		int rc;
		rc=(*proxy_sqlite3_bind_text)(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		rc=(*proxy_sqlite3_bind_int)(statement, 2, mmsd->port); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		unsigned long long time_now=realtime_time();
		time_now=time_now-(mmsd->t2 - start_time);
		rc=(*proxy_sqlite3_bind_int64)(statement, 3, time_now); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1)); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		rc=(*proxy_sqlite3_bind_text)(statement, 5, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		SAFE_SQLITE3_STEP2(statement);
		rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		if (mmsd->mysql_error_msg == NULL) {
			ping_success = true;
		}
#ifdef TEST_AURORA
//		}
#endif // TEST_AURORA
	}
__fast_exit_monitor_ping_thread:
	if (mmsd->mysql) {
		// if we reached here we didn't put the connection back
		mmsd->t2=monotonic_time();
		if (mmsd->mysql_error_msg) {
#ifdef DEBUG
			proxy_error("Error after %lldms: server %s:%d , mmsd %p , MYSQL %p , FD %d : %s\n", (mmsd->t2-mmsd->t1)/1000, mmsd->hostname, mmsd->port, mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
#else
			proxy_error("Error after %lldms on server %s:%d : %s\n", (mmsd->t2-mmsd->t1)/1000, mmsd->hostname, mmsd->port, mmsd->mysql_error_msg);
#endif // DEBUG
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
			GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
		} else {
			if (crc) {
				bool rc=mmsd->set_wait_timeout();
				if (rc) {
					GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
				} else {
#ifdef DEBUG
					proxy_error("Error on: mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
#else
					proxy_error("Error on server %s:%d : %s\n", mmsd->hostname, mmsd->port, mmsd->mysql_error_msg);
#endif // DEBUG
					MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
					GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
				}
			} else { // really not sure how we reached here, drop it
				proxy_error("Error after %lldms: mmsd %p , MYSQL %p , FD %d : %s\n", (mmsd->t2-mmsd->t1)/1000, mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
				GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
			}
		}
	}
	if (ping_success) {
		__sync_fetch_and_add(&GloMyMon->ping_check_OK,1);
	} else {
		__sync_fetch_and_add(&GloMyMon->ping_check_ERR,1);
	}
	delete mysql_thr;
	return NULL;
}

bool MySQL_Monitor_State_Data::set_wait_timeout() {
	if (mysql_thread___monitor_wait_timeout==false) {
		return true;
	}
#if defined(TEST_AURORA) || defined(TEST_GALERA) || defined(TEST_GROUPREP)
	return true;
#endif // TEST_AURORA || TEST_GALERA || TEST_GROUPREP
	bool ret=false;
	char *query=NULL;
	char *qt=(char *)"SET wait_timeout=%d";
	int wait_timeout=mysql_thread___monitor_ping_interval*10/1000;	// convert to second and multiply by 10
	query=(char *)malloc(strlen(qt)+32);
	sprintf(query,qt,wait_timeout);
	t1=monotonic_time();
	async_exit_status=mysql_query_start(&interr,mysql,query);
	while (async_exit_status) {
		async_exit_status=wait_for_mysql(mysql, async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > t1 + mysql_thread___monitor_ping_timeout * 1000) {
			mysql_error_msg=strdup("timeout");
			goto __exit_set_wait_timeout;
		}
		if (GloMyMon->shutdown==true) {
			goto __exit_set_wait_timeout;	// exit immediately
		}
		if ((async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			async_exit_status=mysql_query_cont(&interr, mysql, async_exit_status);
		}
	}
	if (interr) { // SET failed
		ret=false;
	} else {
		ret=true;
	}
__exit_set_wait_timeout:
	free(query);
	return ret;
}

bool MySQL_Monitor_State_Data::create_new_connection() {
	mysql=mysql_init(NULL);
	assert(mysql);
	std::unique_ptr<MySQLServers_SslParams> ssl_params { nullptr };
	if (use_ssl && port) {
		ssl_params = std::unique_ptr<MySQLServers_SslParams>(
			MyHGM->get_Server_SSL_Params(hostname, port, mysql_thread___monitor_username)
		);
		MySQL_Connection::set_ssl_params(mysql, ssl_params.get());
		mysql_options(mysql, MARIADB_OPT_SSL_KEYLOG_CALLBACK, (void*)proxysql_keylog_write_line_callback);
	}
	unsigned int timeout=mysql_thread___monitor_connect_timeout/1000;
	if (timeout==0) timeout=1;
	mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "program_name", "proxysql_monitor");
	mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "_server_host", hostname);
	MYSQL *myrc=NULL;
	if (port) {
		myrc=mysql_real_connect(mysql, MySQL_Monitor::dns_lookup(hostname).c_str(), mysql_thread___monitor_username, mysql_thread___monitor_password, NULL, port, NULL, 0);
	} else {
		myrc=mysql_real_connect(mysql, "localhost", mysql_thread___monitor_username, mysql_thread___monitor_password, NULL, 0, hostname, 0);
	}
	if (myrc==NULL) {
		mysql_error_msg=strdup(mysql_error(mysql));
		int myerrno=mysql_errno(mysql);
		MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, hostgroup_id, hostname, port, myerrno);
		if (ssl_params != NULL && myerrno == 2026) {
			proxy_error("Failed to connect to server %s:%d . SSL Params: %s , %s , %s , %s , %s , %s , %s , %s\n",
				( port ? hostname : "localhost" ) , port ,
				ssl_params->ssl_ca.c_str() , ssl_params->ssl_cert.c_str() , ssl_params->ssl_key.c_str() , ssl_params->ssl_capath.c_str() ,
				ssl_params->ssl_crl.c_str() , ssl_params->ssl_crlpath.c_str() , ssl_params->ssl_cipher.c_str() , ssl_params->tls_version.c_str()
			);
		}
		if (myerrno < 2000) {
			mysql_close(mysql);
		} else {
			close_mysql(mysql);
		}
		mysql = NULL;
		return false;
	} else {
		// mariadb client library disables NONBLOCK for SSL connections ... re-enable it!
		mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
		int f=fcntl(mysql->net.fd, F_GETFL);
#ifdef FD_CLOEXEC
		// asynchronously set also FD_CLOEXEC , this to prevent then when a fork happens the FD are duplicated to new process
		fcntl(mysql->net.fd, F_SETFL, f|O_NONBLOCK|FD_CLOEXEC);
#else
		fcntl(mysql->net.fd, F_SETFL, f|O_NONBLOCK);
#endif /* FD_CLOEXEC */
		MySQL_Monitor::update_dns_cache_from_mysql_conn(mysql);
	}
	return true;
}

void * monitor_read_only_thread(const std::vector<MySQL_Monitor_State_Data*>& data) {
	assert(!data.empty());
	mysql_close(mysql_init(NULL));
	bool timeout_reached = false;
	MySQL_Monitor_State_Data *mmsd = data.front();
	std::string monitor_query;
	bool stale_ip_timeout = false;
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	mysql_thr->refresh_variables();

	mmsd->mysql=GloMyMon->My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port, mmsd);
	unsigned long long start_time=mysql_thr->curtime;

	bool read_only_success = false;
	mmsd->t1=start_time;

	bool crc=false;
	if (mmsd->mysql==NULL) { // we don't have a connection, let's create it
		bool rc;
		rc=mmsd->create_new_connection();
		if (mmsd->mysql) {
			GloMyMon->My_Conn_Pool->conn_register(mmsd);
		}
		crc=true;
		if (rc==false) {
			unsigned long long now=monotonic_time();
			char * new_error = (char *)malloc(50+strlen(mmsd->mysql_error_msg));
			sprintf(new_error,"timeout on creating new connection: %s",mmsd->mysql_error_msg);
			free(mmsd->mysql_error_msg);
			mmsd->mysql_error_msg = new_error;
			proxy_error("Timeout on read_only check for %s:%d after %lldms. Unable to create a connection. If the server is overload, increase mysql-monitor_connect_timeout. Error: %s.\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000, new_error);
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_READ_ONLY_CHECK_CONN_TIMEOUT);
			timeout_reached = true;
			goto __exit_monitor_read_only_thread;
			//goto __fast_exit_monitor_read_only_thread;
		}
	}

	mmsd->t1=monotonic_time();
	mmsd->interr=0; // reset the value
	if (mmsd->get_task_type() == MON_AWS_RDS_TOPOLOGY_DISCOVERY) {
		monitor_query = QUERY_AWS_RDS_TOPOLOGY_DISCOVERY;
	} else {
#if defined(TEST_READONLY) || defined(TEST_RDS_BGD)
		monitor_query = "SELECT @@global.read_only read_only";
		monitor_query += " " + std::string(mmsd->hostname) + ":" + std::to_string(mmsd->port);
#else
		if (mmsd->get_task_type() == MON_INNODB_READ_ONLY) {
			monitor_query = "SELECT @@global.innodb_read_only read_only";
		} else if (mmsd->get_task_type() == MON_SUPER_READ_ONLY) {
			monitor_query = "SELECT @@global.super_read_only read_only";
		} else if (mmsd->get_task_type() == MON_READ_ONLY__AND__INNODB_READ_ONLY) {
			monitor_query = "SELECT @@global.read_only&@@global.innodb_read_only read_only";
		} else if (mmsd->get_task_type() == MON_READ_ONLY__OR__INNODB_READ_ONLY) {
			monitor_query = "SELECT @@global.read_only|@@global.innodb_read_only read_only";
		} else { // default
			monitor_query = "SELECT @@global.read_only read_only";
		}
#endif // TEST_READONLY || TEST_RDS_BGD
	}
	mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,monitor_query.c_str());
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
#ifdef DEBUG
		const unsigned long long now = (GloMyMon->proxytest_forced_timeout == false) ? monotonic_time() : ULLONG_MAX;
#else
		const unsigned long long now = monotonic_time();
#endif
		if (now > mmsd->t1 + mysql_thread___monitor_read_only_timeout * 1000) {
			stale_ip_timeout = GloMyMon->timeout_validate_ip_change(mmsd);
			mmsd->mysql_error_msg=strdup(stale_ip_timeout ? "resolved IP no longer valid" : "timeout check");
			if (stale_ip_timeout) {
				proxy_debug(PROXY_DEBUG_MONITOR, 5,
					"Ignoring read_only timeout for %s:%d because resolved IP is no longer valid\n",
					mmsd->hostname, mmsd->port);
			} else {
				proxy_error("Timeout on read_only check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_read_only_timeout.\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_READ_ONLY_CHECK_TIMEOUT);
			}
			timeout_reached = true;
			goto __exit_monitor_read_only_thread;
		}
		if (mmsd->interr) {
			// error during query
			mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
			goto __exit_monitor_read_only_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_read_only_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_query_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) {
		// error during query
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
		MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
		goto __exit_monitor_read_only_thread;
	}
	mmsd->async_exit_status=mysql_store_result_start(&mmsd->result,mmsd->mysql);
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
#ifdef DEBUG
		const unsigned long long now = (GloMyMon->proxytest_forced_timeout == false) ? monotonic_time() : ULLONG_MAX;
#else
		const unsigned long long now = monotonic_time();
#endif
		if (now > mmsd->t1 + mysql_thread___monitor_read_only_timeout * 1000) {
			stale_ip_timeout = GloMyMon->timeout_validate_ip_change(mmsd);
			mmsd->mysql_error_msg=strdup(stale_ip_timeout ? "resolved IP no longer valid" : "timeout check");
			if (stale_ip_timeout) {
				proxy_debug(PROXY_DEBUG_MONITOR, 5,
					"Ignoring read_only timeout for %s:%d because resolved IP is no longer valid\n",
					mmsd->hostname, mmsd->port);
			} else {
				proxy_error("Timeout on read_only check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_read_only_timeout.\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_READ_ONLY_CHECK_TIMEOUT);
			}
			timeout_reached = true;
			goto __exit_monitor_read_only_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_read_only_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_store_result_cont(&mmsd->result, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) { // ping failed
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
		MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
	}

__exit_monitor_read_only_thread:
	mmsd->t2=monotonic_time();
	if (mmsd->get_task_type() == MON_AWS_RDS_TOPOLOGY_DISCOVERY) {
		if (mmsd->interr == 0 && mmsd->result) {
			GloMyMon->process_aws_rds_topology(mmsd);
			mysql_free_result(mmsd->result);
			mmsd->result = NULL;
			read_only_success = true;
		}
	} else {  /* handle read_only checks */
		char *query=NULL;
		query=(char *)"INSERT OR REPLACE INTO mysql_server_read_only_log VALUES (?1 , ?2 , ?3 , ?4 , ?5 , ?6)";
		auto [rc1, statement_unique] = mmsd->mondb->prepare_v2(query);
		ASSERT_SQLITE_OK(rc1, mmsd->mondb);
		sqlite3_stmt *statement = statement_unique.get();
		int rc;
		int read_only=1; // as a safety mechanism , read_only=1 is the default
		bool valid_result = true;
		rc=(*proxy_sqlite3_bind_text)(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		rc=(*proxy_sqlite3_bind_int)(statement, 2, mmsd->port); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		unsigned long long time_now=realtime_time();
		time_now=time_now-(mmsd->t2 - start_time);
		rc=(*proxy_sqlite3_bind_int64)(statement, 3, time_now); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1)); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		if (mmsd->interr == 0 && mmsd->result) {
			int num_fields=0;
			int k=0;
			MYSQL_FIELD *fields = mysql_fetch_fields(mmsd->result);
			int j=-1;
			num_fields = mysql_num_fields(mmsd->result);
			fields = mysql_fetch_fields(mmsd->result);
			if (fields && num_fields == 1) {
				for(k = 0; k < num_fields; k++) {
 					if (strcmp((char *)"read_only", (char *)fields[k].name)==0) {
						j=k;
					}
				}
				if (j>-1) {
					MYSQL_ROW row=mysql_fetch_row(mmsd->result);
					if (row) {
VALGRIND_DISABLE_ERROR_REPORTING;
						if (row[j]) {
							if (!strcmp(row[j],"0") || !strcasecmp(row[j],"OFF"))
								read_only=0;
						}
VALGRIND_ENABLE_ERROR_REPORTING;
					}
				}
//					if (repl_lag>=0) {
				rc=(*proxy_sqlite3_bind_int64)(statement, 5, read_only); ASSERT_SQLITE_OK(rc, mmsd->mondb);
//					} else {
//						rc=(*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
//					}
			} else {
				valid_result = false;
				rc=(*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
				proxy_error("mysql_fetch_fields returns NULL, or mysql_num_fields is incorrect. Server %s:%d . See bug #1994\n", mmsd->hostname, mmsd->port);
				proxy_info("Dumping read_only result for server %s:%d, query: %s\n", mmsd->hostname, mmsd->port, monitor_query.c_str());
				dump_mysql_result(stderr, mmsd->result);
			}
			mysql_free_result(mmsd->result);
			mmsd->result=NULL;
		} else {
			rc=(*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		}
		if (mmsd->result) {
			// make sure it is clear
			mysql_free_result(mmsd->result);
			mmsd->result=NULL;
		}
		rc=(*proxy_sqlite3_bind_text)(statement, 6, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		SAFE_SQLITE3_STEP2(statement);
		rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);

		if (valid_result && mmsd->mysql_error_msg == NULL) {
			read_only_success = true;
		}

		if (!valid_result || stale_ip_timeout) {
			// Ignore; do not infer backend state.
		} else if (timeout_reached == false && mmsd->interr == 0) {
			MyHGM->read_only_action_v2( std::list<read_only_server_t> {
										read_only_server_t { mmsd->hostname, mmsd->port, read_only }
										} ); // default behavior
		} else {
			char *error=NULL;
			int cols=0;
			int affected_rows=0;
			SQLite3_result *resultset=NULL;
			char *new_query=NULL;
			SQLite3DB *mondb=mmsd->mondb;
			new_query=(char *)"SELECT 1 FROM (SELECT hostname,port,read_only,error FROM mysql_server_read_only_log WHERE hostname='%s' AND port='%d' ORDER BY time_start_us DESC LIMIT %d) a WHERE read_only IS NULL AND SUBSTR(error,1,7) = 'timeout' GROUP BY hostname,port HAVING COUNT(*)=%d";
			char *buff=(char *)malloc(strlen(new_query)+strlen(mmsd->hostname)+32);
			int max_failures=mysql_thread___monitor_read_only_max_timeout_count;
			sprintf(buff,new_query, mmsd->hostname, mmsd->port, max_failures, max_failures);
			mondb->execute_statement(buff, &error , &cols , &affected_rows , &resultset);
			if (!error) {
				if (resultset) {
					if (resultset->rows_count) {
						// disable host
						proxy_error("Server %s:%d missed %d read_only checks. Assuming read_only=1\n", mmsd->hostname, mmsd->port, max_failures);
						MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_READ_ONLY_CHECKS_MISSED);
						MyHGM->read_only_action_v2( std::list<read_only_server_t> {
													read_only_server_t { mmsd->hostname, mmsd->port, read_only }
													} ); // N timeouts reached
					}
					delete resultset;
					resultset=NULL;
				}
			} else {
				proxy_error("Error on %s : %s\n", buff, error);
			}
			free(buff);
		}
	}

	/* error handling for both read_only and rds_topology checks */
	if (mmsd->interr || mmsd->mysql_error_msg) { // check failed
		if (mmsd->mysql) {
			// AWS RDS topology discovery probes every replication-hostgroup member, but
			// mysql.rds_topology exists only where a blue/green deployment is active.
			// Treat ER_NO_SUCH_TABLE (1146) as "no topology here" and skip quietly.
			if (mmsd->get_task_type() == MON_AWS_RDS_TOPOLOGY_DISCOVERY && mysql_errno(mmsd->mysql) == 1146) {
				proxy_debug(PROXY_DEBUG_MONITOR, 5,
					"mysql.rds_topology not present on %s:%d; skipping blue/green discovery\n",
					mmsd->hostname, mmsd->port);
			} else {
				proxy_error("Got error: mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
			}
			GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
		}
	} else {
		if (crc==false) {
			if (mmsd->mysql) {
				GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
			}
		}
	}

__fast_exit_monitor_read_only_thread:
	if (mmsd->mysql) {
		// if we reached here we didn't put the connection back
		if (mmsd->mysql_error_msg) {
			proxy_error("Got error: mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
			GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
		} else {
			if (crc) {
				bool rc=mmsd->set_wait_timeout();
				if (rc) {
					GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
				} else {
					proxy_error("Got error: mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
					MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
					GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
				}
			} else { // really not sure how we reached here, drop it
				proxy_error("Got error: mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
				GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
			}
		}
	}

	if (read_only_success) {
		__sync_fetch_and_add(&GloMyMon->read_only_check_OK,1);
	} else {
		__sync_fetch_and_add(&GloMyMon->read_only_check_ERR,1);
	}

	delete mysql_thr;
	return NULL;
}

void * monitor_group_replication_thread(const std::vector<MySQL_Monitor_State_Data*>& data) {
	assert(!data.empty());
	mysql_close(mysql_init(NULL));
	MySQL_Monitor_State_Data *mmsd = data.front();
	bool stale_ip_timeout = false;
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	mysql_thr->refresh_variables();

	mmsd->mysql=GloMyMon->My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port, mmsd);
	unsigned long long start_time=mysql_thr->curtime;


	mmsd->t1=start_time;

	bool crc=false;
	if (mmsd->mysql==NULL) { // we don't have a connection, let's create it
		bool rc;
		rc=mmsd->create_new_connection();
		if (mmsd->mysql) {
			GloMyMon->My_Conn_Pool->conn_register(mmsd);
		}
		crc=true;
		if (rc==false) {
			goto __fast_exit_monitor_group_replication_thread;
		}
	}

	mmsd->t1=monotonic_time();
	//async_exit_status=mysql_change_user_start(&ret_bool, mysql,"msandbox2","msandbox2","information_schema");
	//mmsd->async_exit_status=mysql_ping_start(&mmsd->interr,mmsd->mysql);
	mmsd->interr=0; // reset the value
#ifdef TEST_GROUPREP
	{
		std::string s { "SELECT viable_candidate,read_only,transactions_behind,members FROM GR_MEMBER_ROUTING_CANDIDATE_STATUS" };
		s += " " + std::string(mmsd->hostname) + ":" + std::to_string(mmsd->port);
		mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,s.c_str());
	}
#else
	mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SELECT viable_candidate,read_only,transactions_behind FROM sys.gr_member_routing_candidate_status");
#endif
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
#ifdef DEBUG
		const unsigned long long now = (GloMyMon->proxytest_forced_timeout == false) ? monotonic_time() : ULLONG_MAX;
#else
		const unsigned long long now = monotonic_time();
#endif
		if (now > mmsd->t1 + mysql_thread___monitor_groupreplication_healthcheck_timeout * 1000) {
			stale_ip_timeout = GloMyMon->timeout_validate_ip_change(mmsd);
			mmsd->mysql_error_msg=strdup(stale_ip_timeout ? "resolved IP no longer valid" : "timeout check");
			if (stale_ip_timeout) {
				proxy_debug(PROXY_DEBUG_MONITOR, 5,
					"Ignoring group replication timeout for %s:%d because resolved IP is no longer valid\n",
					mmsd->hostname, mmsd->port);
			} else {
				proxy_error("Timeout on group replication health check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_groupreplication_healthcheck_timeout. Assuming viable_candidate=NO and read_only=YES\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_GR_HEALTH_CHECK_TIMEOUT);
			}
			goto __exit_monitor_group_replication_thread;
		}
		if (mmsd->interr) {
			// error during query
			mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
			goto __exit_monitor_group_replication_thread;
		}

		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_group_replication_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_query_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) {
		// error during query
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
		MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
		goto __exit_monitor_group_replication_thread;
	}
	mmsd->async_exit_status=mysql_store_result_start(&mmsd->result,mmsd->mysql);
	while (mmsd->async_exit_status && ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0)) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
#ifdef DEBUG
		const unsigned long long now = (GloMyMon->proxytest_forced_timeout == false) ? monotonic_time() : ULLONG_MAX;
#else
		const unsigned long long now = monotonic_time();
#endif
		if (now > mmsd->t1 + mysql_thread___monitor_groupreplication_healthcheck_timeout * 1000) {
			stale_ip_timeout = GloMyMon->timeout_validate_ip_change(mmsd);
			mmsd->mysql_error_msg=strdup(stale_ip_timeout ? "resolved IP no longer valid" : "timeout check");
			if (stale_ip_timeout) {
				proxy_debug(PROXY_DEBUG_MONITOR, 5,
					"Ignoring group replication timeout for %s:%d because resolved IP is no longer valid\n",
					mmsd->hostname, mmsd->port);
			} else {
				proxy_error("Timeout on group replication health check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_groupreplication_healthcheck_timeout. Assuming viable_candidate=NO and read_only=YES\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_GR_HEALTH_CHECK_TIMEOUT);
			}
			goto __exit_monitor_group_replication_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_group_replication_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_store_result_cont(&mmsd->result, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) { // group replication check failed
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
		MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
		proxy_error("Got error: mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
		if (mmsd->mysql) {
			GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
		}
	} else {
		if (crc==false) {
			GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
		}
	}

__exit_monitor_group_replication_thread:
	mmsd->t2=monotonic_time();
	{
		// TODO : complete this
		char buf[128];
		char *s=NULL;
		int l=strlen(mmsd->hostname);
		if (l<110) {
			s=buf;
		}	else {
			s=(char *)malloc(l+16);
		}
		sprintf(s,"%s:%d",mmsd->hostname,mmsd->port);
		bool viable_candidate=false;
		bool read_only=true;
		int num_timeouts = 0;
		long long transactions_behind=-1;
		if (mmsd->interr == 0 && mmsd->result) {
			int num_fields=0;
			int num_rows=0;
			MYSQL_FIELD * fields = mysql_fetch_fields(mmsd->result);
			num_fields = mysql_num_fields(mmsd->result);
			num_rows = mysql_num_rows(mmsd->result);
			if (fields == NULL || num_fields!=3 || num_rows!=1) {
				proxy_error("mysql_fetch_fields returns NULL, or mysql_num_fields is incorrect. Server %s:%d . See bug #1994\n", mmsd->hostname, mmsd->port);
				if (mmsd->mysql_error_msg==NULL) {
					mmsd->mysql_error_msg = strdup("Unknown error");
				}
				goto __end_process_group_replication_result2;
			}
			MYSQL_ROW row=mysql_fetch_row(mmsd->result);
			if (row[0] && !strcasecmp(row[0],"YES")) {
				viable_candidate=true;
			}
			if (row[1] && !strcasecmp(row[1],"NO")) {
				read_only=false;
			}
			if (row[2]) {
				transactions_behind=atol(row[2]);
			}
			mysql_free_result(mmsd->result);
			mmsd->result=NULL;
		}
		if (mmsd->result) {
			// make sure it is clear
			mysql_free_result(mmsd->result);
			mmsd->result=NULL;
		}
		//proxy_info("GR: %s:%d , viable=%s , ro=%s, trx=%ld, err=%s\n", mmsd->hostname, mmsd->port, (viable_candidate ? "YES": "NO") , (read_only ? "YES": "NO") , transactions_behind, ( mmsd->mysql_error_msg ? mmsd->mysql_error_msg : "") );
		if (mmsd->mysql_error_msg) {
			//proxy_warning("GR: %s:%d , viable=%s , ro=%s, trx=%ld, err=%s\n", mmsd->hostname, mmsd->port, (viable_candidate ? "YES": "NO") , (read_only ? "YES": "NO") , transactions_behind, ( mmsd->mysql_error_msg ? mmsd->mysql_error_msg : "") );
		}
		unsigned long long time_now=realtime_time();
		time_now=time_now-(mmsd->t2 - start_time);
		pthread_mutex_lock(&GloMyMon->group_replication_mutex);
		//auto it =
		// TODO : complete this
		std::map<std::string, MyGR_monitor_node *>::iterator it2;
		it2 = GloMyMon->Group_Replication_Hosts_Map.find(s);
		MyGR_monitor_node *node=NULL;
		if (it2!=GloMyMon->Group_Replication_Hosts_Map.end()) {
			node=it2->second;
			node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1) , transactions_behind,viable_candidate,read_only,mmsd->mysql_error_msg);
		} else {
			node = new MyGR_monitor_node(mmsd->hostname,mmsd->port,mmsd->writer_hostgroup);
			node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1) , transactions_behind,viable_candidate,read_only,mmsd->mysql_error_msg);
			GloMyMon->Group_Replication_Hosts_Map.insert(std::make_pair(s,node));
		}
		if (mmsd->mysql_error_msg) {
			if (strncasecmp(mmsd->mysql_error_msg, (char *)"timeout", 7) == 0) {
				num_timeouts=node->get_timeout_count();
				proxy_warning("%s:%d : group replication health check timeout count %d. Max threshold %d.\n",
					mmsd->hostname, mmsd->port, num_timeouts, mmsd->max_transactions_behind_count);
			}
		}
		// NOTE: Previously 'lag_counts' was only updated for 'read_only'
		// because 'writers' were never selected for being set 'OFFLINE' due to
		// replication lag. Since the change of this behavior to 'SHUNNING'
		// with replication lag, no matter it's 'read_only' value, 'lag_counts'
		// is computed everytime.
		int lag_counts = node->get_lag_behind_count(mmsd->max_transactions_behind);
		pthread_mutex_unlock(&GloMyMon->group_replication_mutex);

		// NOTE: we update MyHGM outside the mutex group_replication_mutex
		if (stale_ip_timeout) {
			// Logged/counted; do not change GR state for stale DNS targets.
		} else if (mmsd->mysql_error_msg) { // there was an error checking the status of the server, surely we need to reconfigure GR
			if (num_timeouts == 0) {
				// it wasn't a timeout, reconfigure immediately
				MyHGM->update_group_replication_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, mmsd->mysql_error_msg);
			} else {
				// it was a timeout. Check if we are having consecutive timeout
				if (num_timeouts == mysql_thread___monitor_groupreplication_healthcheck_max_timeout_count) {
					proxy_error("Server %s:%d missed %d group replication checks. Number retries %d, Assuming offline\n",
					mmsd->hostname, mmsd->port, num_timeouts, num_timeouts);
					MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_GR_HEALTH_CHECKS_MISSED);
					MyHGM->update_group_replication_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, mmsd->mysql_error_msg);
				} else {
					// not enough timeout
				}
			}
		} else {
			if (viable_candidate==false) {
				MyHGM->update_group_replication_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"viable_candidate=NO");
			} else {
				if (read_only==true) {
					MyHGM->update_group_replication_set_read_only(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"read_only=YES");
				} else {
					// the node is a writer
					// TODO: for now we don't care about the number of writers
					MyHGM->update_group_replication_set_writer(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup);
				}

				// NOTE: Replication lag action should takes place **after** the
				// servers have been placed in the correct hostgroups, otherwise
				// during the reconfiguration of the servers due to 'update_group_replication_set_writer'
				// there would be a small window in which the 'SHUNNED' server
				// will be treat as 'ONLINE' letting some new connections to
				// take places, before it becomes 'SHUNNED' again.
				bool enable = true;
				if (lag_counts >= mysql_thread___monitor_groupreplication_max_transactions_behind_count) {
					enable = false;
				}
				MyHGM->group_replication_lag_action(
					mmsd->writer_hostgroup, mmsd->hostname, mmsd->port, lag_counts, read_only, enable
				);
			}
		}

		// clean up
		if (l<110) {
		} else {
			free(s);
		}
/*
		sqlite3_stmt *statement=NULL;
		sqlite3 *mondb=mmsd->mondb->get_db();
		int rc;
		char *query=NULL;
		query=(char *)"INSERT OR REPLACE INTO mysql_server_read_only_log VALUES (?1 , ?2 , ?3 , ?4 , ?5 , ?6)";
		rc=(*proxy_sqlite3_prepare_v2)(mondb, query, -1, &statement, 0);
		ASSERT_SQLITE_OK(rc, mmsd->mondb);
		int read_only=1; // as a safety mechanism , read_only=1 is the default
		rc=(*proxy_sqlite3_bind_text)(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		rc=(*proxy_sqlite3_bind_int)(statement, 2, mmsd->port); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		unsigned long long time_now=realtime_time();
		time_now=time_now-(mmsd->t2 - start_time);
		rc=(*proxy_sqlite3_bind_int64)(statement, 3, time_now); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1)); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		if (mmsd->result) {
			int num_fields=0;
			int k=0;
			MYSQL_FIELD *fields=NULL;
			int j=-1;
			num_fields = mysql_num_fields(mmsd->result);
			fields = mysql_fetch_fields(mmsd->result);
			for(k = 0; k < num_fields; k++) {
				//if (strcmp("VARIABLE_NAME", fields[k].name)==0) {
				if (strcmp((char *)"Value", (char *)fields[k].name)==0) {
					j=k;
				}
			}
			if (j>-1) {
				MYSQL_ROW row=mysql_fetch_row(mmsd->result);
				if (row) {
					if (row[j]) {
						if (!strcmp(row[j],"0") || !strcasecmp(row[j],"OFF"))
							read_only=0;
					}
				}
			}
//					if (repl_lag>=0) {
			rc=(*proxy_sqlite3_bind_int64)(statement, 5, read_only); ASSERT_SQLITE_OK(rc, mmsd->mondb);
//					} else {
//						rc=(*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
//					}
			mysql_free_result(mmsd->result);
			mmsd->result=NULL;
		} else {
			rc=(*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		}
		rc=(*proxy_sqlite3_bind_text)(statement, 6, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		SAFE_SQLITE3_STEP2(statement);
		rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);

		MyHGM->read_only_action(mmsd->hostname, mmsd->port, read_only);

		(*proxy_sqlite3_finalize)(statement);
*/

	}
__end_process_group_replication_result2:
	if (mmsd->interr || mmsd->mysql_error_msg) { // check failed
		if (mmsd->mysql) {
			proxy_error("Got error. mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
			GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
		}
	} else {
		if (crc==false) {
			if (mmsd->mysql) {
				GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
			}
		}
	}
__fast_exit_monitor_group_replication_thread:
	if (mmsd->mysql) {
		// if we reached here we didn't put the connection back
		if (mmsd->mysql_error_msg) {
			proxy_error("Got error. mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
			GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
		} else {
			if (crc) {
				bool rc=mmsd->set_wait_timeout();
				if (rc) {
					GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
				} else {
					proxy_error("Got error. mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
					MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
					GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
				}
			} else { // really not sure how we reached here, drop it
				proxy_error("Got error. mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
				GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
			}
		}
	}
	delete mysql_thr;
	return NULL;
}

void * monitor_galera_thread(const std::vector<MySQL_Monitor_State_Data*>& data) {
	assert(!data.empty());
	mysql_close(mysql_init(NULL));
	MySQL_Monitor_State_Data *mmsd = data.front();
	bool stale_ip_timeout = false;
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	mysql_thr->refresh_variables();

	mmsd->mysql=GloMyMon->My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port, mmsd);
	unsigned long long start_time=mysql_thr->curtime;

#ifdef DEBUG
	MYSQL *mysqlcopy __attribute__((unused)) = NULL;
#endif // DEBUG

	mmsd->t1=start_time;
	mmsd->interr=0; // reset the value

	bool crc=false;
	if (mmsd->mysql==NULL) { // we don't have a connection, let's create it
		bool rc;
		rc=mmsd->create_new_connection();
		if (mmsd->mysql) {
			GloMyMon->My_Conn_Pool->conn_register(mmsd);
		}
		crc=true;
		if (rc==false) {
			unsigned long long now=monotonic_time();
			char * new_error = (char *)malloc(50+strlen(mmsd->mysql_error_msg));
			sprintf(new_error,"timeout or error in creating new connection: %s",mmsd->mysql_error_msg);
			free(mmsd->mysql_error_msg);
			mmsd->mysql_error_msg = new_error;
			proxy_error("Error on Galera check for %s:%d after %lldms. Unable to create a connection. If the server is overload, increase mysql-monitor_connect_timeout. Error: %s.\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000, new_error);
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_GALERA_HEALTH_CHECK_CONN_TIMEOUT);
			goto __exit_monitor_galera_thread;
		}
	}

#ifdef DEBUG
	mysqlcopy = mmsd->mysql;
#endif // DEBUG

	mmsd->t1=monotonic_time();
	mmsd->interr=0; // reset the value
	{
#ifdef TEST_GALERA
		char *q1 = (char *)"SELECT wsrep_local_state , read_only , wsrep_local_recv_queue , wsrep_desync , wsrep_reject_queries , wsrep_sst_donor_rejects_queries , "
			" wsrep_cluster_status, pxc_maint_mode FROM HOST_STATUS_GALERA WHERE hostgroup_id=%d AND hostname='%s' AND port=%d";
		char *q2 = (char *)malloc(strlen(q1)+strlen(mmsd->hostname)+32);
		sprintf(q2,q1, mmsd->writer_hostgroup, mmsd->hostname, mmsd->port);
		mmsd->async_exit_status = mysql_query_start(&mmsd->interr, mmsd->mysql, q2);
		free(q2);
#else
		// Same MariaDB / MySQL 8.4+ consideration as the synchronous Galera
		// healthcheck above (lib/MySQL_Monitor.cpp:749): MariaDB always uses
		// INFORMATION_SCHEMA; non-MariaDB MySQL >= 5.7 must use
		// performance_schema (INFORMATION_SCHEMA.GLOBAL_STATUS removed in 8.4).
		const char *sv = mmsd->mysql->server_version;
		bool is_mariadb = (sv != NULL && strstr(sv, "MariaDB") != NULL);
		int sv_major = (sv != NULL) ? atoi(sv) : 0;
		bool use_perf_schema = !is_mariadb &&
			(sv_major >= 8 || (sv_major == 5 && sv != NULL && strncmp(sv, "5.7", 3) == 0));
		if (use_perf_schema) {
			mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SELECT (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='WSREP_LOCAL_STATE') "
			"wsrep_local_state, @@read_only read_only, (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='WSREP_LOCAL_RECV_QUEUE') wsrep_local_recv_queue , "
			"@@wsrep_desync wsrep_desync, @@wsrep_reject_queries wsrep_reject_queries, @@wsrep_sst_donor_rejects_queries wsrep_sst_donor_rejects_queries, "
			"(SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='WSREP_CLUSTER_STATUS') wsrep_cluster_status , "
			"(SELECT COALESCE(MAX(VARIABLE_VALUE),'DISABLED') FROM performance_schema.global_variables WHERE variable_name='pxc_maint_mode') pxc_maint_mode ");
		} else {
			// MariaDB Galera (any version) and legacy MySQL/PXC < 5.7
			mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SELECT (SELECT VARIABLE_VALUE FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME='WSREP_LOCAL_STATE') "
			"wsrep_local_state, @@read_only read_only, (SELECT VARIABLE_VALUE FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME='WSREP_LOCAL_RECV_QUEUE') wsrep_local_recv_queue , "
			"@@wsrep_desync wsrep_desync, @@wsrep_reject_queries wsrep_reject_queries, @@wsrep_sst_donor_rejects_queries wsrep_sst_donor_rejects_queries, "
			"(SELECT VARIABLE_VALUE FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME='WSREP_CLUSTER_STATUS') wsrep_cluster_status , (SELECT 'DISABLED') pxc_maint_mode");
		}
#endif // TEST_GALERA
	}
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
#ifdef DEBUG
		const unsigned long long now = (GloMyMon->proxytest_forced_timeout == false) ? monotonic_time() : ULLONG_MAX;
#else
		const unsigned long long now = monotonic_time();
#endif
		 if (now > mmsd->t1 + mysql_thread___monitor_galera_healthcheck_timeout * 1000) {
			stale_ip_timeout = GloMyMon->timeout_validate_ip_change(mmsd);
			mmsd->mysql_error_msg=strdup(stale_ip_timeout ? "resolved IP no longer valid" : "timeout check");
			if (stale_ip_timeout) {
				proxy_debug(PROXY_DEBUG_MONITOR, 5,
					"Ignoring Galera timeout for %s:%d because resolved IP is no longer valid\n",
					mmsd->hostname, mmsd->port);
			} else {
				proxy_error("Timeout on Galera health check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_galera_healthcheck_timeout.\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_GALERA_HEALTH_CHECK_TIMEOUT);
			}
			goto __exit_monitor_galera_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_galera_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_query_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	mmsd->async_exit_status=mysql_store_result_start(&mmsd->result,mmsd->mysql);
	while (mmsd->async_exit_status && ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0)) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
#ifdef DEBUG
		const unsigned long long now = (GloMyMon->proxytest_forced_timeout == false) ? monotonic_time() : ULLONG_MAX;
#else
		const unsigned long long now = monotonic_time();
#endif
		if (now > mmsd->t1 + mysql_thread___monitor_galera_healthcheck_timeout * 1000) {
			stale_ip_timeout = GloMyMon->timeout_validate_ip_change(mmsd);
			mmsd->mysql_error_msg=strdup(stale_ip_timeout ? "resolved IP no longer valid" : "timeout check");
			if (stale_ip_timeout) {
				proxy_debug(PROXY_DEBUG_MONITOR, 5,
					"Ignoring Galera timeout for %s:%d because resolved IP is no longer valid\n",
					mmsd->hostname, mmsd->port);
			} else {
				proxy_error("Timeout on Galera health check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_galera_healthcheck_timeout.\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_GALERA_HEALTH_CHECK_TIMEOUT);
			}
			goto __exit_monitor_galera_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_galera_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_store_result_cont(&mmsd->result, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) { // ping failed
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
		MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
		proxy_error("Got error. mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
		if (mmsd->mysql) {
			GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
		}
	} else {
		if (crc==false) {
#ifdef TEST_GALERA
			if ( rand()%3 == 0) { // drop the connection once every 3 checks
				GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
			} else {
				GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
			}
#else
			GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
#endif // TEST_GALERA
		}
	}

__exit_monitor_galera_thread:
	mmsd->t2=monotonic_time();
	{
		// TODO : complete this
		char buf[128];
		char *s=NULL;
		int l=strlen(mmsd->hostname);
		if (l<110) {
			s=buf;
		}	else {
			s=(char *)malloc(l+16);
		}
		sprintf(s,"%s:%d",mmsd->hostname,mmsd->port);
		bool primary_partition = false;
		bool read_only=true;
		bool wsrep_desync = true;
		int wsrep_local_state = 0;
		bool wsrep_reject_queries = true;
		bool wsrep_sst_donor_rejects_queries = true;
		long long wsrep_local_recv_queue=0;
		bool pxc_maint_mode=false;
		int num_timeouts = 0;
		MYSQL_FIELD * fields=NULL;
		if (mmsd->interr == 0 && mmsd->result) {
			int num_fields=0;
			int num_rows=0;
			num_fields = mysql_num_fields(mmsd->result);
			fields = mysql_fetch_fields(mmsd->result);
			num_rows = mysql_num_rows(mmsd->result);
			if (fields==NULL || num_fields!=8 || num_rows!=1) {
				proxy_error("mysql_fetch_fields returns NULL, or mysql_num_fields is incorrect. Server %s:%d . See bug #1994\n", mmsd->hostname, mmsd->port);
				if (mmsd->mysql_error_msg==NULL) {
					mmsd->mysql_error_msg = strdup("Unknown error");
				}
				goto __end_process_galera_result2;
			}
			MYSQL_ROW row=mysql_fetch_row(mmsd->result);
			if (row[0]) {
				wsrep_local_state = atoi(row[0]);
			}
			if (row[1]) {
				if (!strcasecmp(row[1],"NO") || !strcasecmp(row[1],"OFF") || !strcasecmp(row[1],"0")) {
					read_only=false;
				}
			}
			if (row[2]) {
				wsrep_local_recv_queue = atoll(row[2]);
			}
			if (row[3]) {
				if (!strcasecmp(row[3],"NO") || !strcasecmp(row[3],"OFF") || !strcasecmp(row[3],"0")) {
					wsrep_desync = false;
				}
			}
			if (row[4]) {
				if (!strcasecmp(row[4],"NONE")) {
					wsrep_reject_queries = false;
				}
			}
			if (row[5]) {
				if (!strcasecmp(row[5],"NO") || !strcasecmp(row[5],"OFF") || !strcasecmp(row[5],"0")) {
					wsrep_sst_donor_rejects_queries = false;
				}
			}
			if (row[6]) {
				if (!strcasecmp(row[6],"Primary")) {
					primary_partition = true;
				}
			}
			if (row[7]) {
				std::string s(row[7]);
				std::transform(s.begin(), s.end(), s.begin(), ::toupper);
				if (!strncmp("DISABLED",s.c_str(),8)) {
					pxc_maint_mode=false;
				}
				else {
					pxc_maint_mode=true;
				}
			}
			mysql_free_result(mmsd->result);
			mmsd->result=NULL;
		}
		if (mmsd->mysql_error_msg) {
		}
		unsigned long long time_now=realtime_time();
		time_now=time_now-(mmsd->t2 - start_time);
		pthread_mutex_lock(&GloMyMon->galera_mutex);
		//auto it =
		// TODO : complete this
		std::map<std::string, Galera_monitor_node *>::iterator it2;
		it2 = GloMyMon->Galera_Hosts_Map.find(s);
		Galera_monitor_node *node=NULL;
		if (it2!=GloMyMon->Galera_Hosts_Map.end()) {
			node=it2->second;
			//node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1) , transactions_behind,viable_candidate,read_only,mmsd->mysql_error_msg);
			node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1) , wsrep_local_recv_queue, primary_partition, read_only, wsrep_local_state, wsrep_desync, wsrep_reject_queries, wsrep_sst_donor_rejects_queries, pxc_maint_mode, mmsd->mysql_error_msg);
		} else {
			node = new Galera_monitor_node(mmsd->hostname,mmsd->port,mmsd->writer_hostgroup);
			//node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1) , transactions_behind,viable_candidate,read_only,mmsd->mysql_error_msg);
			node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1) , wsrep_local_recv_queue, primary_partition, read_only, wsrep_local_state, wsrep_desync, wsrep_reject_queries, wsrep_sst_donor_rejects_queries, pxc_maint_mode, mmsd->mysql_error_msg);
			GloMyMon->Galera_Hosts_Map.insert(std::make_pair(s,node));
		}
		if (mmsd->mysql_error_msg) {
			if (strncasecmp(mmsd->mysql_error_msg, (char *)"timeout", 7) == 0) {
				// it was a timeout . Let's count the number of consecutive timeouts
				int max_num_timeout = 10;
				if (mysql_thread___monitor_galera_healthcheck_max_timeout_count < max_num_timeout) {
					max_num_timeout = mysql_thread___monitor_galera_healthcheck_max_timeout_count;
				}
				unsigned long long start_times[max_num_timeout];
				bool timeouts[max_num_timeout];
				for (int i=0; i<max_num_timeout; i++) {
					start_times[i]=0;
					timeouts[i]=false;
				}
				for (int i=0; i<Galera_Nentries; i++) {
					if (node->last_entries[i].start_time) {
						int smallidx = 0;
						for (int j=0; j<max_num_timeout; j++) {
							//find the smaller value
							if (j!=smallidx) {
								if (start_times[j] < start_times[smallidx]) {
									smallidx = j;
								}
							}
						}
						if (start_times[smallidx] < node->last_entries[i].start_time) {
							start_times[smallidx] = node->last_entries[i].start_time;
							timeouts[smallidx] = false;
							if (node->last_entries[i].error) {
								if (strncasecmp(node->last_entries[i].error, (char *)"timeout", 7) == 0) {
									timeouts[smallidx] = true;
								}
							}
						}
					}
				}
				for (int i=0; i<max_num_timeout; i++) {
					if (timeouts[i]) {
						num_timeouts++;
					}
				}
			}
		}
		pthread_mutex_unlock(&GloMyMon->galera_mutex);

		// NOTE: we update MyHGM outside the mutex galera_mutex
		if (stale_ip_timeout) {
			// Logged/counted; do not change Galera state for stale DNS targets.
		} else if (mmsd->mysql_error_msg) { // there was an error checking the status of the server, surely we need to reconfigure Galera
			if (num_timeouts == 0) {
				// it wasn't a timeout, reconfigure immediately
				MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, mmsd->mysql_error_msg);
			} else {
				// it was a timeout. Check if we are having consecutive timeout
				if (num_timeouts == mysql_thread___monitor_galera_healthcheck_max_timeout_count) {
					proxy_error("Server %s:%d missed %d Galera checks. Assuming offline\n", mmsd->hostname, mmsd->port, num_timeouts);
					MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_GALERA_HEALTH_CHECKS_MISSED);
					MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, mmsd->mysql_error_msg);
				} else {
					// not enough timeout
				}
			}
		} else {
			if (fields) { // if we didn't get any error, but fileds is NULL, we are likely hitting bug #1994
				if (primary_partition == false || wsrep_desync == true || (wsrep_local_state!=4 && (wsrep_local_state != 2 || wsrep_sst_donor_rejects_queries))) {
					if (primary_partition == false) {
						MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"primary_partition=NO");
					} else {
						if (wsrep_desync == true) {
							MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"wsrep_desync=YES");
						} else {
							char msg[80];
							snprintf(msg, sizeof(msg), "wsrep_local_state=%d", wsrep_local_state);
							MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, msg);
						}
					}
				} else {
					//if (wsrep_sst_donor_rejects_queries || wsrep_reject_queries) {
					if (wsrep_reject_queries) {
						MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"wsrep_reject_queries=true");
						//	} else {
						//		// wsrep_sst_donor_rejects_queries
						//		MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"wsrep_sst_donor_rejects_queries=true");
						//	}
					} else {
						if (pxc_maint_mode) {
							MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"pxc_maint_mode=YES", true);
					    } else {
						    if (read_only==true) {
								if (wsrep_local_recv_queue > mmsd->max_transactions_behind) {
									MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"slave is lagging");
								} else {
									MyHGM->update_galera_set_read_only(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"read_only=YES");
								}
							} else {
								// the node is a writer
								// TODO: for now we don't care about the number of writers
								MyHGM->update_galera_set_writer(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup);
							}
						}
					}
				}
			} else {
				proxy_error("mysql_fetch_fields returns NULL. Server %s:%d . See bug #1994\n", mmsd->hostname, mmsd->port);
			}
		}

		// clean up
		if (l<110) {
		} else {
			free(s);
		}
	}
__end_process_galera_result2:
	if (mmsd->interr || mmsd->mysql_error_msg) { // check failed
		if (mmsd->mysql) {
			proxy_error("Got error. mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
			GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
		}
	} else {
		if (crc==false) {
			if (mmsd->mysql) {
				GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
			}
		}
	}
__fast_exit_monitor_galera_thread:
	if (mmsd->mysql) {
		// if we reached here we didn't put the connection back
		if (mmsd->mysql_error_msg) {
			proxy_error("Got error. mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
			GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
		} else {
			if (crc) {
				bool rc=mmsd->set_wait_timeout();
				if (rc) {
					GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
				} else {
					proxy_error("Got error. mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
					MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
					GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
				}
			} else { // really not sure how we reached here, drop it
				proxy_error("Got error. mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
				GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
			}
		}
	}
	delete mysql_thr;
	return NULL;
}

void * monitor_replication_lag_thread(const std::vector<MySQL_Monitor_State_Data*>& data) {
	assert(!data.empty());
	mysql_close(mysql_init(NULL));
	MySQL_Monitor_State_Data *mmsd = data.front();
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	mysql_thr->refresh_variables();

#ifdef DEBUG
	MYSQL *mysqlcopy __attribute__((unused)) = NULL;
#endif // DEBUG

	mmsd->mysql=GloMyMon->My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port, mmsd);
	unsigned long long start_time=mysql_thr->curtime;

	bool replication_lag_success = false;

	bool use_percona_heartbeat = false;
	char * percona_heartbeat_table = mysql_thread___monitor_replication_lag_use_percona_heartbeat;

	mmsd->t1=start_time;

	string server_version = "";
	string query = "SHOW SLAVE STATUS";

	bool crc=false;
	if (mmsd->mysql==NULL) { // we don't have a connection, let's create it
		bool rc;
		rc=mmsd->create_new_connection();
		if (mmsd->mysql) {
			GloMyMon->My_Conn_Pool->conn_register(mmsd);
		}
		crc=true;
		if (rc==false) {
			goto __fast_exit_monitor_replication_lag_thread;
		}
	} else {
		//GloMyMon->My_Conn_Pool->conn_register(mmsd);
	}

#ifdef DEBUG
	mysqlcopy = mmsd->mysql;
#endif // DEBUG

	mmsd->t1=monotonic_time();
	mmsd->interr=0; // reset the value


	if (mmsd->mysql && mmsd->mysql->server_version) server_version = string(mmsd->mysql->server_version);
#ifdef TEST_REPLICATIONLAG
	{
		const string REPLICA { mysql_get_server_version(mmsd->mysql) < 80023 ? "SLAVE" : "REPLICA" };
		const string SELECT {
			"SELECT " + REPLICA + " STATUS " + string(mmsd->hostname) + ":" + std::to_string(mmsd->port)
		};
		mmsd->async_exit_status = mysql_query_start(&mmsd->interr, mmsd->mysql, SELECT.c_str());
	}
#else
	if (percona_heartbeat_table) {
		int l = strlen(percona_heartbeat_table);
		if (l) {
			use_percona_heartbeat = true;
			char *base_query = (char *)"SELECT MAX(ROUND(TIMESTAMPDIFF(MICROSECOND, ts, SYSDATE(6))/1000000)) AS Seconds_Behind_Master FROM %s";
			char *replication_query = (char *)malloc(strlen(base_query)+l);
			sprintf(replication_query,base_query,percona_heartbeat_table);
			query = string(replication_query);
			free(replication_query);
		}
	}
	if (use_percona_heartbeat == false) {
		query = "SHOW SLAVE STATUS";
		if (mysql_get_server_version(mmsd->mysql) >= 80023) {
			query = "SHOW REPLICA STATUS";
		}
	}
	if (strcasestr(server_version.c_str(), (const char *)SERVER_VERSION_READYSET) != NULL) {
		query = "SHOW READYSET STATUS";
	}
	mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,query.c_str());
#endif // TEST_REPLICATIONLAG
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
#ifdef DEBUG
		const unsigned long long now = (GloMyMon->proxytest_forced_timeout == false) ? monotonic_time() : ULLONG_MAX;
#else
		const unsigned long long now = monotonic_time();
#endif
		if (now > mmsd->t1 + mysql_thread___monitor_replication_lag_timeout * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			goto __exit_monitor_replication_lag_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_replication_lag_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_query_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		//} else {
		//	mmsd->mysql_error_msg=strdup("timeout check");
		//	goto __exit_monitor_replication_lag_thread;
		}
	}
	mmsd->async_exit_status=mysql_store_result_start(&mmsd->result,mmsd->mysql);
	while (mmsd->async_exit_status && ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0)) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
#ifdef DEBUG
		const unsigned long long now = (GloMyMon->proxytest_forced_timeout == false) ? monotonic_time() : ULLONG_MAX;
#else
		const unsigned long long now = monotonic_time();
#endif
		if (now > mmsd->t1 + mysql_thread___monitor_replication_lag_timeout * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			goto __exit_monitor_replication_lag_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_replication_lag_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_store_result_cont(&mmsd->result, mmsd->mysql, mmsd->async_exit_status);
		//} else {
		//	mmsd->mysql_error_msg=strdup("timeout check");
		//	goto __exit_monitor_replication_lag_thread;
		}
	}
	if (mmsd->interr) { // replication lag check failed
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
		MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
#ifdef DEBUG
		unsigned long long now=monotonic_time();
		proxy_error("Error after %lldms: mmsd %p , MYSQL %p , FD %d : %s\n", (now-mmsd->t1)/1000, mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
#endif // DEBUG
		GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
	} else {
		if (crc==false) {
			GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
		}
	}

__exit_monitor_replication_lag_thread:
	mmsd->t2=monotonic_time();
	{
		int rc;
		char *query=NULL;

		if (strcasestr(server_version.c_str(), (const char *)SERVER_VERSION_READYSET) == NULL) {
			query=(char *)"INSERT OR REPLACE INTO mysql_server_replication_lag_log VALUES (?1 , ?2 , ?3 , ?4 , ?5 , ?6)";
			auto [rc1, statement_unique] = mmsd->mondb->prepare_v2(query);
			ASSERT_SQLITE_OK(rc1, mmsd->mondb);
			sqlite3_stmt *statement = statement_unique.get();
				// 'replication_lag' to be feed to 'replication_lag_action'
				int repl_lag=-2;
				bool override_repl_lag = true;
				rc=(*proxy_sqlite3_bind_text)(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
				rc=(*proxy_sqlite3_bind_int)(statement, 2, mmsd->port); ASSERT_SQLITE_OK(rc, mmsd->mondb);
				unsigned long long time_now=realtime_time();
				time_now=time_now-(mmsd->t2 - start_time);
				rc=(*proxy_sqlite3_bind_int64)(statement, 3, time_now); ASSERT_SQLITE_OK(rc, mmsd->mondb);
				rc=(*proxy_sqlite3_bind_int64)(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1)); ASSERT_SQLITE_OK(rc, mmsd->mondb);
				if (mmsd->interr == 0 && mmsd->result) {
					int num_fields=0;
					int k=0;
					MYSQL_FIELD * fields=NULL;
					int j=-1;
					num_fields = mysql_num_fields(mmsd->result);
					fields = mysql_fetch_fields(mmsd->result);
#ifdef TEST_REPLICATIONLAG
					if (fields && num_fields == 1 )
#else
					if (
						fields && (
						( num_fields == 1 && use_percona_heartbeat == true )
						||
						( num_fields > 30 && use_percona_heartbeat == false )
						)
					) 
#endif					
					{
						for(k = 0; k < num_fields; k++) {
							if (fields[k].name) {
								if (
									strcmp("Seconds_Behind_Master", fields[k].name)==0
									|| strcmp("Seconds_Behind_Source", fields[k].name)==0
								) {
									j=k;
								}
							}
						}
						if (j>-1) {
							MYSQL_ROW row=mysql_fetch_row(mmsd->result);
							if (row) {
								repl_lag=-1; // this is old behavior
								override_repl_lag = true;
								if (row[j]) { // if Seconds_Behind_Master is not NULL
									repl_lag=atoi(row[j]);
									override_repl_lag = false;
								} else {
									MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_SRV_NULL_REPLICATION_LAG);
								}
							}
						}
						if (/*repl_lag >= 0 ||*/ override_repl_lag == false) {
							rc=(*proxy_sqlite3_bind_int64)(statement, 5, repl_lag); ASSERT_SQLITE_OK(rc, mmsd->mondb);
						} else {
							rc=(*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
						}
					} else {
							proxy_error("mysql_fetch_fields returns NULL, or mysql_num_fields is incorrect. Server %s:%d . See bug #1994\n", mmsd->hostname, mmsd->port);
							rc=(*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
					}
					mysql_free_result(mmsd->result);
					mmsd->result=NULL;
				} else {
					rc=(*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
					// 'replication_lag_check' timed out, we set 'repl_lag' to '-3' to avoid server to be 're-enabled'.
					repl_lag=-3;
				}
				rc=(*proxy_sqlite3_bind_text)(statement, 6, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
				SAFE_SQLITE3_STEP2(statement);
				rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);
				rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);
				MyHGM->replication_lag_action( std::list<replication_lag_server_t> {
												replication_lag_server_t {mmsd->hostgroup_id, mmsd->hostname, mmsd->port, repl_lag, override_repl_lag }
												} );
			if (mmsd->mysql_error_msg == NULL) {
				replication_lag_success = true;
			}
		} else { // readyset
			query=(char *)"INSERT OR REPLACE INTO readyset_status_log VALUES (?1 , ?2 , ?3 , ?4 , ?5 , ?6)";
			auto [rc2, statement_unique2] = mmsd->mondb->prepare_v2(query);
			ASSERT_SQLITE_OK(rc2, mmsd->mondb);
			sqlite3_stmt *statement = statement_unique2.get();
			unordered_map<string,string> status_output = {};
			enum MySerStatus status = MYSQL_SERVER_STATUS_SHUNNED; // default status
			rc=(*proxy_sqlite3_bind_text)(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			rc=(*proxy_sqlite3_bind_int)(statement, 2, mmsd->port); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			unsigned long long time_now=realtime_time();
			time_now=time_now-(mmsd->t2 - start_time);
			rc=(*proxy_sqlite3_bind_int64)(statement, 3, time_now); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			rc=(*proxy_sqlite3_bind_int64)(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1)); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			if (mmsd->interr == 0 && mmsd->result) {
				int num_fields=0;
				MYSQL_FIELD * fields=NULL;
				num_fields = mysql_num_fields(mmsd->result);
				fields = mysql_fetch_fields(mmsd->result);
				if ( fields && (num_fields == 2) ) {
					int num_rows = mysql_num_rows(mmsd->result);
					for (int i = 0; i < num_rows; i++) {
						MYSQL_ROW row = mysql_fetch_row(mmsd->result);
						string Variable_name = string(row[0]);
						string Value = (row[1] == NULL ? string("") : string(row[1]) );
						status_output[Variable_name] = Value;
						if (Variable_name == "Status") {
							if (strcasecmp(Value.c_str(), (const char *)"Online") == 0) {
								status = MYSQL_SERVER_STATUS_ONLINE; // set to ONLINE
							} else if (strncasecmp(Value.c_str(), (const char *)"Maintenance", strlen("Maintenance")) == 0) {
								status = MYSQL_SERVER_STATUS_OFFLINE_SOFT; // set to OFFLINE_SOFT
							} else {
								status = MYSQL_SERVER_STATUS_SHUNNED; // set to SHUNNED
							}
						}
					}
					nlohmann::json json_output = status_output; // directly assign the map to the json object
					std::string json_string = json_output.dump();
					rc=(*proxy_sqlite3_bind_text)(statement, 5, json_string.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
				} else {
					proxy_error("mysql_fetch_fields returns NULL, or mysql_num_fields is incorrect. Server %s:%d . See bug #1994\n", mmsd->hostname, mmsd->port);
					rc=(*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
				}

				mysql_free_result(mmsd->result);
				mmsd->result=NULL;
			} else {
				rc=(*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement, 6, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			SAFE_SQLITE3_STEP2(statement);
			rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			MyHGM->set_Readyset_status(mmsd->hostname, mmsd->port, status);
			if (mmsd->mysql_error_msg == NULL) {
				replication_lag_success = true;
			}
		}
	}
	if (mmsd->interr || mmsd->mysql_error_msg) { // check failed
		if (mmsd->mysql) {
#ifdef DEBUG
			proxy_error("Error after %lldms: server %s:%d , mmsd %p , MYSQL %p , FD %d : %s\n", (mmsd->t2-mmsd->t1)/1000, mmsd->hostname, mmsd->port, mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
#else
			proxy_error("Error after %lldms on server %s:%d : %s\n", (mmsd->t2-mmsd->t1)/1000, mmsd->hostname, mmsd->port, mmsd->mysql_error_msg);
#endif // DEBUG
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
			GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
		}
	} else {
		if (mmsd->mysql) {
			GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
		}
	}
__fast_exit_monitor_replication_lag_thread:
	if (mmsd->mysql) {
		mmsd->t2=monotonic_time();
		// if we reached here we didn't put the connection back
		if (mmsd->mysql_error_msg) {
#ifdef DEBUG
			proxy_error("Error after %lldms: server %s:%d , mmsd %p , MYSQL %p , FD %d : %s\n", (mmsd->t2-mmsd->t1)/1000, mmsd->hostname, mmsd->port, mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
#else
			proxy_error("Error after %lldms on server %s:%d : %s\n", (mmsd->t2-mmsd->t1)/1000, mmsd->hostname, mmsd->port, mmsd->mysql_error_msg);
#endif // DEBUG
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
			GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
		} else {
			if (crc) {
				bool rc=mmsd->set_wait_timeout();
				if (rc) {
					GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
				} else {
#ifdef DEBUG
					proxy_error("Error after %lldms: server %s:%d , mmsd %p , MYSQL %p , FD %d : %s\n", (mmsd->t2-mmsd->t1)/1000, mmsd->hostname, mmsd->port, mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);	
#else
					proxy_error("Error after %lldms on server %s:%d : %s\n", (mmsd->t2-mmsd->t1)/1000, mmsd->hostname, mmsd->port, mmsd->mysql_error_msg);
#endif // DEBUG
					MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
					GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
				}
			} else { // really not sure how we reached here, drop it
#ifdef DEBUG
				proxy_error("Error after %lldms: server %s:%d , mmsd %p , MYSQL %p , FD %d : %s\n", (mmsd->t2-mmsd->t1)/1000, mmsd->hostname, mmsd->port, mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
#else
				proxy_error("Error after %lldms on server %s:%d : %s\n", (mmsd->t2-mmsd->t1)/1000, mmsd->hostname, mmsd->port, mmsd->mysql_error_msg);
#endif // DEBUG
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
				GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
			}
		}
	}
	if (replication_lag_success) {
		__sync_fetch_and_add(&GloMyMon->replication_lag_check_OK,1);
	} else {
		__sync_fetch_and_add(&GloMyMon->replication_lag_check_ERR,1);
	}
	delete mysql_thr;
	return NULL;
}


void * MySQL_Monitor::monitor_connect() {
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();


	unsigned long long t1;
	unsigned long long t2;
	unsigned long long next_loop_at=0;
	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true) {
		// update the 'monitor_internal.mysql_servers' table with the latest 'mysql_servers' from 'MyHGM'
		{
			std::lock_guard<std::mutex> mysql_servers_guard(MyHGM->mysql_servers_to_monitor_mutex);
			update_monitor_mysql_servers(MyHGM->mysql_servers_to_monitor);
		}

		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		// add support for SSL
		char *query=(char *)"SELECT hostname, port, MAX(use_ssl) use_ssl FROM monitor_internal.mysql_servers GROUP BY hostname, port ORDER BY RANDOM()";
		unsigned int glover;
		t1=monotonic_time();

		if (!GloMTH) return NULL;	// quick exit during shutdown/restart
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			next_loop_at=0;
		}

		if (t1 < next_loop_at) {
			goto __sleep_monitor_connect_loop;
		}
		next_loop_at=t1+1000*mysql_thread___monitor_connect_interval;

		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
			goto __end_monitor_connect_loop;
		} else {
			if (resultset->rows_count==0) {
				goto __end_monitor_connect_loop;
			}
			int us=100;
			if (resultset->rows_count) {
				us=mysql_thread___monitor_connect_interval/2/resultset->rows_count;
				us*=40;
				if (us > 1000000 || us <= 0) {
					us = 10000;
				}
				us = us + rand()%us;
				if (resultset->rows_count==1) {
					// only 1 server, sleep also before creating the job
					usleep(us);
				}
			}
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				bool rc_ping = true;
				rc_ping = server_responds_to_ping(r->fields[0],atoi(r->fields[1]));
				if (rc_ping) { // only if server is responding to pings
					MySQL_Monitor_State_Data *mmsd=new MySQL_Monitor_State_Data(MON_CONNECT, r->fields[0],atoi(r->fields[1]), atoi(r->fields[2]));
					mmsd->mondb=monitordb;
					WorkItem<MySQL_Monitor_State_Data>* item;
					item=new WorkItem<MySQL_Monitor_State_Data>(mmsd,monitor_connect_thread);
					GloMyMon->queue->add(item);
					usleep(us);
				}
				if (GloMyMon->shutdown) return NULL;
			}
		}


__end_monitor_connect_loop:
		if (mysql_thread___monitor_enabled==true) {
			char *query=NULL;
			query=(char *)"DELETE FROM mysql_server_connect_log WHERE time_start_us < ?1";
			auto [rc1, statement_unique] = monitordb->prepare_v2(query);
			ASSERT_SQLITE_OK(rc1, monitordb);
			sqlite3_stmt *statement = statement_unique.get();
			int rc;
			if (mysql_thread___monitor_history < mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 )) { // issue #626
				if (mysql_thread___monitor_ping_interval < 3600000)
					mysql_thread___monitor_history = mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 );
			}
			unsigned long long time_now=realtime_time();
			rc=(*proxy_sqlite3_bind_int64)(statement, 1, time_now-(unsigned long long)mysql_thread___monitor_history*1000); ASSERT_SQLITE_OK(rc, monitordb);
			SAFE_SQLITE3_STEP2(statement);
			rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, monitordb);
			rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, monitordb);
		}
		if (resultset)
			delete resultset;

__sleep_monitor_connect_loop:
		t2=monotonic_time();
		if (t2<next_loop_at) {
			unsigned long long st=0;
			st=next_loop_at-t2;
			if (st > 500000) {
				st = 500000;
			}
			usleep(st);
		}
	}
	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr=NULL;
	}
	for (unsigned int i=0;i<num_threads; i++) {
		WorkItem<MySQL_Monitor_State_Data> *item=NULL;
		GloMyMon->queue->add(item);
	}
	return NULL;
}

void * MySQL_Monitor::monitor_ping() {
	mysql_close(mysql_init(NULL));
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
//	struct event_base *libevent_base;
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();

	unsigned long long t1;
	unsigned long long t2;
	unsigned long long next_loop_at=0;

	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true) {
		// update the 'monitor_internal.mysql_servers' table with the latest 'mysql_servers' from 'MyHGM'
		{
			std::lock_guard<std::mutex> mysql_servers_guard(MyHGM->mysql_servers_to_monitor_mutex);
			update_monitor_mysql_servers(MyHGM->mysql_servers_to_monitor);
		}

		unsigned int glover;
		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		char *query=(char *)"SELECT hostname, port, MAX(use_ssl) use_ssl FROM monitor_internal.mysql_servers GROUP BY hostname, port ORDER BY RANDOM()";
		t1=monotonic_time();

		if (!GloMTH) return NULL;	// quick exit during shutdown/restart
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			next_loop_at=0;
		}

		if (t1 < next_loop_at) {
			goto __sleep_monitor_ping_loop;
		}
		next_loop_at=t1+1000*mysql_thread___monitor_ping_interval;

		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
			goto __end_monitor_ping_loop;
		}
		
		if (resultset->rows_count == 0) {
			goto __end_monitor_ping_loop;
		}
		
		// resultset must be initialized before calling monitor_ping_async
		monitor_ping_async(resultset);
		if (shutdown) return NULL;

__end_monitor_ping_loop:
		if (mysql_thread___monitor_enabled==true) {
			char *query=NULL;
			query=(char *)"DELETE FROM mysql_server_ping_log WHERE time_start_us < ?1";
			auto [rc1, statement_unique] = monitordb->prepare_v2(query);
			ASSERT_SQLITE_OK(rc1, monitordb);
			sqlite3_stmt *statement = statement_unique.get();
			int rc;
			if (mysql_thread___monitor_history < mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 )) { // issue #626
				if (mysql_thread___monitor_ping_interval < 3600000)
					mysql_thread___monitor_history = mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 );
			}
			unsigned long long time_now=realtime_time();
			rc=(*proxy_sqlite3_bind_int64)(statement, 1, time_now-(unsigned long long)mysql_thread___monitor_history*1000); ASSERT_SQLITE_OK(rc, monitordb);
			SAFE_SQLITE3_STEP2(statement);
			rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, monitordb);
			rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, monitordb);
		}

		if (resultset) {
			delete resultset;
			resultset=NULL;
		}

		// now it is time to shun all problematic hosts
		query=(char *)"SELECT DISTINCT a.hostname, a.port FROM monitor_internal.mysql_servers a JOIN monitor.mysql_server_ping_log b ON a.hostname=b.hostname WHERE b.ping_error IS NOT NULL AND b.ping_error NOT LIKE 'Access denied for user\%'";
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
// we disable valgrind here. Probably a bug in SQLite3
VALGRIND_DISABLE_ERROR_REPORTING;
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
VALGRIND_ENABLE_ERROR_REPORTING;
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
		} else {
			// get all addresses and ports
			int i=0;
			int j=0;
			char **addresses=(char **)malloc(resultset->rows_count * sizeof(char *));
			char **ports=(char **)malloc(resultset->rows_count * sizeof(char *));
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				addresses[i]=strdup(r->fields[0]);
				ports[i]=strdup(r->fields[1]);
				i++;
			}
			if (resultset) {
				delete resultset;
				resultset=NULL;
			}
			char *new_query=NULL;
			new_query=(char *)"SELECT 1 FROM (SELECT hostname,port,ping_error FROM mysql_server_ping_log WHERE hostname='%s' AND port='%s' ORDER BY time_start_us DESC LIMIT %d) a WHERE ping_error IS NOT NULL AND ping_error NOT LIKE 'Access denied for user%%' AND ping_error NOT LIKE 'ProxySQL Error: Access denied for user%%' AND ping_error NOT LIKE 'Your password has expired.%%' GROUP BY hostname,port HAVING COUNT(*)=%d";
			for (j=0;j<i;j++) {
				char *buff=(char *)malloc(strlen(new_query)+strlen(addresses[j])+strlen(ports[j])+16);
				int max_failures=mysql_thread___monitor_ping_max_failures;
				sprintf(buff,new_query,addresses[j],ports[j],max_failures,max_failures);
				monitordb->execute_statement(buff, &error , &cols , &affected_rows , &resultset);
				if (!error) {
					if (resultset) {
						if (resultset->rows_count) {
							// disable host
							bool rc_shun = false;
							rc_shun = MyHGM->shun_and_killall(addresses[j],atoi(ports[j]));
							if (rc_shun) {
								proxy_error("Server %s:%s missed %d heartbeats, shunning it and killing all the connections. Disabling other checks until the node comes back online.\n", addresses[j], ports[j], max_failures);
							}
						}
						delete resultset;
						resultset=NULL;
					}
				} else {
					proxy_error("Error on %s : %s\n", query, error);
				}
				free(buff);
			}

			while (i) { // now free all the addresses/ports
				i--;
				free(addresses[i]);
				free(ports[i]);
			}
			free(addresses);
			free(ports);
		}


		// now it is time to update current_lantency_ms
		query=(char *)"SELECT DISTINCT a.hostname, a.port FROM monitor_internal.mysql_servers a JOIN monitor.mysql_server_ping_log b ON a.hostname=b.hostname WHERE b.ping_error IS NULL";
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
VALGRIND_DISABLE_ERROR_REPORTING;
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
VALGRIND_ENABLE_ERROR_REPORTING;
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
		} else {
			// get all addresses and ports
			int i=0;
			int j=0;
			char **addresses=(char **)malloc(resultset->rows_count * sizeof(char *));
			char **ports=(char **)malloc(resultset->rows_count * sizeof(char *));
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				addresses[i]=strdup(r->fields[0]);
				ports[i]=strdup(r->fields[1]);
				i++;
			}
			if (resultset) {
				delete resultset;
				resultset=NULL;
			}
			char *new_query=NULL;

			new_query=(char *)"SELECT hostname,port,COALESCE(CAST(AVG(ping_success_time_us) AS INTEGER),10000) FROM (SELECT hostname,port,ping_success_time_us,ping_error FROM mysql_server_ping_log WHERE hostname='%s' AND port='%s' ORDER BY time_start_us DESC LIMIT 3) a WHERE ping_error IS NULL GROUP BY hostname,port";
			for (j=0;j<i;j++) {
				char *buff=(char *)malloc(strlen(new_query)+strlen(addresses[j])+strlen(ports[j])+16);
				sprintf(buff,new_query,addresses[j],ports[j]);
				monitordb->execute_statement(buff, &error , &cols , &affected_rows , &resultset);
				if (!error) {
					if (resultset) {
						if (resultset->rows_count) {
							for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
								SQLite3_row *r=*it; // this should be called just once, but we create a generic for loop
								// update current_latency_ms
								MyHGM->set_server_current_latency_us(addresses[j],atoi(ports[j]), atoi(r->fields[2]));
							}
						}
						delete resultset;
						resultset=NULL;
					}
				} else {
					proxy_error("Error on %s : %s\n", query, error);
				}
				free(buff);
			}
			while (i) { // now free all the addresses/ports
				i--;
				free(addresses[i]);
				free(ports[i]);
			}
			free(addresses);
			free(ports);
		}

__sleep_monitor_ping_loop:
		t2=monotonic_time();
		if (t2<next_loop_at) {
			unsigned long long st=0;
			st=next_loop_at-t2;
			if (st > 500000) {
				st = 500000;
			}
			usleep(st);
		}
	}
	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr=NULL;
	}
	for (unsigned int i=0;i<num_threads; i++) {
		WorkItem<MySQL_Monitor_State_Data>* item=NULL;
		GloMyMon->queue->add(item);
	}
	return NULL;
}



bool MySQL_Monitor::server_responds_to_ping(char *address, int port) {
	bool ret = true; // default
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *new_query=NULL;
	new_query=(char *)"SELECT 1 FROM (SELECT hostname,port,ping_error FROM mysql_server_ping_log WHERE hostname='%s' AND port=%d ORDER BY time_start_us DESC LIMIT %d) a WHERE ping_error IS NOT NULL AND ping_error NOT LIKE 'Access denied for user%%' GROUP BY hostname,port HAVING COUNT(*)=%d";
	char *buff=(char *)malloc(strlen(new_query)+strlen(address)+32);
	int max_failures = mysql_thread___monitor_ping_max_failures;
	sprintf(buff,new_query,address,port,max_failures,max_failures);
VALGRIND_DISABLE_ERROR_REPORTING;
	monitordb->execute_statement(buff, &error , &cols , &affected_rows , &resultset);
VALGRIND_ENABLE_ERROR_REPORTING;
	if (!error) {
		if (resultset) {
			if (resultset->rows_count) {
				ret = false;
			}
			delete resultset;
			resultset=NULL;
		}
	} else {
		proxy_error("Error on %s : %s\n", buff, error);
	}
	if (resultset) {
		delete resultset;
		resultset=NULL;
	}
	free(buff);
	return ret;
}

/**
* @brief Add discovered servers to 'runtime_mysql_servers' and reader hostgroup.
*
* @param origin_server      A string which denotes the hostname of the originating server, from which the discovered servers were queried and found.
* @param discovered_servers A vector of servers discovered when querying the cluster's topology.
* @param reader_hostgroup   Reader hostgroup to which we will add the discovered servers.
*/
void MySQL_Monitor::handle_aws_rds_multi_az_cluster(const std::string& origin_server, const std::vector<AWS_RDS_Topology_Node>& discovered_servers, int reader_hostgroup) {
	char *error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result *runtime_mysql_servers = NULL;

	char *query=(char *)"SELECT DISTINCT hostname FROM monitor_internal.mysql_servers ORDER BY hostname";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	monitordb->execute_statement(query, &error, &cols, &affected_rows, &runtime_mysql_servers);

	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		vector<tuple<string, int, int>> new_servers;
		vector<string> saved_hostnames;
		saved_hostnames.push_back(origin_server);

		// Do an initial loop through the query results to save existing runtime server hostnames
		for (std::vector<SQLite3_row *>::iterator it = runtime_mysql_servers->rows.begin(); it != runtime_mysql_servers->rows.end(); it++) {
			SQLite3_row *r1 = *it;
			string current_runtime_hostname = r1->fields[0];

			saved_hostnames.push_back(current_runtime_hostname);
		}

		// Loop through discovered servers and process the ones we haven't saved yet
		for (const AWS_RDS_Topology_Node& s : discovered_servers) {
			if (s.endpoint.empty()) {
				continue;
			}
			const string& current_discovered_hostname = s.endpoint;
			int current_discovered_port_int = s.port;

			if (find(saved_hostnames.begin(), saved_hostnames.end(), current_discovered_hostname) == saved_hostnames.end()) {
				tuple<string, int, int> new_server(current_discovered_hostname, current_discovered_port_int, reader_hostgroup);
				new_servers.push_back(new_server);
				saved_hostnames.push_back(current_discovered_hostname);
			}
		}

		// Add the new servers if any
		if (!new_servers.empty()) {
			MyHGM->add_discovered_servers_to_mysql_servers_and_replication_hostgroups(new_servers);
		}
	}
}

/**
* @brief Parse a 'SELECT * FROM mysql.rds_topology' result into an AWS_RDS_Topology_Result.
*
* @details Columns are resolved by name (they may be absent or differently ordered by RDS type).
*   'blue_green' is set when the 'role'/'status' columns are present and non-NULL on the first row.
*
* @return The parsed topology; empty 'nodes' if 'result' is NULL or has no rows. The result cursor is rewound before returning.
*/
AWS_RDS_Topology_Result MySQL_Monitor::parse_aws_rds_topology(MYSQL_RES* result) {
	AWS_RDS_Topology_Result out;
	if (result == NULL) {
		return out;
	}

	unsigned int num_fields = mysql_num_fields(result);
	MYSQL_FIELD *fields = mysql_fetch_fields(result);
	int id_idx = -1, endpoint_idx = -1, port_idx = -1, role_idx = -1, status_idx = -1;
	for (unsigned int i = 0; i < num_fields; i++) {
		if (fields[i].name == NULL) {
			continue;
		}
		if (strcasecmp(fields[i].name, "id") == 0) {
			id_idx = (int)i;
		} else if (strcasecmp(fields[i].name, "endpoint") == 0) {
			endpoint_idx = (int)i;
		} else if (strcasecmp(fields[i].name, "port") == 0) {
			port_idx = (int)i;
		} else if (strcasecmp(fields[i].name, "role") == 0) {
			role_idx = (int)i;
		} else if (strcasecmp(fields[i].name, "status") == 0) {
			status_idx = (int)i;
		}
	}

	bool first = true;
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result))) {
		AWS_RDS_Topology_Node node;
		if (id_idx >= 0 && row[id_idx]) {
			node.id = row[id_idx];
		}
		if (endpoint_idx >= 0 && row[endpoint_idx]) {
			node.endpoint = row[endpoint_idx];
		}
		if (port_idx >= 0 && row[port_idx]) {
			try {
				node.port = std::stoi(row[port_idx]);
			} catch (...) {
				node.port = 0;
			}
		}
		if (role_idx >= 0 && row[role_idx]) {
			node.role = row[role_idx];
		}
		if (status_idx >= 0 && row[status_idx]) {
			node.status = row[status_idx];
		}
		if (first) {
			// blue/green deployment exposes non-NULL role/status; absent or NULL => Multi-AZ Cluster
			out.blue_green = (role_idx >= 0 && status_idx >= 0
				&& row[role_idx] != NULL && row[status_idx] != NULL);
			first = false;
		}
		out.nodes.push_back(std::move(node));
	}
	mysql_data_seek(result, 0); // rewind for any subsequent reader
	return out;
}

/**
* @brief Classify the parsed mysql.rds_topology result and dispatch.
*
* @details A blue/green deployment optionally auto-generates a runtime aws_rds_bgd_hostgroups
*   entry (when 'mysql-aws_blue_green_deployment_auto_discovery' is enabled); otherwise the rows
*   are treated as a Multi-AZ Cluster and handed to the existing auto-discovery path.
*/
void MySQL_Monitor::process_aws_rds_topology(MySQL_Monitor_State_Data* mmsd) {
	if (mmsd->result == NULL) {
		return;
	}

	AWS_RDS_Topology_Result topology = parse_aws_rds_topology(mmsd->result);
	if (topology.nodes.empty()) {
		return;
	}

	if (topology.blue_green) {
		if (mysql_thread___aws_blue_green_deployment_auto_discovery) {
			MyHGM->add_aws_rds_bgd_hostgroup_entry(mmsd->hostname, mmsd->port);
		}
	} else {
		handle_aws_rds_multi_az_cluster(mmsd->hostname, topology.nodes, mmsd->reader_hostgroup);
	}
}

void * MySQL_Monitor::monitor_read_only() {
	mysql_close(mysql_init(NULL));
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();

	unsigned long long t1;
	unsigned long long t2;
	unsigned long long next_loop_at=0;
	int topology_loop = 0;

	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true) {
		int topology_loop_max = mysql_thread___monitor_aws_rds_topology_discovery_interval;
		bool do_discovery_check = false;

		unsigned int glover;
		char *error=NULL;
		SQLite3_result *resultset=NULL;
		// add support for SSL
		char *query=(char *)SELECT_SERVERS_FOR_READ_ONLY;
		t1=monotonic_time();

		if (!GloMTH) return NULL;	// quick exit during shutdown/restart
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			next_loop_at=0;
		}

		if (t1 < next_loop_at) {
			goto __sleep_monitor_read_only;
		}
		next_loop_at=t1+1000*mysql_thread___monitor_read_only_interval;
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
		resultset = MyHGM->execute_query(query, &error);
		assert(resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
			goto __end_monitor_read_only_loop;
		}

		if (resultset->rows_count == 0) {
			goto __end_monitor_read_only_loop;
		}

		if (topology_loop_max > 0) { // if the discovery interval is set to zero, do not query for the topology
			if (topology_loop >= topology_loop_max) {
				do_discovery_check = true;
				topology_loop = 0;
			}
			topology_loop += 1;
		}

		// resultset must be initialized before calling monitor_read_only_async
		monitor_read_only_async(resultset, do_discovery_check);
		if (shutdown) return NULL;

__end_monitor_read_only_loop:
		if (mysql_thread___monitor_enabled==true) {
			char *query=NULL;
			query=(char *)"DELETE FROM mysql_server_read_only_log WHERE time_start_us < ?1";
			auto [rc1, statement_unique] = monitordb->prepare_v2(query);
			ASSERT_SQLITE_OK(rc1, monitordb);
			sqlite3_stmt *statement = statement_unique.get();
			int rc;
			if (mysql_thread___monitor_history < mysql_thread___monitor_read_only_interval * (mysql_thread___monitor_read_only_max_timeout_count + 1 )) { // issue #626
				if (mysql_thread___monitor_read_only_interval < 3600000)
					mysql_thread___monitor_history = mysql_thread___monitor_read_only_interval * (mysql_thread___monitor_read_only_max_timeout_count + 1 );
			}
			unsigned long long time_now=realtime_time();
			rc=(*proxy_sqlite3_bind_int64)(statement, 1, time_now-(unsigned long long)mysql_thread___monitor_history*1000); ASSERT_SQLITE_OK(rc, monitordb);
			SAFE_SQLITE3_STEP2(statement);
			rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, monitordb);
			rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, monitordb);
		}

		if (resultset)
			delete resultset;

__sleep_monitor_read_only:
		t2=monotonic_time();
		if (t2<next_loop_at) {
			unsigned long long st=0;
			st=next_loop_at-t2;
			if (st > 500000) {
				st = 500000;
			}
			usleep(st);
		}
	}

	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr=NULL;
	}
	for (unsigned int i=0;i<num_threads; i++) {
		WorkItem<MySQL_Monitor_State_Data> *item=NULL;
		GloMyMon->queue->add(item);
	}
	return NULL;
}

set<uint32_t> extract_writer_hgs(SQLite3_result* Group_Replication_Hosts_resultset) {
	set<uint32_t> writer_hgs {};

	// NOTE: This operation should be at worst `N * log(N)`
	if (Group_Replication_Hosts_resultset->rows_count) {
		for (SQLite3_row* sqlite_row : Group_Replication_Hosts_resultset->rows) {
			writer_hgs.insert(atoi(sqlite_row->fields[0]));
		}
	}

	return writer_hgs;
}

/**
 * @brief Extracts a 'MySQL_Monitor_State_Data' from the provided 'SQLite3_result*'.
 * @details The expected contents of the provided 'SQLite3_result*' are the ones generated by
 *  'MySQL_HostGroups_Manager::generate_mysql_group_replication_hostgroups_table'.
 * @param Group_Replication_Hosts_resultset Resultset held by 'MySQL_Monitor' and generated by
 *  'MySQL_HostGroups_Manager' to be used to build a 'MySQL_Monitor_State_Data'.
 * @return Vector with the GR servers configurations.
 */
vector<gr_host_def_t> extract_gr_host_defs(
	uint32_t tg_writer_hg, SQLite3_result* Group_Replication_Hosts_resultset
) {
	vector<gr_host_def_t> result {};

	for (SQLite3_row* row : Group_Replication_Hosts_resultset->rows) {
		uint32_t writer_hg = atoi(row->fields[0]);

		if (tg_writer_hg == writer_hg) {
			char* hostname = row->fields[1];
			int port = atoi(row->fields[2]);
			bool use_ssl = atoi(row->fields[3]);
			bool wr_is_also_rd = atoi(row->fields[4]);
			int max_trx_behind = atoi(row->fields[5]);
			int max_trx_behind_count = mysql_thread___monitor_groupreplication_healthcheck_max_timeout_count;

			result.push_back({ hostname, port, use_ssl, wr_is_also_rd, max_trx_behind, max_trx_behind_count });
		}
	}

	return result;
}

/**
 * @brief Filter the responsive servers from the supplied hosts definitions.
 * @details Responsive servers are servers not exceeding 'mysql_thread___monitor_ping_max_failures'.
 * @param hosts_defs Hosts definitions to filter
 * @return Responsive servers found in the supplied hosts definitions.
 */
vector<gr_host_def_t> find_resp_srvs(const vector<gr_host_def_t>& hosts_defs) {
	vector<gr_host_def_t> resp_srvs {};

	for (const gr_host_def_t& host_def : hosts_defs) {
		char* c_hostname = const_cast<char*>(host_def.host.c_str());

		if (GloMyMon->server_responds_to_ping(c_hostname, host_def.port)) {
			resp_srvs.push_back(host_def);
		}
	}

	return resp_srvs;
}

string create_conn_err_msg(const unique_ptr<MySQL_Monitor_State_Data>& mmsd) {
	const char ACCESS_DENIED_MSG[] { "Access denied for user" };

	const char* srv_overload = "If the server is overload, increase mysql-monitor_connect_timeout. ";
	if (strncmp(mmsd->mysql_error_msg, ACCESS_DENIED_MSG, strlen(ACCESS_DENIED_MSG)) == 0) {
		srv_overload = "";
	}

	cfmt_t err_fmt = cstr_format(
		"%sError: timeout or error in creating new connection: %s", srv_overload, mmsd->mysql_error_msg
	);

	return err_fmt.str;
}

/**
 * @brief Initializes a 'MySQL_Monitor_State_Data' with a MySQL conn.
 *
 * @param srv_def The server info for the initialization.
 * @param writer_hg The writer_hostgroup to specify.
 * @param start_time The time at which this conn creation operation was started.
 *
 * @return A wrapper over the created 'mmsd' with the conn creation info.
 */
unique_ptr<MySQL_Monitor_State_Data> init_mmsd_with_conn(
	const gr_host_def_t srv_def, uint32_t writer_hg, uint64_t start_time
) {
	char* c_hostname = const_cast<char*>(srv_def.host.c_str());
	unique_ptr<MySQL_Monitor_State_Data> mmsd {
		new MySQL_Monitor_State_Data { MON_GROUP_REPLICATION, c_hostname, srv_def.port, static_cast<bool>(srv_def.use_ssl) }
	};
	mmsd->t1 = start_time;
	mmsd->init_time = start_time;
	mmsd->writer_hostgroup = writer_hg;
	mmsd->writer_is_also_reader = srv_def.writer_is_also_reader;
	mmsd->max_transactions_behind = srv_def.max_transactions_behind;
	mmsd->max_transactions_behind_count = srv_def.max_transactions_behind_count;
	mmsd->mysql = GloMyMon->My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port, mmsd.get());

	if (mmsd->mysql == NULL) {
		bool rc = mmsd->create_new_connection();

		if (rc && mmsd->mysql) {
			GloMyMon->My_Conn_Pool->conn_register(mmsd.get());
			mmsd->created_conn = true;
		} else {
			uint64_t now = monotonic_time();
			string err_msg = create_conn_err_msg(mmsd);

			proxy_error(
				"Error on Group Replication check for %s:%d after %lldms. Unable to create a connection. %s.\n",
				mmsd->hostname, mmsd->port, (now - mmsd->t1)/1000, err_msg.c_str()
			);
			MyHGM->p_update_mysql_error_counter(
				p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port,
				ER_PROXYSQL_GR_HEALTH_CONN_CHECK_TIMEOUT
			);

			// Update 'mmsd' error message to report connection creating failure
			cfmt_t conn_err_msg = cstr_format(
				"timeout or error in creating new connection: %s", mmsd->mysql_error_msg
			);
			mmsd->mysql_error_msg = strdup(conn_err_msg.str.c_str());
			mmsd->task_result_ = MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_FAILED;
		}
	}

	return mmsd;
}

using gr_srv_addr_t = pair<string,int32_t>;

struct gr_srv_st_t {
	bool viable_candidate = false;
	bool read_only = true;
	int64_t transactions_behind = -1;
	bool inv_srv_state = false;
	vector<gr_srv_addr_t> gr_members {};
};

#define GR_MEMBER_ENTRY_ERR "%s '%s' in 'members' field from GR query to server '%s:%d'. Autodiscovery action aborted.\n"

vector<pair<string,int32_t>> parse_gr_members_addrs(
	const MySQL_Monitor_State_Data* mmsd, const vector<string>& gr_cluster_members
) {
#ifdef DEBUG
	nlohmann::ordered_json members { gr_cluster_members };
	proxy_debug(
		PROXY_DEBUG_MONITOR, 7, "Received 'members' field '%s' from GR query to server '%s:%d'\n", members.dump().c_str(),
		mmsd->hostname, mmsd->port
	);
#endif
	vector<pair<string,int32_t>> result {};

	for (const auto& cluster_member : gr_cluster_members) {
		const vector<string> gr_member_host_port { split_str(cluster_member, ':') };
		if (gr_member_host_port.size() != 2) {
			proxy_error(GR_MEMBER_ENTRY_ERR, "Invalid server entry", cluster_member.c_str(), mmsd->hostname, mmsd->port);
			break;
		}

		const string srv_host { gr_member_host_port[0] };
		const char* c_str_port { gr_member_host_port[1].c_str() };

		int32_t srv_port = -1;

		{
			char* p_end = nullptr;
			long port = std::strtol(c_str_port, &p_end, 10);

			if (c_str_port == p_end) {
				proxy_error(
					GR_MEMBER_ENTRY_ERR, "Failed to parse port for server entry", cluster_member.c_str(), mmsd->hostname, mmsd->port
				);
				break;
			} else {
				srv_port = port;
			}
		}

		result.push_back({srv_host, srv_port});
	}

	// If any entry fails to parse, we invalidate the whole action
	if (gr_cluster_members.size() != result.size()) {
		return {};
	} else {
		return result;
	}
}

gr_srv_st_t extract_gr_srv_st(MySQL_Monitor_State_Data* mmsd) {
	gr_srv_st_t gr_srv_st {};

	if (mmsd->interr == 0 && mmsd->result) {
		int num_fields=0;
		int num_rows=0;
		MYSQL_FIELD * fields = mysql_fetch_fields(mmsd->result);
		num_fields = mysql_num_fields(mmsd->result);
		num_rows = mysql_num_rows(mmsd->result);

		if (fields == NULL || num_fields!=4 || num_rows!=1) {
			if (num_rows == 0) {
				proxy_error(
					"Empty resultset for GR monitoring query from server %s:%d. Server is likely misconfigured\n",
					mmsd->hostname, mmsd->port
				);
			} else {
				proxy_error(
					"Invalid resultset for GR monitoring query from server %s:%d. Either 'mysql_fetch_fields=NULL' or unexpected 'mysql_num_fields=%d'."
						" Please report this incident\n",
					 mmsd->hostname, mmsd->port, num_fields
				);
			}
			if (mmsd->mysql_error_msg == NULL) {
				mmsd->mysql_error_msg = strdup("Invalid or malformed resultset");
			}
			gr_srv_st.inv_srv_state = true;
		} else {
			MYSQL_ROW row=mysql_fetch_row(mmsd->result);
			if (row[0] && !strcasecmp(row[0],"YES")) {
				gr_srv_st.viable_candidate=true;
			}
			if (row[1] && !strcasecmp(row[1],"NO")) {
				gr_srv_st.read_only=false;
			}
			if (row[2]) {
				gr_srv_st.transactions_behind=atol(row[2]);
			}
			if (mmsd->cur_monitored_gr_srvs && row[3]) {
				const string str_members_addrs { row[3] };
				const vector<string> members_addrs { split_str(str_members_addrs, ',') };

				gr_srv_st.gr_members = parse_gr_members_addrs(mmsd, members_addrs);
			}
		}
	}

	proxy_debug(
		PROXY_DEBUG_MONITOR, 7,
		"Fetched %u:%s:%d info - interr: %d, error: %s, viable_candidate:'%d', read_only:'%d',"
			" transactions_behind:'%ld'\n",
		mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mmsd->interr, mmsd->mysql_error_msg,
		gr_srv_st.viable_candidate, gr_srv_st.read_only, gr_srv_st.transactions_behind
	);

	if (mmsd->result) {
		mysql_free_result(mmsd->result);
		mmsd->result=NULL;
	}

	return gr_srv_st;
}

/**
 * @brief Holds all info required for performing monitoring actions over the GR node.
 */
struct gr_node_info_t {
	gr_srv_st_t srv_st;
	bool unresp_server = false;
	int num_timeouts = 0;
	int lag_counts = 0;
};

gr_node_info_t gr_update_hosts_map(
	uint64_t start_time, const gr_srv_st_t& gr_srv_st, MySQL_Monitor_State_Data* mmsd
) {
	// NOTE: This isn't specified in the initializer list due to current standard limitations
	gr_node_info_t node_info {};
	node_info.srv_st = gr_srv_st;

	// Consider 'time_now' to be 'now - fetch_duration'
	unsigned long long time_now=realtime_time();
	time_now=time_now-(mmsd->t2 - start_time);
	cfmt_t fmt_srv_addr = cstr_format("%s:%d", mmsd->hostname, mmsd->port);

	pthread_mutex_lock(&GloMyMon->group_replication_mutex);

	std::map<std::string, MyGR_monitor_node *>::iterator it2;
	it2 = GloMyMon->Group_Replication_Hosts_Map.find(fmt_srv_addr.str);
	MyGR_monitor_node *node=NULL;

	if (it2!=GloMyMon->Group_Replication_Hosts_Map.end()) {
		node=it2->second;
		node->add_entry(
			time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1), gr_srv_st.transactions_behind,
			gr_srv_st.viable_candidate, gr_srv_st.read_only,mmsd->mysql_error_msg
		);
	} else {
		node = new MyGR_monitor_node(mmsd->hostname,mmsd->port,mmsd->writer_hostgroup);
		node->add_entry(
			time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1), gr_srv_st.transactions_behind,
			gr_srv_st.viable_candidate, gr_srv_st.read_only,mmsd->mysql_error_msg
		);
		GloMyMon->Group_Replication_Hosts_Map.insert(std::make_pair(fmt_srv_addr.str,node));
	}
	if (mmsd->mysql_error_msg) {
		if (strncasecmp(mmsd->mysql_error_msg, (char *)"timeout", 7) == 0) {
			node_info.num_timeouts = node->get_timeout_count();
		}
	}
	// NOTE: Previously 'lag_counts' was only updated for 'read_only'
	// because 'writers' were never selected for being set 'OFFLINE' due to
	// replication lag. Since the change of this behavior to 'SHUNNING'
	// with replication lag, no matter it's 'read_only' value, 'lag_counts'
	// is computed everytime.
	node_info.lag_counts = node->get_lag_behind_count(mmsd->max_transactions_behind);

	pthread_mutex_unlock(&GloMyMon->group_replication_mutex);

	return node_info;
}

/**
 * @brief Perform the actual monitoring action on the server based on the 'mmsd' info.
 *
 * @param mmsd The 'mmsd' holding info about fetching errors.
 * @param node_info The fetched server information itself.
 */
void gr_mon_action_over_resp_srv(MySQL_Monitor_State_Data* mmsd, const gr_node_info_t& node_info) {
	// NOTE: We update MyHGM outside the mutex group_replication_mutex
	if (mmsd->mysql_error_msg) { // there was an error checking the status of the server, surely we need to reconfigure GR
		if (node_info.num_timeouts == 0) {
			// it wasn't a timeout, reconfigure immediately
			MyHGM->update_group_replication_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, mmsd->mysql_error_msg);
		} else {
			proxy_warning("%s:%d : group replication health check timeout count %d. Max threshold %d.\n",
				mmsd->hostname, mmsd->port, node_info.num_timeouts, mmsd->max_transactions_behind_count);

			// It was a timeout. Check if we are having consecutive timeout
			if (node_info.num_timeouts == mysql_thread___monitor_groupreplication_healthcheck_max_timeout_count) {
				proxy_error("Server %s:%d missed %d group replication checks. Number retries %d, Assuming offline\n",
					mmsd->hostname, mmsd->port, node_info.num_timeouts, node_info.num_timeouts);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_GR_HEALTH_CHECKS_MISSED);
				MyHGM->update_group_replication_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, mmsd->mysql_error_msg);
			}
		}
	} else {
		if (node_info.srv_st.viable_candidate==false) {
			MyHGM->update_group_replication_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"viable_candidate=NO");
		} else {
			if (node_info.srv_st.read_only==true) {
				MyHGM->update_group_replication_set_read_only(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"read_only=YES");
			} else {
				// the node is a writer
				// TODO: for now we don't care about the number of writers
				MyHGM->update_group_replication_set_writer(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup);
			}

			// NOTE: Replication lag action should takes place **after** the
			// servers have been placed in the correct hostgroups, otherwise
			// during the reconfiguration of the servers due to 'update_group_replication_set_writer'
			// there would be a small window in which the 'SHUNNED' server
			// will be treat as 'ONLINE' letting some new connections to
			// take places, before it becomes 'SHUNNED' again.
			bool enable = true;
			if (node_info.lag_counts >= mysql_thread___monitor_groupreplication_max_transactions_behind_count) {
				enable = false;
			}
			MyHGM->group_replication_lag_action(
				mmsd->writer_hostgroup, mmsd->hostname, mmsd->port, node_info.lag_counts, node_info.srv_st.read_only, enable
			);

			if (mmsd->cur_monitored_gr_srvs && node_info.srv_st.gr_members.empty() == false) {
				for (const gr_srv_addr_t& gr_member : node_info.srv_st.gr_members) {
					const string& srv_host { gr_member.first };
					const int32_t srv_port { gr_member.second };
					bool found = false;

					for (const gr_host_def_t& host_def : *mmsd->cur_monitored_gr_srvs) {
						if (srv_host == host_def.host && srv_port == host_def.port) {
							found = true;
						}
					}

					if (found == false) {
						MyHGM->update_group_replication_add_autodiscovered(srv_host, srv_port, mmsd->writer_hostgroup);
					}
				}
			}
		}
	}
}

/**
 * @brief NOTE: Currently unused. Unresponsive servers are SHUNNED by monitoring PING actions, and no further
 *  monitoring actions are performed on them.
 *
 * @param hosts_defs Unresponsive hosts.
 * @param wr_hg The writer hostgroup from the unresponsive hosts.
 */
void gr_handle_actions_over_unresp_srvs(const vector<gr_host_def_t>& hosts_defs, uint32_t wr_hg) {
	char unresp_err_msg[] = "Server unresponsive to PING requests";

	for (const gr_host_def_t& host_def : hosts_defs) {
		char* c_hostname = const_cast<char*>(host_def.host.c_str());

		proxy_warning(
			"%s:%d: Server considered OFFLINE due to unresponsiveness to PING requests", c_hostname, host_def.port
		);
		MyHGM->update_group_replication_set_offline(c_hostname, host_def.port, wr_hg, unresp_err_msg);
	}
}

/**
 * @brief Handles the return of the 'MySQL' conn used by the 'mmsd' to Monitor 'ConnectionPool'.
 * @details Connections are returned to the 'ConnectionPool' if no errors took place during the fetching. If
 *  the connection is a new created connection, we try to configured it with the proper 'set_wait_timeout'
 *  before placing the connection back into the 'ConnectionPool', on failure, we discard the connection.
 * @param mmsd The mmsd wrapper holding all information for returning the connection.
 */
void handle_mmsd_mysql_conn(MySQL_Monitor_State_Data* mmsd) {
	if (mmsd == nullptr) return;

	if (mmsd->mysql) {
		if (mmsd->interr || mmsd->mysql_error_msg) {
			// If 'MySQL_Monitor_State_Data' reaches the end of a task_handler without 'TASK_RESULT_UNKNOWN':
			//  1. Connection failed to be created, 'task_result' should be 'TASK_RESULT_UNKNOWN'. No
			//     unregister needed.
			//  2. Fetching operation failed, the async fetching handler already handled the 'unregister'.
			GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
		} else {
			if (mmsd->created_conn) {
				bool rc = mmsd->set_wait_timeout();
				if (rc) {
					GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
				} else {
					proxy_error(
						"Error by 'set_wait_timeout' for new connection. mmsd %p , MYSQL %p , FD %d : %s\n",
						mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg
					);
					MyHGM->p_update_mysql_error_counter(
						p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql)
					);
					GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
				}
			} else {
				GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
			}
		}
	}
}

/**
 * @brief Report the fetching errors of the supplied 'mmsd' and increase the corresponding counter.
 * @param mmsd The 'mmsd' which failures are to be reported.
 */
void gr_report_fetching_errs(MySQL_Monitor_State_Data* mmsd) {
	if (mmsd->mysql) {
		if (mmsd->interr || mmsd->mysql_error_msg) {
			proxy_error(
				"Got error. mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql,
				mmsd->mysql->net.fd, mmsd->mysql_error_msg
			);
			MyHGM->p_update_mysql_error_counter(
				p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql)
			);
		}
	}
}

/**
 * @brief Performs the corresponding monitoring actions over the supplied 'MySQL_Monitor_State_Data'.
 * @details This function expects to be called when the fetching operation has completed for the supplied
 *  'MySQL_Monitor_State_Data' holding a final 'MYSQL_RES' or an error.  Otherwise servers will be set to
 *  'OFFLINE_HARD' due to defaults on 'gr_srv_st_t'. Actions taken are:
 *     1. Extract fetching results from the supplied 'MySQL_Monitor_State_Data' into 'gr_srv_st_t'.
 *     2. Update 'Group_Replication_Hosts_Map' and build a resulting 'gr_node_info_t' with the required info
 *     for performing the monitoring actions.
 *     3. Perform any required actions to the servers through 'MySQL_HostGroups_Manager'.
 *
 *  NOTE: We only perform monitoring actions over responsive servers, unresponsive servers are SHUNNED
 *  by monitoring PING actions, and no further monitoring actions should be performed on them.
 *
 * @param start_time The time at which this complete 'fetch + actions' monitoring cycle started.
 * @param mmsd The server 'MySQL_Monitor_State_Data' after the fetching is completed. It should either
 *  hold a valid 'MYSQL_RES' or an error.
 */
void async_gr_mon_actions_handler(MySQL_Monitor_State_Data* mmsd) {
	// We base 'start_time' on the conn init for 'MySQL_Monitor_State_Data'. If a conn creation was
	// required, we take into account this time into account, otherwise we assume that 'start_time=t1'.
	uint64_t start_time = 0;
	if (mmsd->created_conn) {
		start_time = mmsd->init_time;
	} else {
		start_time = mmsd->t1;
	}

	// Extract the server status from the 'mmsd'. Reports if invalid data is received
	gr_srv_st_t gr_srv_st { extract_gr_srv_st(mmsd) };

	// Report fetch errors; logs should report 'cause -> effect'
	gr_report_fetching_errs(mmsd);

	// Perform monitoring actions; only if the response wasn't illformed
	if (gr_srv_st.inv_srv_state == false) {
		gr_node_info_t node_info { gr_update_hosts_map(start_time, gr_srv_st, mmsd) };
		gr_mon_action_over_resp_srv(mmsd, node_info);
	}

	// Handle 'mmsd' MySQL conn return to 'ConnectionPool'
	handle_mmsd_mysql_conn(mmsd);
}

/**
 * @brief Initializes the structures related with a MySQL_Thread.
 * @details It doesn't initialize a real thread, just the structures associated with it.
 * @return The created and initialized 'MySQL_Thread'.
 */
unique_ptr<MySQL_Thread> init_mysql_thread_struct() {
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	if (!GloMTH) return NULL;
	unique_ptr<MySQL_Thread> mysql_thr { new MySQL_Thread() };
	mysql_thr->curtime = monotonic_time();
	mysql_thr->refresh_variables();

	return mysql_thr;
}

struct mon_thread_info_t {
	pthread_t pthread;
	uint32_t writer_hg;
};

void* monitor_GR_thread_HG(void *arg) {
	uint32_t wr_hg = *(static_cast<uint32_t*>(arg));
	set_thread_name("MonitorGRwrHG", GloVars.set_thread_name);
	proxy_info("Started Monitor thread for Group Replication writer HG %u\n", wr_hg);

	// Quick exit during shutdown/restart
	if (!GloMTH) { return NULL; }

	// Initial Monitor thread variables version
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version = GloMTH->get_global_version();
	// MySQL thread structure used for variable refreshing
	unique_ptr<MySQL_Thread> mysql_thr { init_mysql_thread_struct() };

	pthread_mutex_lock(&GloMyMon->group_replication_mutex);
	// Get the initial config checksum; this thread must exist on any config changes
	uint64_t initial_raw_checksum = GloMyMon->Group_Replication_Hosts_resultset->raw_checksum();
	// Extract the monitoring data required for the target writer hostgroup
	vector<gr_host_def_t> hosts_defs { extract_gr_host_defs(wr_hg, GloMyMon->Group_Replication_Hosts_resultset) };
	pthread_mutex_unlock(&GloMyMon->group_replication_mutex);

	uint64_t next_check_time = 0;
	uint64_t MAX_CHECK_DELAY_US = 500000;
	// On first iteration after thread (re)start, ignore the cached ping state
	// in mysql_server_ping_log — it may reflect stale failures from before the
	// monitor was reconfigured (e.g. a previous test left these hostnames
	// marked unpingable). Probing all configured hosts forces a fresh ping_log
	// entry, so subsequent iterations see real state instead of skipping
	// healthcheck_interval seconds while the writer HG stays empty.
	bool first_iteration = true;

	while (GloMyMon->shutdown == false && mysql_thread___monitor_enabled == true) {
		if (!GloMTH) { break; } // quick exit during shutdown/restart

		// Config check; Exit if config has been altered
		{
			pthread_mutex_lock(&GloMyMon->group_replication_mutex);
			uint64_t current_raw_checksum = GloMyMon->Group_Replication_Hosts_resultset->raw_checksum();
			pthread_mutex_unlock(&GloMyMon->group_replication_mutex);

			if (current_raw_checksum != initial_raw_checksum) {
				break;
			}
		}

		// Check variable version changes; refresh if needed and don't delay next check
		unsigned int glover = GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version = glover;
			mysql_thr->refresh_variables();
			next_check_time = 0;
		}

		uint64_t curtime = monotonic_time();

		// Delay the next check if needed
		if (curtime < next_check_time) {
			uint64_t time_left = next_check_time - curtime;
			uint64_t next_check_delay = 0;

			if (time_left > MAX_CHECK_DELAY_US) {
				next_check_delay = MAX_CHECK_DELAY_US;
			} else {
				next_check_delay = time_left;
			}

			usleep(next_check_delay);
			continue;
		}

		// Get the current 'pingable' status for the servers. See first_iteration
		// note above: skip the cache filter on the very first cycle so we do not
		// inherit stale ping failures from before this thread was started.
		vector<gr_host_def_t> resp_srvs;
		if (first_iteration) {
			resp_srvs = hosts_defs;
			first_iteration = false;
		} else {
			resp_srvs = find_resp_srvs(hosts_defs);
		}
		if (resp_srvs.empty()) {
			proxy_error("No node is pingable for Group Replication cluster with writer HG %u\n", wr_hg);
			next_check_time = curtime + mysql_thread___monitor_groupreplication_healthcheck_interval * 1000;
			continue;
		}

		// Initialize the 'MMSD' for data fetching for responsive servers
		vector<unique_ptr<MySQL_Monitor_State_Data>> conn_mmsds {};
		vector<unique_ptr<MySQL_Monitor_State_Data>> fail_mmsds {};

		// Separate the 'mmsds' based on success of obtaining a conn
		for (const gr_host_def_t& host_def : resp_srvs) {
			unique_ptr<MySQL_Monitor_State_Data> mmsd = init_mmsd_with_conn(host_def, wr_hg, curtime);

			if (mmsd->mysql_error_msg) {
				fail_mmsds.push_back(std::move(mmsd));
			} else {
				conn_mmsds.push_back(std::move(mmsd));
			}
		}

		int rnd_discoverer = conn_mmsds.size() == 0 ? -1 : rand() % conn_mmsds.size();
		if (rnd_discoverer != -1) {
			conn_mmsds[rnd_discoverer]->cur_monitored_gr_srvs = &hosts_defs;
		}

		// TODO: This needs to be reworked once we change the way monitoring actions work on clusters, taking
		// the full cluster fetch data to avoid transient states. For now, since we perform the monitoring
		// actions independently, we workaround the limitation of 'Monitor_Poll' of only handling
		// 'MySQL_Monitor_State_Data' which hold valid connections, by:
		//  1. Separate the 'MySQL_Monitor_State_Data' between failed to obtain conn and not.
		//  2. Perform the required monitoring actions over the servers that failed to obtain conns.
		//  3. Delegate the async fetching + actions of 'MySQL_Monitor_State_Data' with conns on 'Monitor_Poll'.
		///////////////////////////////////////////////////////////////////////////////////////

		// NOTE: This is just a best effort to avoid invalid memory accesses during 'SHUTDOWN SLOW'. Since the
		// previous section is 'time consuming', there are good changes that we can detect a shutdown before
		// trying to perform the monitoring actions on the acquired 'mmsd'. This exact scenario and timing has
		// been previously observed in the CI.
		if (GloMyMon->shutdown) {
			break;
		}

		// Handle 'mmsds' that failed to optain conns
		for (const unique_ptr<MySQL_Monitor_State_Data>& mmsd : fail_mmsds) {
			async_gr_mon_actions_handler(mmsd.get());
		}

		// Update 't1' for subsequent fetch operations and reset errors
		for (const unique_ptr<MySQL_Monitor_State_Data>& mmsd : conn_mmsds) {
			if (mmsd->mysql) {
				mmsd->t1 = monotonic_time();
				mmsd->interr = 0;
			}
		}

		// Perform the async fetch + actions over the 'MySQL_Monitor_State_Data'
		if (conn_mmsds.empty() == false) {
			GloMyMon->monitor_gr_async_actions_handler(conn_mmsds);
		}

		///////////////////////////////////////////////////////////////////////////////////////

		if (rnd_discoverer != -1) {
			conn_mmsds[rnd_discoverer]->cur_monitored_gr_srvs = nullptr;
		}

		// Set the time for the next iteration
		next_check_time = curtime + mysql_thread___monitor_groupreplication_healthcheck_interval * 1000;
	}

	proxy_info("Stopping Monitor thread for Group Replication writer HG %u\n", wr_hg);
	return NULL;
}

/**
 * @brief Creates a monitoring thread for each 'GroupReplication' cluster determined by writer hostgroups.
 * @param writer_hgs The writer hostgroups to use when creating the threads.
 * @return A vector of 'mon_thread_info_t' holding info of the created threads.
 */
vector<mon_thread_info_t> create_group_replication_worker_threads(const set<uint32_t>& writer_hgs) {
	proxy_info("Activating Monitoring of %lu Group Replication clusters\n", writer_hgs.size());

	vector<mon_thread_info_t> threads_info {};

	for (const uint32_t writer_hg : writer_hgs) {
		threads_info.push_back({pthread_t {}, writer_hg});
	}

	for (mon_thread_info_t& thread_info : threads_info) {
		proxy_info("Starting Monitor thread for Group Replication writer HG %u\n", thread_info.writer_hg);
		int err = pthread_create(&thread_info.pthread, NULL, monitor_GR_thread_HG, &thread_info.writer_hg);

		if (err) {
			proxy_error("Thread creation failed with error '%s'\n", strerror(err));
			assert(0);
		}
	}

	return threads_info;
}


void* MySQL_Monitor::monitor_group_replication_2() {
	uint64_t last_raw_checksum = 0;

	// Quick exit during shutdown/restart
	if (!GloMTH) return NULL;

	// Initial Monitor thread variables version
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version = 0;
	MySQL_Monitor__thread_MySQL_Thread_Variables_version = GloMTH->get_global_version();

	// MySQL thread structure used for variable refreshing
	unique_ptr<MySQL_Thread> mysql_thr { init_mysql_thread_struct() };

	// Info of the current GR monitoring threads: handle + writer_hg
	vector<mon_thread_info_t> threads_info {};

	while (GloMyMon->shutdown == false && mysql_thread___monitor_enabled == true) {
		// Quick exit during shutdown/restart
		if (!GloMTH) { return NULL; }

		// Check variable version changes; refresh if needed
		unsigned int glover = GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version = glover;
			mysql_thr->refresh_variables();
		}

		// Config check; Wait for all threads to stop before relaunch in case servers or options changed
		pthread_mutex_lock(&group_replication_mutex);
		uint64_t new_raw_checksum = Group_Replication_Hosts_resultset->raw_checksum();
		pthread_mutex_unlock(&group_replication_mutex);

		if (new_raw_checksum != last_raw_checksum) {
			proxy_info("Detected new/changed definition for Group Replication monitoring\n");
			// Update the new checksum
			last_raw_checksum = new_raw_checksum;

			// Wait for the threads to terminate; Threads should exit on config change
			if (threads_info.empty() == false) {
				for (const mon_thread_info_t& thread_info : threads_info) {
					pthread_join(thread_info.pthread, NULL);
					proxy_info("Stopped Monitor thread for Group Replication writer HG %u\n", thread_info.writer_hg);
				}
			}

			pthread_mutex_lock(&group_replication_mutex);
			set<uint32_t> wr_hgs_set = extract_writer_hgs(Group_Replication_Hosts_resultset);
			threads_info = create_group_replication_worker_threads(wr_hgs_set);
			pthread_mutex_unlock(&group_replication_mutex);
		}

		usleep(10000);
	}

	// Signal monitor worker threads to stop
	for (unsigned int i=0;i<num_threads; i++) {
		WorkItem<MySQL_Monitor_State_Data> *item=NULL;
		GloMyMon->queue->add(item);
	}

	return NULL;
}

void * MySQL_Monitor::monitor_group_replication() {
	mysql_close(mysql_init(NULL));
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
//	struct event_base *libevent_base;
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();

	unsigned long long t1;
	unsigned long long t2;
	unsigned long long next_loop_at=0;

	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true) {

		unsigned int glover;
//		char *error=NULL;
//		SQLite3_result *resultset=NULL;
		// add support for SSL
//		char *query=(char *)"SELECT hostname, port, MAX(use_ssl) use_ssl FROM mysql_servers JOIN mysql_group_replication_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=writer_hostgroup hostgroup_id=reader_hostgroup WHERE status NOT LIKE 'OFFLINE\%' GROUP BY hostname, port";
		t1=monotonic_time();

		if (!GloMTH) return NULL;	// quick exit during shutdown/restart
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			next_loop_at=0;
		}

		if (t1 < next_loop_at) {
			goto __sleep_monitor_group_replication;
		}
		next_loop_at=t1+1000*mysql_thread___monitor_groupreplication_healthcheck_interval;
		pthread_mutex_lock(&group_replication_mutex);
//		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
//		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
//		resultset = MyHGM->execute_query(query, &error);
//		assert(resultset);
		if (Group_Replication_Hosts_resultset==NULL) {
			pthread_mutex_unlock(&group_replication_mutex);
			proxy_error("Group replication hosts result set is absent\n");
			goto __end_monitor_group_replication_loop;
		}

		if (Group_Replication_Hosts_resultset->rows_count == 0) {
			pthread_mutex_unlock(&group_replication_mutex);
			goto __end_monitor_group_replication_loop;
		}
		pthread_mutex_unlock(&group_replication_mutex);

		// Group_Replication_Hosts_resultset must be initialized before calling monitor_group_replication_async
		monitor_group_replication_async();
		if (shutdown) return NULL;

__end_monitor_group_replication_loop:
		if (mysql_thread___monitor_enabled==true) {
/*
			sqlite3_stmt *statement=NULL;
			sqlite3 *mondb=monitordb->get_db();
			int rc;
			char *query=NULL;
			query=(char *)"DELETE FROM mysql_server_read_only_log WHERE time_start_us < ?1";
			rc=(*proxy_sqlite3_prepare_v2)(mondb, query, -1, &statement, 0);
			ASSERT_SQLITE_OK(rc, monitordb);
			if (mysql_thread___monitor_history < mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 )) { // issue #626
				if (mysql_thread___monitor_ping_interval < 3600000)
					mysql_thread___monitor_history = mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 );
			}
			unsigned long long time_now=realtime_time();
			rc=(*proxy_sqlite3_bind_int64)(statement, 1, time_now-(unsigned long long)mysql_thread___monitor_history*1000); ASSERT_SQLITE_OK(rc, monitordb);
			SAFE_SQLITE3_STEP2(statement);
			rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, monitordb);
			rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, monitordb);
			(*proxy_sqlite3_finalize)(statement);
*/
		}


//		if (resultset)
//			delete resultset;



__sleep_monitor_group_replication:
		t2=monotonic_time();
		if (t2<next_loop_at) {
			unsigned long long st=0;
			st=next_loop_at-t2;
			if (st > 500000) {
				st = 500000;
			}
			usleep(st);
		}
	}
	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr=NULL;
	}
	for (unsigned int i=0;i<num_threads; i++) {
		WorkItem<MySQL_Monitor_State_Data>*item=NULL;
		GloMyMon->queue->add(item);
	}
	return NULL;
}
void * MySQL_Monitor::monitor_galera() {
	mysql_close(mysql_init(NULL));
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
//	struct event_base *libevent_base;
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();

	unsigned long long t1;
	unsigned long long t2;
	unsigned long long next_loop_at=0;

	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true) {

		unsigned int glover;
		t1=monotonic_time();

		if (!GloMTH) return NULL;	// quick exit during shutdown/restart
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			next_loop_at=0;
		}

		if (t1 < next_loop_at) {
			goto __sleep_monitor_galera;
		}
		next_loop_at=t1+1000*mysql_thread___monitor_galera_healthcheck_interval;
		
		pthread_mutex_lock(&galera_mutex);
		if (Galera_Hosts_resultset == NULL || Galera_Hosts_resultset->rows_count == 0) {
			pthread_mutex_unlock(&galera_mutex);
			goto __end_monitor_galera_loop;
		}
		pthread_mutex_unlock(&galera_mutex);
		
		// Galera_Hosts_resultset must be initialized before calling monitor_galera_async
		monitor_galera_async();
		if (shutdown) return NULL;

__end_monitor_galera_loop:
		if (mysql_thread___monitor_enabled==true) {
		}


__sleep_monitor_galera:
		t2=monotonic_time();
		if (t2<next_loop_at) {
			unsigned long long st=0;
			st=next_loop_at-t2;
			if (st > 500000) {
				st = 500000;
			}
			usleep(st);
		}
	}
	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr=NULL;
	}
	for (unsigned int i=0;i<num_threads; i++) {
		WorkItem<MySQL_Monitor_State_Data>*item=NULL;
		queue->add(item);
	}
	return NULL;
}

void * MySQL_Monitor::monitor_replication_lag() {
	mysql_close(mysql_init(NULL));
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();

	unsigned long long t1;
	unsigned long long t2;
	unsigned long long next_loop_at=0;

	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true) {

		unsigned int glover;
		char *error=NULL;
		SQLite3_result *resultset=NULL;
		string ReadySetServers_query = "";
		for (const auto& server : ReadySet_Servers) {
			ReadySetServers_query += " OR (hostname = '" + server.ipAddress + "' AND port = " + to_string(server.port) + ")";
		}
		string queryS = "";
		if (mysql_thread___monitor_replication_lag_group_by_host==true) {
			queryS = "SELECT MIN(hostgroup_id), hostname, port, MIN(max_replication_lag), MAX(use_ssl) FROM mysql_servers WHERE (max_replication_lag > 0 AND status NOT IN (2,3)) " + ReadySetServers_query + " GROUP BY hostname, port";
		} else {
			queryS=(char *)"SELECT hostgroup_id, hostname, port, max_replication_lag, use_ssl FROM mysql_servers WHERE (max_replication_lag > 0 AND status NOT IN (2,3))" + ReadySetServers_query;
		}
		char *query= (char *)queryS.c_str();
		t1=monotonic_time();

		if (!GloMTH) return NULL;	// quick exit during shutdown/restart
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			next_loop_at=0;
		}

		if (t1 < next_loop_at) {
			goto __sleep_monitor_replication_lag;
		}
		next_loop_at=t1+1000*mysql_thread___monitor_replication_lag_interval;

		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
		resultset = MyHGM->execute_query(query, &error);
		assert(resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
			goto __end_monitor_replication_lag_loop;
		} 
		
		if (resultset->rows_count == 0) {
			goto __end_monitor_replication_lag_loop;
		}

		// resultset must be initialized before calling monitor_replication_lag_async
		monitor_replication_lag_async(resultset);
		if (shutdown) return NULL;

__end_monitor_replication_lag_loop:
		if (mysql_thread___monitor_enabled==true) {
			char *query=NULL;
			query=(char *)"DELETE FROM mysql_server_replication_lag_log WHERE time_start_us < ?1";
			auto [rc1, statement1_unique] = monitordb->prepare_v2(query);
			ASSERT_SQLITE_OK(rc1, monitordb);
			sqlite3_stmt *statement1 = statement1_unique.get();
			query=(char *)"DELETE FROM readyset_status_log WHERE time_start_us < ?1";
			auto [rc2, statement2_unique] = monitordb->prepare_v2(query);
			ASSERT_SQLITE_OK(rc2, monitordb);
			sqlite3_stmt *statement2 = statement2_unique.get();
			int rc;
			if (mysql_thread___monitor_history < mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 )) { // issue #626
				if (mysql_thread___monitor_ping_interval < 3600000)
					mysql_thread___monitor_history = mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 );
			}
			unsigned long long time_now=realtime_time();
			rc=(*proxy_sqlite3_bind_int64)(statement1, 1, time_now-(unsigned long long)mysql_thread___monitor_history*1000); ASSERT_SQLITE_OK(rc, monitordb);
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, monitordb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, monitordb);
			rc=(*proxy_sqlite3_bind_int64)(statement2, 1, time_now-(unsigned long long)mysql_thread___monitor_history*1000); ASSERT_SQLITE_OK(rc, monitordb);
			SAFE_SQLITE3_STEP2(statement2);
			rc=(*proxy_sqlite3_clear_bindings)(statement2); ASSERT_SQLITE_OK(rc, monitordb);
			rc=(*proxy_sqlite3_reset)(statement2); ASSERT_SQLITE_OK(rc, monitordb);
		}

		if (resultset)
			delete resultset;

__sleep_monitor_replication_lag:
		t2=monotonic_time();
		if (t2<next_loop_at) {
			unsigned long long st=0;
			st=next_loop_at-t2;
			if (st > 500000) {
				st = 500000;
			}
			usleep(st);
		}
	}
	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr=NULL;
	}
	for (unsigned int i=0;i<num_threads; i++) {
		WorkItem<MySQL_Monitor_State_Data>*item=NULL;
		GloMyMon->queue->add(item);
	}
	return NULL;
}

// validate_ip(), get_connected_peer_ip_from_socket(), debug_iplisttostring()
// and monitor_dns_resolver_thread() moved to lib/DNS_Cache.cpp so they can
// back both MySQL_Monitor and PgSQL_Monitor.

void* MySQL_Monitor::monitor_dns_cache() {
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version = 0;
	std::unique_ptr<MySQL_Thread> mysql_thr(new MySQL_Thread());
	mysql_thr->curtime = monotonic_time();
	if (!GloMTH) return NULL;	// quick exit during shutdown/restart

	constexpr unsigned int num_dns_resolver_threads = 1;
	constexpr unsigned int num_dns_resolver_max_threads = 32;
	unsigned long long t1 = 0;
	unsigned long long t2 = 0;
	unsigned long long next_loop_at = 0;
	bool dns_cache_enable = true;

	// Bookkeeper for dns records and ttl
	std::list<DNS_Cache_Record> dns_records_bookkeeping;

	// Queue for DNS resolver request
	wqueue<WorkItem<DNS_Resolve_Data>*> dns_resolver_queue;

	while (GloMyMon->shutdown == false) {

		if (!GloMTH) return NULL;	// quick exit during shutdown/restart
		const unsigned int glover = GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version = glover;
			mysql_thr->refresh_variables();
			next_loop_at = 0;

			// dns cache is disabled
			if (mysql_thread___monitor_local_dns_cache_ttl == 0 ||
				mysql_thread___monitor_local_dns_cache_refresh_interval == 0) {
				dns_cache_enable = false;
				dns_cache->set_enabled_flag(false);
				dns_cache->clear();
				dns_records_bookkeeping.clear();
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "DNS cache is disabled.\n");
				/*while (dns_resolver_queue.size()) {
					WorkItem<DNS_Resolve_Data>* item = dns_resolver_queue.remove();
					if (item) {
						if (item->data) {
							delete item->data;
						}
						delete item;
					}
				}*/
			}
			else {
				//dns cache enabled
				dns_cache_enable = true;
				dns_cache->set_enabled_flag(true);
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "DNS cache is enabled.\n");
			}
		}

		if (!dns_cache_enable) {
			usleep(200000);
			continue;
		}

		char* error = NULL;
		int cols = 0;
		int affected_rows = 0;
		SQLite3_result* resultset = NULL;
		const char* query = (char*)"SELECT trim(hostname) FROM monitor_internal.mysql_servers WHERE port!=0"
			" UNION "
			"SELECT trim(hostname) FROM monitor_internal.proxysql_servers WHERE port!=0";

		t1 = monotonic_time();

		if (t1 < next_loop_at && !force_dns_cache_update) {
			goto __sleep_monitor_dns_cache_loop;
		}
		force_dns_cache_update = false;
		next_loop_at = t1 + (1000 * mysql_thread___monitor_local_dns_cache_refresh_interval);

		// update the 'monitor_internal.mysql_servers' table with the latest 'mysql_servers' from 'MyHGM'
		{
			std::lock_guard<std::mutex> mysql_servers_guard(MyHGM->mysql_servers_to_monitor_mutex);
			update_monitor_mysql_servers(MyHGM->mysql_servers_to_monitor);
		}

		if (GloProxyCluster) {
			std::lock_guard<std::mutex> proxysql_servers_guard(GloProxyCluster->proxysql_servers_to_monitor_mutex);
			update_monitor_proxysql_servers(GloProxyCluster->proxysql_servers_to_monitor);
		}

		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
		admindb->execute_statement(query, &error, &cols, &affected_rows, &resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
			goto __end_monitor_dns_cache_loop;
		}
		else {
			if (resultset->rows_count == 0) {

				// Remove orphaned records if any
				if (dns_cache->empty() == false) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Clearing all orphaned DNS records from cache.\n");
					dns_cache->clear();
				}

				if (dns_records_bookkeeping.empty() == false) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Clearing all orphaned DNS records from bookkeeper.\n");
					dns_records_bookkeeping.clear();
				}
				goto __end_monitor_dns_cache_loop;
			}

			std::vector<DNSResolverThread*> dns_resolver_threads(num_dns_resolver_threads);
			
			for (unsigned int i = 0; i < num_dns_resolver_threads; i++) {
				dns_resolver_threads[i] = new DNSResolverThread(dns_resolver_queue, 0);
				dns_resolver_threads[i]->start(2048, false);
			}

			std::set<std::string> hostnames;

			for (const auto row : resultset->rows) {
				const std::string& hostname = row->fields[0];
				
				// Add only hostnames/domain and ignore IPs
				if (!validate_ip(hostname))
					hostnames.insert(hostname);
			}

			std::list<std::future<std::tuple<bool, DNS_Cache_Record>>> dns_resolve_result;

			int delay_us = 100;
			if (hostnames.empty() == false) {
				delay_us = mysql_thread___monitor_local_dns_cache_refresh_interval / 2 / hostnames.size();
				delay_us *= 40;
				if (delay_us > 1000000 || delay_us <= 0) {
					delay_us = 10000;
				}
				delay_us = delay_us + rand() % delay_us;
			}

			if (dns_records_bookkeeping.empty() == false) {
				unsigned long long current_time = monotonic_time();

				for (auto itr = dns_records_bookkeeping.begin();
					itr != dns_records_bookkeeping.end();) {
					// remove orphaned records
					if (hostnames.find(itr->hostname_) == hostnames.end()) {
						dns_cache->remove(itr->hostname_);
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Removing orphaned DNS record from bookkeeper. (Hostname:[%s] IP:[%s])\n", itr->hostname_.c_str(), debug_iplisttostring(itr->ips_).c_str());					
						itr = dns_records_bookkeeping.erase(itr);
					}
					else {
						hostnames.erase(itr->hostname_);

						// Renew dns records if expired
						if (current_time > itr->ttl_) {
							std::unique_ptr<DNS_Resolve_Data> dns_resolve_data(new DNS_Resolve_Data());
							dns_resolve_data->hostname = std::move(itr->hostname_);
							dns_resolve_data->cached_ips = std::move(itr->ips_);
							dns_resolve_data->ttl = mysql_thread___monitor_local_dns_cache_ttl;
							dns_resolve_data->refresh_intv = mysql_thread___monitor_local_dns_cache_refresh_interval;
							dns_resolve_data->dns_cache = dns_cache;
							dns_resolve_data->ai_family = mysql_resolution_family_to_ai_family(mysql_thread___resolution_family);
							dns_resolve_result.emplace_back(dns_resolve_data->result.get_future());

							proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Removing expired DNS record from bookkeeper. (Hostname:[%s] IP:[%s])\n", itr->hostname_.c_str(), debug_iplisttostring(dns_resolve_data->cached_ips).c_str());
							dns_resolver_queue.add(new WorkItem<DNS_Resolve_Data>(dns_resolve_data.release(), monitor_dns_resolver_thread));
							itr = dns_records_bookkeeping.erase(itr);
							usleep(delay_us);
							continue;
						}

						itr++;
					}
				}
			}

			{
				unsigned int qsize = dns_resolver_queue.size();
				unsigned int num_threads = dns_resolver_threads.size();

				if (qsize > (static_cast<unsigned int>(mysql_thread___monitor_local_dns_resolver_queue_maxsize) / 8)) {
					proxy_warning("DNS resolver queue too big: %d. Please refer to https://proxysql.com/documentation/dns-cache/ for further information.\n", qsize);

					unsigned int threads_max = num_dns_resolver_max_threads;

					if (threads_max > num_threads) {
						unsigned int new_threads = threads_max - num_threads;

						if ((qsize / 8) < new_threads) {
							new_threads = qsize / 8; // try to not burst threads
						}

						if (new_threads) {
							unsigned int old_num_threads = num_threads;
							num_threads += new_threads;
							dns_resolver_threads.resize(num_threads);

							for (unsigned int i = old_num_threads; i < num_threads; i++) {
								dns_resolver_threads[i] = new DNSResolverThread(dns_resolver_queue, 0);
								dns_resolver_threads[i]->start(2048, false);
							}
						}
					}
				}
			}

			if (hostnames.empty() == false) {

				for (const std::string& hostname : hostnames) {
					std::unique_ptr<DNS_Resolve_Data> dns_resolve_data(new DNS_Resolve_Data());
					dns_resolve_data->hostname = hostname;
					dns_resolve_data->ttl = mysql_thread___monitor_local_dns_cache_ttl;
					dns_resolve_data->refresh_intv = mysql_thread___monitor_local_dns_cache_refresh_interval;
					dns_resolve_data->dns_cache = dns_cache;
					dns_resolve_data->ai_family = mysql_resolution_family_to_ai_family(mysql_thread___resolution_family);
					dns_resolve_result.emplace_back(dns_resolve_data->result.get_future());
					dns_resolver_queue.add(new WorkItem<DNS_Resolve_Data>(dns_resolve_data.release(), monitor_dns_resolver_thread));
					usleep(delay_us);
				}
			}

			{
				unsigned int qsize = dns_resolver_queue.size();
				unsigned int num_threads = dns_resolver_threads.size();

				if (qsize > (static_cast<unsigned int>(mysql_thread___monitor_local_dns_resolver_queue_maxsize) / 4)) {
					proxy_warning("DNS resolver queue too big: %d. Please refer to https://proxysql.com/documentation/dns-cache/ for further information.\n", qsize);

					unsigned int threads_max = num_dns_resolver_max_threads;

					if (threads_max > num_threads) {
						unsigned int new_threads = threads_max - num_threads;

						if ((qsize / 4) < new_threads) {
							new_threads = qsize / 4; // try to not burst threads
						}

						if (new_threads) {
							unsigned int old_num_threads = num_threads;
							num_threads += new_threads;
							dns_resolver_threads.resize(num_threads);

							proxy_info("Starting %d helper threads\n", new_threads);

							for (unsigned int i = old_num_threads; i < num_threads; i++) {
								dns_resolver_threads[i] = new DNSResolverThread(dns_resolver_queue, 0);
								dns_resolver_threads[i]->start(2048, false);
							}
						}
					}
				}
			}

			// close all worker threads
			for (size_t i = 0; i < dns_resolver_threads.size(); i++)
				dns_resolver_queue.add(NULL);
			
			// update dns records with ip and ttl
			for (auto& dns_result : dns_resolve_result) {
				auto ret_value = dns_result.get();

				if (std::get<0>(ret_value)) {
					DNS_Cache_Record dns_record = get<1>(ret_value);
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Adding DNS record to bookkeeper. (Hostname:[%s] IP:[%s])\n", dns_record.hostname_.c_str(), debug_iplisttostring(dns_record.ips_).c_str());
					dns_records_bookkeeping.emplace_back(std::move(dns_record));
				}
			}
		
			for (DNSResolverThread* const dns_resolver_thread : dns_resolver_threads) {
				dns_resolver_thread->join();
				delete dns_resolver_thread;
			}
	
			if (GloMyMon->shutdown) return NULL;
		}

	__end_monitor_dns_cache_loop:
		if (resultset) {
			delete resultset;
			resultset = NULL;
		}

	__sleep_monitor_dns_cache_loop:
		t2 = monotonic_time();
		if (t2 < next_loop_at) {
			unsigned long long st = 0;
			st = next_loop_at - t2;
			if (st > 500000) {
				st = 500000;
			}
			usleep(st);
		}
	}

	return NULL;
}


void * MySQL_Monitor::run() {
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	pthread_mutex_init(&mon_en_mutex,NULL);
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();
	//if (!GloMTH) return NULL;	// quick exit during shutdown/restart

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 2048 * 1024);

	// DNS Cache is not dependent on monitor enable flag, so need to initialize it here
	pthread_t monitor_dns_cache_thread;
	if (pthread_create(&monitor_dns_cache_thread, &attr, &monitor_dns_cache_pthread, NULL) != 0) {
		// LCOV_EXCL_START
		proxy_error("Thread creation\n");
		assert(0);
		// LCOV_EXCL_STOP
	}

__monitor_run:
	while (queue->size()) { // this is a clean up in case Monitor was restarted
		WorkItem<MySQL_Monitor_State_Data>* item = static_cast<WorkItem<MySQL_Monitor_State_Data>*>(queue->remove());
		if (item) {
			for (auto ptr : item->data)
				delete ptr;
			item->data.clear();
			delete item;
		}
	}
	ConsumerThread<MySQL_Monitor_State_Data> **threads= (ConsumerThread<MySQL_Monitor_State_Data> **)malloc(sizeof(ConsumerThread<MySQL_Monitor_State_Data> *)*num_threads);
	for (unsigned int i=0;i<num_threads; i++) {
		threads[i] = new ConsumerThread<MySQL_Monitor_State_Data>(*queue, 0, "MyMonStateData");
		threads[i]->start(2048,false);
	}
	started_threads += num_threads;
	this->metrics.p_counter_array[p_mon_counter::mysql_monitor_workers_started]->Increment(num_threads);

	pthread_t monitor_connect_thread;
	if (pthread_create(&monitor_connect_thread, &attr, &monitor_connect_pthread,NULL) != 0) {
		// LCOV_EXCL_START
		proxy_error("Thread creation\n");
		assert(0);
		// LCOV_EXCL_STOP
	}
	pthread_t monitor_ping_thread;
	if (pthread_create(&monitor_ping_thread, &attr, &monitor_ping_pthread,NULL) != 0) {
		// LCOV_EXCL_START
		proxy_error("Thread creation\n");
		assert(0);
		// LCOV_EXCL_STOP
	}
	pthread_t monitor_read_only_thread;
	if (pthread_create(&monitor_read_only_thread, &attr, &monitor_read_only_pthread,NULL) != 0) {
		// LCOV_EXCL_START
		proxy_error("Thread creation\n");
		assert(0);
		// LCOV_EXCL_STOP
	}
	pthread_t monitor_group_replication_thread;
	if (pthread_create(&monitor_group_replication_thread, &attr, &monitor_group_replication_pthread,NULL) != 0) {
		// LCOV_EXCL_START
		proxy_error("Thread creation\n");
		assert(0);
		// LCOV_EXCL_STOP
	}
	pthread_t monitor_galera_thread;
	if (pthread_create(&monitor_galera_thread, &attr, &monitor_galera_pthread,NULL) != 0) {
		// LCOV_EXCL_START
		proxy_error("Thread creation\n");
		assert(0);
		// LCOV_EXCL_STOP
	}
	pthread_t monitor_aws_aurora_thread;
	if (pthread_create(&monitor_aws_aurora_thread, &attr, &monitor_aws_aurora_pthread,NULL) != 0) {
		// LCOV_EXCL_START
		proxy_error("Thread creation\n");
		assert(0);
		// LCOV_EXCL_STOP
	}
	pthread_t monitor_aws_rds_bgd_thread;
	if (pthread_create(&monitor_aws_rds_bgd_thread, &attr, &monitor_aws_rds_bgd_pthread,NULL) != 0) {
		// LCOV_EXCL_START
		proxy_error("Thread creation\n");
		assert(0);
		// LCOV_EXCL_STOP
	}
	pthread_t monitor_replication_lag_thread;
	if (pthread_create(&monitor_replication_lag_thread, &attr, &monitor_replication_lag_pthread,NULL) != 0) {
		// LCOV_EXCL_START
		proxy_error("Thread creation\n");
		assert(0);
		// LCOV_EXCL_STOP
	}
	while (shutdown==false && mysql_thread___monitor_enabled==true) {
		unsigned int glover;
		if (GloMTH) {
			glover=GloMTH->get_global_version();
			if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
				MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
				mysql_thr->refresh_variables();
				unsigned int old_num_threads = num_threads;
				unsigned int threads_min = (unsigned int)mysql_thread___monitor_threads_min;
				if (old_num_threads < threads_min) {
					num_threads = threads_min;
					this->metrics.p_gauge_array[p_mon_gauge::mysql_monitor_workers]->Set(threads_min);
					threads= (ConsumerThread<MySQL_Monitor_State_Data> **)realloc(threads, sizeof(ConsumerThread<MySQL_Monitor_State_Data> *)*num_threads);
					started_threads += (num_threads - old_num_threads);
					for (unsigned int i = old_num_threads ; i < num_threads ; i++) {
						threads[i] = new ConsumerThread<MySQL_Monitor_State_Data>(*queue, 0, "MyMonStateData");
						threads[i]->start(2048,false);
					}
				}
			}
		}
		pthread_mutex_lock(&mon_en_mutex);
		monitor_enabled=mysql_thread___monitor_enabled;
		pthread_mutex_unlock(&mon_en_mutex);
		if ( rand()%10 == 0) { // purge once in a while
			My_Conn_Pool->purge_some_connections();
		}
		usleep(200000);
		unsigned int qsize=queue->size();
		if (qsize > (unsigned int)mysql_thread___monitor_threads_queue_maxsize/4) {
			proxy_warning("Monitor queue too big: %d\n", qsize);
			unsigned int threads_max = (unsigned int)mysql_thread___monitor_threads_max;
			if (threads_max > num_threads) {
				unsigned int new_threads = threads_max - num_threads;
				if ((qsize / 4) < new_threads) {
					new_threads = qsize/4; // try to not burst threads
				}
				if (new_threads) {
					unsigned int old_num_threads = num_threads;
					num_threads += new_threads;
					this->metrics.p_gauge_array[p_mon_gauge::mysql_monitor_workers]->Increment(new_threads);
					threads= (ConsumerThread<MySQL_Monitor_State_Data> **)realloc(threads, sizeof(ConsumerThread<MySQL_Monitor_State_Data> *)*num_threads);
					started_threads += new_threads;
					for (unsigned int i = old_num_threads ; i < num_threads ; i++) {
						threads[i] = new ConsumerThread<MySQL_Monitor_State_Data>(*queue, 0, "MyMonStateData");
						threads[i]->start(2048,false);
					}
				}
			}
			// check again. Do we need also aux threads?
			usleep(50000);
			qsize=queue->size();
			if (qsize > (unsigned int)mysql_thread___monitor_threads_queue_maxsize) {
				qsize=qsize/50;
				unsigned int threads_max = (unsigned int)mysql_thread___monitor_threads_max;
				if ((qsize + num_threads) > (threads_max * 2)) { // allow a small bursts
					qsize = threads_max * 2 - num_threads;
				}
				if (qsize > 0) {
					proxy_info("Monitor is starting %d helper threads\n", qsize);
					ConsumerThread<MySQL_Monitor_State_Data> **threads_aux= (ConsumerThread<MySQL_Monitor_State_Data> **)malloc(sizeof(ConsumerThread<MySQL_Monitor_State_Data> *)*qsize);
					aux_threads = qsize;
					started_threads += aux_threads;
					for (unsigned int i=0; i<qsize; i++) {
						threads_aux[i] = new ConsumerThread<MySQL_Monitor_State_Data>(*queue, 245, "MyMonStateData");
						threads_aux[i]->start(2048,false);
					}
					for (unsigned int i=0; i<qsize; i++) {
						threads_aux[i]->join();
						delete threads_aux[i];
					}
					free(threads_aux);
					aux_threads = 0;
				}
			}
		}
	}
	for (unsigned int i=0;i<num_threads; i++) {
		WorkItem<MySQL_Monitor_State_Data>*item=NULL;
		GloMyMon->queue->add(item);
	}
	for (unsigned int i=0;i<num_threads; i++) {
		threads[i]->join();
		delete threads[i];
	}
	free(threads);
	pthread_join(monitor_connect_thread,NULL);
	pthread_join(monitor_ping_thread,NULL);
	pthread_join(monitor_read_only_thread,NULL);
	pthread_join(monitor_group_replication_thread,NULL);
	pthread_join(monitor_galera_thread,NULL);
	pthread_join(monitor_aws_aurora_thread,NULL);
	pthread_join(monitor_aws_rds_bgd_thread,NULL);
	pthread_join(monitor_replication_lag_thread,NULL);
	
	My_Conn_Pool->purge_all_connections();

	while (shutdown==false) {
		unsigned int glover;
		if (GloMTH) {
			glover=GloMTH->get_global_version();
			if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
				MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
				mysql_thr->refresh_variables();
			}
		}
		monitor_enabled=mysql_thread___monitor_enabled;
		if (mysql_thread___monitor_enabled==true) {
			goto __monitor_run;
		}

		usleep(200000);
	}

	pthread_join(monitor_dns_cache_thread, NULL);

	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr=NULL;
	}
	
	return NULL;
};


MyGR_monitor_node::MyGR_monitor_node(char *_a, int _p, int _whg) {
	addr=NULL;
	if (_a) {
		addr=strdup(_a);
	}
	port=_p;
	idx_last_entry=-1;
	writer_hostgroup=_whg;
	int i;
	for (i=0;i<MyGR_Nentries;i++) {
		last_entries[i].error=NULL;
		last_entries[i].start_time=0;
	}
}

MyGR_monitor_node::~MyGR_monitor_node() {
	if (addr) {
		free(addr);
	}
}

int MyGR_monitor_node::get_lag_behind_count(int txs_behind) {
	int max_lag = 10;
	if (mysql_thread___monitor_groupreplication_max_transactions_behind_count < max_lag)
		max_lag = mysql_thread___monitor_groupreplication_max_transactions_behind_count;
	bool lags[max_lag];
	unsigned long long start_times[max_lag];
	int lag_counts=0;
	for (int i=0; i<max_lag; i++) {
		start_times[i]=0;
		lags[i]=false;
	}
	for (int i=0; i<MyGR_Nentries; i++) {
		if (last_entries[i].start_time) {
			int smallidx = 0;
			for (int j=0; j<max_lag; j++) {
				if (j!=smallidx) {
					if (start_times[j] < start_times[smallidx]) {
						smallidx = j;
					}
				}
			}
			if (start_times[smallidx] < last_entries[i].start_time) {
				start_times[smallidx] = last_entries[i].start_time;
				lags[smallidx] = false;
				if (last_entries[i].transactions_behind > txs_behind) {
					lags[smallidx] = true;
				}
			}
		}
	}
	for (int i=0; i<max_lag; i++) {
		if (lags[i]) {
			lag_counts++;
		}
	}

	return lag_counts;
}

int MyGR_monitor_node::get_timeout_count() {
	int num_timeouts = 0;
	int max_num_timeout = 10;
	if (mysql_thread___monitor_groupreplication_healthcheck_max_timeout_count < max_num_timeout)
		max_num_timeout = mysql_thread___monitor_groupreplication_healthcheck_max_timeout_count;
	unsigned long long start_times[max_num_timeout];
	bool timeouts[max_num_timeout];
	for (int i=0; i<max_num_timeout; i++) {
		start_times[i]=0;
		timeouts[i]=false;
	}
	for (int i=0; i<MyGR_Nentries; i++) {
		if (last_entries[i].start_time) {
			int smallidx = 0;
			for (int j=0; j<max_num_timeout; j++) {
				if (j!=smallidx) {
					if (start_times[j] < start_times[smallidx]) {
						smallidx = j;
					}
				}
			}
			if (start_times[smallidx] < last_entries[i].start_time) {
				start_times[smallidx] = last_entries[i].start_time;
				timeouts[smallidx] = false;
				if (last_entries[i].error) {
					if (strncasecmp(last_entries[i].error, (char *)"timeout", 7) == 0) {
						timeouts[smallidx] = true;
					}
				}
			}
		}
	}
	for (int i=0; i<max_num_timeout; i++) {
		if (timeouts[i]) {
			num_timeouts++;
		}
	}
	return num_timeouts;
}

// return true if status changed
bool MyGR_monitor_node::add_entry(unsigned long long _st, unsigned long long _ct, long long _tb, bool _pp, bool _ro, char *_error) {
	bool ret=false;
	if (idx_last_entry==-1) ret=true;
	int prev_last_entry=idx_last_entry;
	idx_last_entry++;
	if (idx_last_entry>=MyGR_Nentries) {
		idx_last_entry=0;
	}
	last_entries[idx_last_entry].start_time=_st;
	last_entries[idx_last_entry].check_time=_ct;
	last_entries[idx_last_entry].transactions_behind=_tb;
	last_entries[idx_last_entry].primary_partition=_pp;
	last_entries[idx_last_entry].read_only=_ro;
	if (last_entries[idx_last_entry].error) {
		free(last_entries[idx_last_entry].error);
		last_entries[idx_last_entry].error=NULL;
	}
	if (_error) {
		last_entries[idx_last_entry].error=strdup(_error);	// we always copy
	}
	if (ret==false) {
		if (last_entries[idx_last_entry].primary_partition != last_entries[prev_last_entry].primary_partition) {
			ret=true;
		}
		if (last_entries[idx_last_entry].read_only != last_entries[prev_last_entry].read_only) {
			ret=true;
		}
		if (
			(last_entries[idx_last_entry].error && last_entries[prev_last_entry].error==NULL)
			||
			(last_entries[idx_last_entry].error==NULL && last_entries[prev_last_entry].error)
			||
			(last_entries[idx_last_entry].error && last_entries[prev_last_entry].error && strcmp(last_entries[idx_last_entry].error,last_entries[prev_last_entry].error))
		) {
			ret=true;
		}
	}
	return ret;
}


AWS_Aurora_replica_host_status_entry::AWS_Aurora_replica_host_status_entry(char *serid, char *sessid, char *lut, float rlm, float _c) {
	server_id = strdup(serid);
	session_id = strdup(sessid);
	last_update_timestamp = strdup(lut);
	replica_lag_ms = rlm;
	cpu = _c;
}

AWS_Aurora_replica_host_status_entry::AWS_Aurora_replica_host_status_entry(char *serid, char *sessid, char *lut, char *rlm, char *_c) {
	server_id = strdup(serid);
	session_id = strdup(sessid);
	last_update_timestamp = strdup(lut);
	replica_lag_ms = strtof(rlm, NULL);
	cpu = strtof(_c, NULL);
}

AWS_Aurora_replica_host_status_entry::~AWS_Aurora_replica_host_status_entry() {
	free(server_id);
	free(session_id);
	free(last_update_timestamp);
}

AWS_Aurora_status_entry::AWS_Aurora_status_entry(unsigned long long st, unsigned long long ct, char *e) {
	start_time = st;
	check_time = ct;
	error = NULL;
	if (e) {
		error = strdup(e);
	}
	host_statuses = new std::vector<AWS_Aurora_replica_host_status_entry *>;
}

AWS_Aurora_status_entry::~AWS_Aurora_status_entry() {
	if (error) {
		free(error);
	}
	AWS_Aurora_replica_host_status_entry *entry;
	for (std::vector<AWS_Aurora_replica_host_status_entry *>::iterator it = host_statuses->begin(); it != host_statuses->end(); ++it) {
		entry=*it;
		delete entry;
	}
	host_statuses->clear();
	delete host_statuses;
}

void AWS_Aurora_status_entry::add_host_status(AWS_Aurora_replica_host_status_entry *hs) {
	host_statuses->push_back(hs);
}

Galera_monitor_node::Galera_monitor_node(char *_a, int _p, int _whg) {
	addr=NULL;
	if (_a) {
		addr=strdup(_a);
	}
	port=_p;
	idx_last_entry=-1;
	writer_hostgroup=_whg;
	int i;
	for (i=0;i<Galera_Nentries;i++) {
		last_entries[i].error=NULL;
		last_entries[i].start_time=0;
	}
}

Galera_monitor_node::~Galera_monitor_node() {
	if (addr) {
		free(addr);
	}
}

// return true if status changed
bool Galera_monitor_node::add_entry(unsigned long long _st, unsigned long long _ct, long long _tb, bool _pp, bool _ro, int _local_state, bool _desync, bool _reject, bool _sst_donor_reject, bool _pxc_maint_mode, char *_error) {
	bool ret=false;
	if (idx_last_entry==-1) ret=true;
	int prev_last_entry=idx_last_entry;
	idx_last_entry++;
	if (idx_last_entry>=Galera_Nentries) {
		idx_last_entry=0;
	}
	last_entries[idx_last_entry].start_time=_st;
	last_entries[idx_last_entry].check_time=_ct;
	last_entries[idx_last_entry].wsrep_local_recv_queue=_tb;
	last_entries[idx_last_entry].primary_partition=_pp;
	last_entries[idx_last_entry].read_only=_ro;
	last_entries[idx_last_entry].wsrep_local_state = _local_state;
	last_entries[idx_last_entry].wsrep_desync = _desync;
	last_entries[idx_last_entry].wsrep_reject_queries = _reject;
	last_entries[idx_last_entry].wsrep_sst_donor_rejects_queries = _sst_donor_reject;
	last_entries[idx_last_entry].pxc_maint_mode = _pxc_maint_mode;
	if (last_entries[idx_last_entry].error) {
		free(last_entries[idx_last_entry].error);
		last_entries[idx_last_entry].error=NULL;
	}
	if (_error) {
		last_entries[idx_last_entry].error=strdup(_error);	// we always copy
	}
	if (ret==false) {
		if (last_entries[idx_last_entry].primary_partition != last_entries[prev_last_entry].primary_partition) {
			ret=true;
		}
		if (last_entries[idx_last_entry].read_only != last_entries[prev_last_entry].read_only) {
			ret=true;
		}
		if (
			(last_entries[idx_last_entry].error && last_entries[prev_last_entry].error==NULL)
			||
			(last_entries[idx_last_entry].error==NULL && last_entries[prev_last_entry].error)
			||
			(last_entries[idx_last_entry].error && last_entries[prev_last_entry].error && strcmp(last_entries[idx_last_entry].error,last_entries[prev_last_entry].error))
		) {
			ret=true;
		}
	}
	return ret;
}

void MySQL_Monitor::populate_monitor_mysql_server_group_replication_log() {
	char *query1=NULL;
	query1=(char *)"INSERT INTO mysql_server_group_replication_log VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)";
	pthread_mutex_lock(&GloMyMon->group_replication_mutex);
	auto [rc1, statement1_unique] = monitordb->prepare_v2(query1);
	ASSERT_SQLITE_OK(rc1, monitordb);
	sqlite3_stmt *statement1 = statement1_unique.get();
	int rc;
	monitordb->execute((char *)"DELETE FROM mysql_server_group_replication_log");
	std::map<std::string, MyGR_monitor_node *>::iterator it2;
	MyGR_monitor_node *node=NULL;
	for (it2=GloMyMon->Group_Replication_Hosts_Map.begin(); it2!=GloMyMon->Group_Replication_Hosts_Map.end(); ++it2) {
		std::string s=it2->first;
		node=it2->second;
		std::size_t found=s.find_last_of(":");
		std::string host=s.substr(0,found);
		std::string port=s.substr(found+1);
		int i;
		for (i=0; i<MyGR_Nentries; i++) {
			if (node->last_entries[i].start_time) {
				rc=(*proxy_sqlite3_bind_text)(statement1, 1, host.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoi(port.c_str())); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 3, node->last_entries[i].start_time ); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 4, node->last_entries[i].check_time ); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 5, ( node->last_entries[i].primary_partition ? (char *)"YES" : (char *)"NO" ) , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 6, ( node->last_entries[i].read_only ? (char *)"YES" : (char *)"NO" ) , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 7, node->last_entries[i].transactions_behind ); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 8, node->last_entries[i].error , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				SAFE_SQLITE3_STEP2(statement1);
				rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, monitordb);
			}
		}
	}
	pthread_mutex_unlock(&GloMyMon->group_replication_mutex);
}

void MySQL_Monitor::populate_monitor_mysql_server_galera_log() {
	char *query1=NULL;
	query1=(char *)"INSERT OR IGNORE INTO mysql_server_galera_log VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";
	pthread_mutex_lock(&GloMyMon->galera_mutex);
	auto [rc1, statement1_unique] = monitordb->prepare_v2(query1);
	ASSERT_SQLITE_OK(rc1, monitordb);
	sqlite3_stmt *statement1 = statement1_unique.get();
	int rc;
	monitordb->execute((char *)"DELETE FROM mysql_server_galera_log");
	std::map<std::string, Galera_monitor_node *>::iterator it2;
	Galera_monitor_node *node=NULL;
	for (it2=GloMyMon->Galera_Hosts_Map.begin(); it2!=GloMyMon->Galera_Hosts_Map.end(); ++it2) {
		std::string s=it2->first;
		node=it2->second;
		std::size_t found=s.find_last_of(":");
		std::string host=s.substr(0,found);
		std::string port=s.substr(found+1);
		int i;
		for (i=0; i<Galera_Nentries; i++) {
			if (node->last_entries[i].start_time) {
				rc=(*proxy_sqlite3_bind_text)(statement1, 1, host.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoi(port.c_str())); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 3, node->last_entries[i].start_time ); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 4, node->last_entries[i].check_time ); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 5, ( node->last_entries[i].primary_partition ? (char *)"YES" : (char *)"NO" ) , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 6, ( node->last_entries[i].read_only ? (char *)"YES" : (char *)"NO" ) , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 7, node->last_entries[i].wsrep_local_recv_queue ); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 8, node->last_entries[i].wsrep_local_state ); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 9, ( node->last_entries[i].wsrep_desync ? (char *)"YES" : (char *)"NO" ) , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 10, ( node->last_entries[i].wsrep_reject_queries ? (char *)"YES" : (char *)"NO" ) , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 11, ( node->last_entries[i].wsrep_sst_donor_rejects_queries ? (char *)"YES" : (char *)"NO" ) , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 12, ( node->last_entries[i].pxc_maint_mode ? (char *)"YES" : (char *)"NO" ) , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 13, node->last_entries[i].error , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
				SAFE_SQLITE3_STEP2(statement1);
				rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, monitordb);
				rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, monitordb);
			}
		}
	}
	pthread_mutex_unlock(&GloMyMon->galera_mutex);
}

char * MySQL_Monitor::galera_find_last_node(int writer_hostgroup) {
/*
	sqlite3 *mondb=monitordb->get_db();
	int rc;
	//char *query=NULL;
	char *query1=NULL;
	query1=(char *)"INSERT INTO mysql_server_galera_log VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
	sqlite3_stmt *statement1=NULL;
*/
	char *str = NULL;
	pthread_mutex_lock(&GloMyMon->galera_mutex);
/*
	rc=(*proxy_sqlite3_prepare_v2)(mondb, query1, -1, &statement1, 0);
	ASSERT_SQLITE_OK(rc, monitordb);
	monitordb->execute((char *)"DELETE FROM mysql_server_galera_log");
*/
	std::map<std::string, Galera_monitor_node *>::iterator it2;
	Galera_monitor_node *node=NULL;
	Galera_monitor_node *writer_node=NULL;
	unsigned int writer_nodes = 0;
	unsigned long long curtime = monotonic_time();
	unsigned long long ti = mysql_thread___monitor_galera_healthcheck_interval;
	ti *= 2;
	std::string s = "";
	for (it2=GloMyMon->Galera_Hosts_Map.begin(); it2!=GloMyMon->Galera_Hosts_Map.end(); ++it2) {
		node=it2->second;
		if (node->writer_hostgroup == (unsigned int)writer_hostgroup) {
			Galera_status_entry_t * st = node->last_entry();
			if (st) {
				if (st->start_time >= curtime - ti) { // only consider recent checks
					if (st->error == NULL) { // no check error
						if (st->read_only == false) { // the server is writable (this check is arguable)
							if (st->wsrep_sst_donor_rejects_queries == false) {
								if (writer_nodes == 0) {
									s=it2->first;
									writer_node = node;
								}
								writer_nodes++;
							}
						}
					}
				}
			}
		}
	}
	if (writer_node && writer_nodes == 1) {
		// we have only one node let
		// we don't care if status
		str = strdup(s.c_str());
/*
		std::size_t found=s.find_last_of(":");
		std::string host=s.substr(0,found);
		std::string port=s.substr(found+1);
*/
	}
	pthread_mutex_unlock(&GloMyMon->galera_mutex);
	return str;
}

std::vector<string> * MySQL_Monitor::galera_find_possible_last_nodes(int writer_hostgroup) {
	std::vector<string> * result = new std::vector<string>();
	pthread_mutex_lock(&GloMyMon->galera_mutex);
	std::map<std::string, Galera_monitor_node *>::iterator it2;
	Galera_monitor_node *node=NULL;
	unsigned long long curtime = monotonic_time();
	unsigned long long ti = mysql_thread___monitor_galera_healthcheck_interval;
	ti *= 2;
	for (it2=GloMyMon->Galera_Hosts_Map.begin(); it2!=GloMyMon->Galera_Hosts_Map.end(); ++it2) {
		node=it2->second;
		if (node->writer_hostgroup == (unsigned int)writer_hostgroup) {
			Galera_status_entry_t * st = node->last_entry();
			if (st) {
				if (st->start_time >= curtime - ti) { // only consider recent checks
					if (st->error == NULL) { // no check error
						if (st->wsrep_reject_queries == false) {
							if (st->read_only == false) { // the server is writable (this check is arguable)
								if (st->wsrep_sst_donor_rejects_queries == false) {
									string s = it2->first;
									result->push_back(s);
								}
							}
						}
					}
				}
			}
		}
	}
	pthread_mutex_unlock(&GloMyMon->galera_mutex);
	return result;
}

void MySQL_Monitor::populate_monitor_mysql_server_aws_aurora_log() {
	char *query1=NULL;
	query1=(char *)"INSERT OR IGNORE INTO mysql_server_aws_aurora_log VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
	char *query2=NULL;
	query2=(char *)"INSERT OR IGNORE INTO mysql_server_aws_aurora_log (hostname, port, time_start_us, success_time_us, error) VALUES (?1, ?2, ?3, ?4, ?5)";
	auto [rc1, statement1_unique] = monitordb->prepare_v2(query1);
	ASSERT_SQLITE_OK(rc1, monitordb);
	auto [rc2, statement2_unique] = monitordb->prepare_v2(query2);
	ASSERT_SQLITE_OK(rc2, monitordb);
	sqlite3_stmt *statement1 = statement1_unique.get();
	sqlite3_stmt *statement2 = statement2_unique.get();
	int rc;
	pthread_mutex_lock(&GloMyMon->aws_aurora_mutex);
	monitordb->execute((char *)"DELETE FROM mysql_server_aws_aurora_log");
	std::map<std::string, AWS_Aurora_monitor_node *>::iterator it2;
	AWS_Aurora_monitor_node *node=NULL;
	for (it2=GloMyMon->AWS_Aurora_Hosts_Map.begin(); it2!=GloMyMon->AWS_Aurora_Hosts_Map.end(); ++it2) {
		std::string s=it2->first;
		node=it2->second;
		std::size_t found=s.find_last_of(":");
		std::string host=s.substr(0,found);
		std::string port=s.substr(found+1);
		int i;
		for (i=0; i<AWS_Aurora_Nentries; i++) {
			AWS_Aurora_status_entry * aase = node->last_entries[i];
			if (aase && aase->start_time) {
				if ( aase->host_statuses->size() ) {
					for (std::vector<AWS_Aurora_replica_host_status_entry *>::iterator it3 = aase->host_statuses->begin(); it3!=aase->host_statuses->end(); ++it3) {
						AWS_Aurora_replica_host_status_entry *hse = *it3;
						if (hse) {
							rc=(*proxy_sqlite3_bind_text)(statement1, 1, host.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoi(port.c_str())); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_int64)(statement1, 3, aase->start_time ); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_int64)(statement1, 4, aase->check_time ); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_text)(statement1, 5, aase->error , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_text)(statement1, 6, hse->server_id , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_text)(statement1, 7, hse->session_id , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_text)(statement1, 8, hse->last_update_timestamp , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_double)(statement1, 9, hse->replica_lag_ms ); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_int64)(statement1, 10, hse->estimated_lag_ms ); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_double)(statement1, 11, hse->cpu ); ASSERT_SQLITE_OK(rc, monitordb);
							SAFE_SQLITE3_STEP2(statement1);
							rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, monitordb);
						}
					}
				} else {
					rc=(*proxy_sqlite3_bind_text)(statement2, 1, host.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 2, atoi(port.c_str())); ASSERT_SQLITE_OK(rc, monitordb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 3, aase->start_time ); ASSERT_SQLITE_OK(rc, monitordb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 4, aase->check_time ); ASSERT_SQLITE_OK(rc, monitordb);
					rc=(*proxy_sqlite3_bind_text)(statement2, 5, aase->error , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
					SAFE_SQLITE3_STEP2(statement2);
					rc=(*proxy_sqlite3_clear_bindings)(statement2); ASSERT_SQLITE_OK(rc, monitordb);
					rc=(*proxy_sqlite3_reset)(statement2); ASSERT_SQLITE_OK(rc, monitordb);
				}
			}
		}
	}
	pthread_mutex_unlock(&GloMyMon->aws_aurora_mutex);
}

void MySQL_Monitor::populate_monitor_mysql_server_aws_aurora_check_status() {
	char *query1=NULL;
	query1=(char *)"INSERT OR IGNORE INTO mysql_server_aws_aurora_check_status VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
	auto [rc1, statement1_unique] = monitordb->prepare_v2(query1);
	ASSERT_SQLITE_OK(rc1, monitordb);
	sqlite3_stmt *statement1 = statement1_unique.get();
	int rc;
	pthread_mutex_lock(&GloMyMon->aws_aurora_mutex);
	monitordb->execute((char *)"DELETE FROM mysql_server_aws_aurora_check_status");
	std::map<std::string, AWS_Aurora_monitor_node *>::iterator it2;
	AWS_Aurora_monitor_node *node=NULL;
	for (it2=GloMyMon->AWS_Aurora_Hosts_Map.begin(); it2!=GloMyMon->AWS_Aurora_Hosts_Map.end(); ++it2) {
		std::string s=it2->first;
		node=it2->second;
		std::size_t found=s.find_last_of(":");
		std::string host=s.substr(0,found);
		std::string port=s.substr(found+1);
		AWS_Aurora_status_entry * aase = node->last_entry();
		char *error_msg = NULL;
		if (aase && aase->start_time) {
			if (aase->error) {
				error_msg = aase->error;
			}
		}
		char lut[30];
		struct tm __tm_info;
		localtime_r(&node->last_checked_at, &__tm_info);
		strftime(lut, 25, "%Y-%m-%d %H:%M:%S", &__tm_info);

/*
		int i;
		for (i=0; i<AWS_Aurora_Nentries; i++) {
			AWS_Aurora_status_entry * aase = node->last_entries[i];
			if (aase && aase->start_time) {
				if ( aase->host_statuses->size() ) {
					for (std::vector<AWS_Aurora_replica_host_status_entry *>::iterator it3 = aase->host_statuses->begin(); it3!=aase->host_statuses->end(); ++it3) {
						AWS_Aurora_replica_host_status_entry *hse = *it3;
						if (hse) {
*/
							rc=(*proxy_sqlite3_bind_int64)(statement1, 1, node->writer_hostgroup); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_text)(statement1, 2, host.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_int64)(statement1, 3, atoi(port.c_str())); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_text)(statement1, 4, lut, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_int64)(statement1, 5, node->num_checks_tot ); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_int64)(statement1, 6, node->num_checks_ok ); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_bind_text)(statement1, 7, error_msg , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
							SAFE_SQLITE3_STEP2(statement1);
							rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, monitordb);
							rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, monitordb);
/*
						}
					}
				} else {
					rc=(*proxy_sqlite3_bind_text)(statement2, 1, host.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 2, atoi(port.c_str())); ASSERT_SQLITE_OK(rc, monitordb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 3, aase->start_time ); ASSERT_SQLITE_OK(rc, monitordb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 4, aase->check_time ); ASSERT_SQLITE_OK(rc, monitordb);
					rc=(*proxy_sqlite3_bind_text)(statement2, 5, aase->error , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitordb);
					SAFE_SQLITE3_STEP2(statement2);
					rc=(*proxy_sqlite3_clear_bindings)(statement2); ASSERT_SQLITE_OK(rc, monitordb);
					rc=(*proxy_sqlite3_reset)(statement2); ASSERT_SQLITE_OK(rc, monitordb);
				}
			}
		}
*/
	}
	pthread_mutex_unlock(&GloMyMon->aws_aurora_mutex);
}

/*
void MySQL_Monitor::gdb_dump___monitor_mysql_server_aws_aurora_log(char *hostname) {
	fprintf(stderr,"gdb_dump___monitor_mysql_server_aws_aurora_log\n");
	std::map<std::string, AWS_Aurora_monitor_node *>::iterator it2;
	AWS_Aurora_monitor_node *node=NULL;
	for (it2=GloMyMon->AWS_Aurora_Hosts_Map.begin(); it2!=GloMyMon->AWS_Aurora_Hosts_Map.end(); ++it2) {
		std::string s=it2->first;
		node=it2->second;
		std::size_t found=s.find_last_of(":");
		std::string host=s.substr(0,found);
		std::string port=s.substr(found+1);
		int i;
		for (i=0; i<AWS_Aurora_Nentries; i++) {
			AWS_Aurora_status_entry * aase = node->last_entries[i];
			if (aase && aase->start_time) {
				if ( aase->host_statuses->size() ) {
					for (std::vector<AWS_Aurora_replica_host_status_entry *>::iterator it3 = aase->host_statuses->begin(); it3!=aase->host_statuses->end(); ++it3) {
						AWS_Aurora_replica_host_status_entry *hse = *it3;
						if (hse) {
							if (hostname == NULL || (hostname && ( (strcmp(hostname,host.c_str())==0) || (strcmp(hostname,hse->server_id)==0)) )) {
								fprintf(stderr,"%s:%d %llu %llu %s %s %s %s %f %f\n", host.c_str(), atoi(port.c_str()), aase->start_time, aase->check_time, aase->error, hse->server_id,hse->session_id, hse->last_update_timestamp, hse->replica_lag_ms , hse->cpu);
							}
						}
					}
				} else {
					if (hostname == NULL || (hostname && strcmp(hostname,host.c_str())==0) ) {
						fprintf(stderr,"%s:%d %llu %llu %s\n", host.c_str(), atoi(port.c_str()), aase->start_time, aase->check_time, aase->error);
					}
				}
			}
		}
	}
}
*/

AWS_Aurora_monitor_node::AWS_Aurora_monitor_node(char *_a, int _p, int _whg) {
	addr=NULL;
	if (_a) {
		addr=strdup(_a);
	}
	port=_p;
	idx_last_entry=-1;
	writer_hostgroup=_whg;
	int i;
	for (i=0;i<AWS_Aurora_Nentries;i++) {
		last_entries[i] = NULL;
		//last_entries[i]->start_time=0;
		//last_entries[i]->check_time=0;
	}
	num_checks_tot = 0;
	num_checks_ok = 0;
	last_checked_at = 0;
}

AWS_Aurora_monitor_node::~AWS_Aurora_monitor_node() {
	if (addr) {
		free(addr);
	}
}

bool AWS_Aurora_monitor_node::add_entry(AWS_Aurora_status_entry *ase) {
	bool ret=false;
	if (idx_last_entry==-1) ret=true;
	idx_last_entry++;
	if (idx_last_entry>=AWS_Aurora_Nentries) {
		idx_last_entry=0;
	}
	if (last_entries[idx_last_entry]) {
		AWS_Aurora_status_entry *old = last_entries[idx_last_entry];
		delete old;
	}
	last_entries[idx_last_entry] = ase;
	num_checks_tot++;
	if (ase->error == NULL) {
		num_checks_ok++;
	}
	last_checked_at = time(NULL);
	return ret; // for now ignored
}


typedef struct _host_def_t {
	char *host;
	int port;
	int use_ssl;
} host_def_t;

static void shuffle_hosts(host_def_t *array, size_t n) {
	char tmp[sizeof(host_def_t)];
	char *arr = (char *)array;
	size_t stride = sizeof(host_def_t) * sizeof(char);

	if (n > 1) {
		size_t i;
		for (i = 0; i < n - 1 ; ++i) {
			size_t rnd = (size_t) fastrand();
			size_t j = i + rnd / (0x7FFF / (n - i) + 1);
			memcpy(tmp, arr + j * stride, sizeof(host_def_t));
			memcpy(arr + j * stride, arr + i * stride, sizeof(host_def_t));
			memcpy(arr + i * stride, tmp, sizeof(host_def_t));
		}
	}
}

void * monitor_AWS_Aurora_thread_HG(void *arg) {
	unsigned int wHG = *(unsigned int *)arg;
	unsigned int rHG = 0;
	unsigned int num_hosts = 0;
	unsigned int cur_host_idx = 0;
	unsigned int max_lag_ms = 0;
	unsigned int check_interval_ms = 0;
	unsigned int check_timeout_ms = 0;
	unsigned int add_lag_ms = 0;
	unsigned int min_lag_ms = 0;
	unsigned int lag_num_checks = 1;
	unsigned int autopurge_missing_checks = 0;
	std::string domain_name;
	std::map<std::string, int> autopurge_counter;
	set_thread_name("MonitorAuroraHG", GloVars.set_thread_name);
	proxy_info("Started Monitor thread for AWS Aurora writer HG %u\n", wHG);

	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();

	uint64_t initial_raw_checksum = 0;

	// this is a static array of the latest reads
	unsigned int ase_idx = 0;
	AWS_Aurora_status_entry *lasts_ase[N_L_ASE];
	for (unsigned int i=0; i<N_L_ASE; i++) {
		lasts_ase[i] = NULL;
	}

	// initial data load
	pthread_mutex_lock(&GloMyMon->aws_aurora_mutex);
	initial_raw_checksum = GloMyMon->AWS_Aurora_Hosts_resultset_checksum;
	// count the number of hosts
	for (std::vector<SQLite3_row *>::iterator it = GloMyMon->AWS_Aurora_Hosts_resultset->rows.begin() ; it != GloMyMon->AWS_Aurora_Hosts_resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		if (atoi(r->fields[0]) == (int)wHG) {
			num_hosts++;
			if (max_lag_ms == 0) {
				max_lag_ms = atoi(r->fields[5]);
			}
			if (check_interval_ms == 0) {
				check_interval_ms = atoi(r->fields[6]);
			}
			if (check_timeout_ms == 0) {
				check_timeout_ms = atoi(r->fields[7]);
			}
			if (rHG == 0) {
				rHG = atoi(r->fields[1]);
			}
			add_lag_ms = atoi(r->fields[8]);
			min_lag_ms = atoi(r->fields[9]);
			lag_num_checks = atoi(r->fields[10]);
			autopurge_missing_checks = atoi(r->fields[11]);
			if (domain_name.empty() && r->fields[12]) {
				domain_name = r->fields[12];
			}
		}
	}
	host_def_t *hpa = (host_def_t *)malloc(sizeof(host_def_t)*num_hosts);
	for (std::vector<SQLite3_row *>::iterator it = GloMyMon->AWS_Aurora_Hosts_resultset->rows.begin() ; it != GloMyMon->AWS_Aurora_Hosts_resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		if (atoi(r->fields[0]) == (int)wHG) {
			hpa[cur_host_idx].host = strdup(r->fields[2]);
			hpa[cur_host_idx].port = atoi(r->fields[3]);
			hpa[cur_host_idx].use_ssl = atoi(r->fields[4]);
			cur_host_idx++;
		}
	}
	// NOTE: 'cur_host_idx' should never be higher than 'num_hosts' otherwise later an invalid memory access
	// can table place later when accessing 'hpa[cur_host_idx]'.
	if (cur_host_idx >= num_hosts) {
		cur_host_idx = num_hosts - 1;
	}
	pthread_mutex_unlock(&GloMyMon->aws_aurora_mutex);

	bool exit_now = false;
	unsigned long long t1 = 0;
	//unsigned long long t2 = 0;
	unsigned long long next_loop_at = 0;

	bool crc = false;

	uint64_t current_raw_checksum = 0;
	size_t rnd;
	bool found_pingable_host = false;
	bool rc_ping = false;
	MySQL_Monitor_State_Data *mmsd = NULL;

	t1 = monotonic_time();
	unsigned long long start_time=t1;

	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true && exit_now==false) {

		
		unsigned int glover;
		t1=monotonic_time();

		//proxy_info("Looping Monitor thread for AWS Aurora writer HG %u\n", wHG);

		if (!GloMTH) {
			//proxy_info("Stopping Monitor thread for AWS Aurora writer HG %u\n", wHG);
			goto __exit_monitor_AWS_Aurora_thread_HG_now;
			return NULL;	// quick exit during shutdown/restart
		}

		// if variables has changed, triggers new checks
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			next_loop_at=0;
		}

		pthread_mutex_lock(&GloMyMon->aws_aurora_mutex);
		current_raw_checksum = GloMyMon->AWS_Aurora_Hosts_resultset_checksum;
		pthread_mutex_unlock(&GloMyMon->aws_aurora_mutex);

		if (current_raw_checksum != initial_raw_checksum) {
			// the content of AWS_Aurora_Hosts_resultset has changed. Exit
			exit_now=true;
			break;
		}
		//fprintf(stderr,"%u : %llu %llu\n", wHG, t1, next_loop_at);
		if (t1 < next_loop_at) {
			unsigned long long st=0;
			st=next_loop_at-t1;
			if (st > 50000) {
				st = 50000;
			}
			usleep(st);
			//proxy_info("Looping Monitor thread for AWS Aurora writer HG %u\n", wHG);
			continue;
		}
		//proxy_info("Running check AWS Aurora writer HG %u\n", wHG);
		found_pingable_host = false;

		rc_ping = false;
		// pick a random host
		rnd = (size_t) rand();
		rnd %= num_hosts;
		rc_ping = GloMyMon->server_responds_to_ping(hpa[rnd].host, hpa[rnd].port);
		//proxy_info("Looping Monitor thread for AWS Aurora writer HG %u\n", wHG);
#ifdef TEST_AURORA_RANDOM
		if (rand() % 100 < 30) {
			// we randomly fail 30% of the requests
			rc_ping = false;
		}
#endif // TEST_AURORA_RANDOM
		if (rc_ping) {
			found_pingable_host = true;
			cur_host_idx = rnd;
		} else {
			MyHGM->p_update_mysql_error_counter(
				p_mysql_error_type::proxysql, wHG, hpa[rnd].host, hpa[rnd].port, ER_PROXYSQL_AWS_NO_PINGABLE_SRV
			);
			// the randomly picked host didn't work work
			shuffle_hosts(hpa,num_hosts);
			for (unsigned int i=0; (found_pingable_host == false && i<num_hosts ) ; i++) {
				rc_ping = GloMyMon->server_responds_to_ping(hpa[i].host, hpa[i].port);
				if (rc_ping) {
					found_pingable_host = true;
					cur_host_idx = i;
				} else {
					MyHGM->p_update_mysql_error_counter(
						p_mysql_error_type::proxysql, wHG, hpa[i].host, hpa[i].port, ER_PROXYSQL_AWS_NO_PINGABLE_SRV
					);
				}
			}
		}

#ifdef TEST_AURORA_RANDOM
		if (rand() % 200 == 0) {
			// we randomly fail 0.5% of the requests
			found_pingable_host = false;
		}
#endif // TEST_AURORA_RANDOM

		if (found_pingable_host == false) {
			proxy_error("No node is pingable for AWS Aurora cluster with writer HG %u\n", wHG);
			next_loop_at = t1 + check_interval_ms * 1000;
			continue;
		}
#ifdef TEST_AURORA
		if (rand() % 1000 == 0) { // suppress 99.9% of the output, too verbose
			proxy_info("Running check for AWS Aurora writer HG %u on %s:%d\n", wHG , hpa[cur_host_idx].host, hpa[cur_host_idx].port);
		}
#endif // TEST_AURORA
		if (mmsd) {
			delete mmsd;
			mmsd = NULL;
		}
		//mmsd = NULL;
		mmsd = new MySQL_Monitor_State_Data(MON_AWS_AURORA, hpa[cur_host_idx].host, hpa[cur_host_idx].port, hpa[cur_host_idx].use_ssl);
		mmsd->writer_hostgroup = wHG;
		mmsd->aws_aurora_check_timeout_ms = check_timeout_ms;
		mmsd->mysql=GloMyMon->My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port, mmsd);
		//unsigned long long start_time=mysql_thr->curtime;
		start_time=t1;


		mmsd->t1=start_time;

		crc=false;
		if (mmsd->mysql==NULL) { // we don't have a connection, let's create it
			bool rc;
			rc=mmsd->create_new_connection();
			if (mmsd->mysql) {
				GloMyMon->My_Conn_Pool->conn_register(mmsd);
			}
			crc=true;
			if (rc==false) {
				unsigned long long now=monotonic_time();
				char * new_error = (char *)malloc(50+strlen(mmsd->mysql_error_msg));
				bool access_denied = false;
				if (strncmp(mmsd->mysql_error_msg,(char *)"Access denied for user",strlen((char *)"Access denied for user"))==0) {
					access_denied = true;
				}
				sprintf(new_error,"timeout or error in creating new connection: %s",mmsd->mysql_error_msg);
				free(mmsd->mysql_error_msg);
				mmsd->mysql_error_msg = new_error;
				proxy_error("Error on AWS Aurora check for %s:%d after %lldms. Unable to create a connection. %sError: %s.\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000, (access_denied ? "" : "If the server is overload, increase mysql-monitor_connect_timeout. " ) , new_error);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_AWS_HEALTH_CHECK_CONN_TIMEOUT);
				goto __exit_monitor_aws_aurora_HG_thread;
			}
		}

	mmsd->t1=monotonic_time();
	mmsd->interr=0; // reset the value
	// for reference we list the old queries.
	// original implementation:
	// mmsd->async_exit_status = mysql_query_start(&mmsd->interr, mmsd->mysql, "SELECT SERVER_ID, SESSION_ID, LAST_UPDATE_TIMESTAMP, IF(SESSION_ID = 'MASTER_SESSION_ID', 0, REPLICA_LAG_IN_MILLISECONDS) AS REPLICA_LAG_IN_MILLISECONDS, CPU FROM INFORMATION_SCHEMA.REPLICA_HOST_STATUS WHERE (REPLICA_LAG_IN_MILLISECONDS > 0 AND REPLICA_LAG_IN_MILLISECONDS <= 600000) OR SESSION_ID = 'MASTER_SESSION_ID' ORDER BY SERVER_ID");
	// to fix a bug in Aurora , see https://github.com/sysown/proxysql/issues/3082
	// mmsd->async_exit_status = mysql_query_start(&mmsd->interr, mmsd->mysql, "SELECT SERVER_ID, SESSION_ID, LAST_UPDATE_TIMESTAMP, IF(SESSION_ID = 'MASTER_SESSION_ID', 0, REPLICA_LAG_IN_MILLISECONDS) AS REPLICA_LAG_IN_MILLISECONDS, CPU FROM INFORMATION_SCHEMA.REPLICA_HOST_STATUS WHERE (REPLICA_LAG_IN_MILLISECONDS > 0 AND REPLICA_LAG_IN_MILLISECONDS <= 600000) OR SESSION_ID = 'MASTER_SESSION_ID' ORDER BY SERVER_ID");
	// slightly modifying the previous query. Replacing:
	//   "REPLICA_LAG_IN_MILLISECONDS > 0"
	// with:
	//   "REPLICA_LAG_IN_MILLISECONDS >= 0"
	// mmsd->async_exit_status = mysql_query_start(&mmsd->interr, mmsd->mysql, "SELECT SERVER_ID, SESSION_ID, LAST_UPDATE_TIMESTAMP, IF(SESSION_ID = 'MASTER_SESSION_ID', 0, REPLICA_LAG_IN_MILLISECONDS) AS REPLICA_LAG_IN_MILLISECONDS, CPU FROM INFORMATION_SCHEMA.REPLICA_HOST_STATUS WHERE (REPLICA_LAG_IN_MILLISECONDS >= 0 AND REPLICA_LAG_IN_MILLISECONDS <= 600000) OR SESSION_ID = 'MASTER_SESSION_ID' ORDER BY SERVER_ID");
	mmsd->async_exit_status = mysql_query_start(
		&mmsd->interr, mmsd->mysql, QUERY_AWS_AURORA_REPLICA_HOST_STATUS);
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
#ifdef DEBUG
		const unsigned long long now = (GloMyMon->proxytest_forced_timeout == false) ? monotonic_time() : ULLONG_MAX;
#else
		const unsigned long long now = monotonic_time();
#endif
		if (now > mmsd->t1 + mmsd->aws_aurora_check_timeout_ms * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			proxy_error("Timeout on AWS Aurora health check for %s:%d after %lldms. If the server is overload, increase mysql_aws_aurora_hostgroups.check_timeout_ms\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_AWS_HEALTH_CHECK_TIMEOUT);
			goto __exit_monitor_aws_aurora_HG_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_aws_aurora_HG_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_query_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	mmsd->async_exit_status=mysql_store_result_start(&mmsd->result,mmsd->mysql);
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
#ifdef DEBUG
		const unsigned long long now = (GloMyMon->proxytest_forced_timeout == false) ? monotonic_time() : ULLONG_MAX;
#else
		const unsigned long long now = monotonic_time();
#endif
		if (now > mmsd->t1 + mmsd->aws_aurora_check_timeout_ms * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			proxy_error("Timeout on AWS Aurora health check for %s:%d after %lldms. If the server is overload, increase mysql_aws_aurora_hostgroups.check_timeout_ms\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_AWS_HEALTH_CHECK_TIMEOUT);
			goto __exit_monitor_aws_aurora_HG_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_aws_aurora_HG_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_store_result_cont(&mmsd->result, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) { // check failed
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
		MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
	}

__exit_monitor_aws_aurora_HG_thread:
		mmsd->t2=monotonic_time();
		next_loop_at = t1 + (check_interval_ms * 1000);
		if (mmsd->t2 > t1) {
			next_loop_at -= (mmsd->t2 - t1);
		}
		{
			// TODO : complete this
			char buf[128];
			char *s=NULL;
			int l=strlen(mmsd->hostname);
			if (l<110) {
				s=buf;
			}	else {
				s=(char *)malloc(l+16);
			}
			sprintf(s,"%s:%d",mmsd->hostname,mmsd->port);
			unsigned long long time_now=realtime_time();
			time_now=time_now-(mmsd->t2 - start_time);
			//AWS_Aurora_status_entry *ase = new AWS_Aurora_status_entry(mmsd->t1, mmsd->t2-mmsd->t1, mmsd->mysql_error_msg);
			//AWS_Aurora_status_entry *ase_l = new AWS_Aurora_status_entry(mmsd->t1, mmsd->t2-mmsd->t1, mmsd->mysql_error_msg);
			AWS_Aurora_status_entry *ase = new AWS_Aurora_status_entry(time_now, mmsd->t2-mmsd->t1, mmsd->mysql_error_msg);
			AWS_Aurora_status_entry *ase_l = new AWS_Aurora_status_entry(time_now, mmsd->t2-mmsd->t1, mmsd->mysql_error_msg);
			if (mmsd->interr == 0 && mmsd->result) {
				int num_fields=0;
				num_fields = mysql_num_fields(mmsd->result);
				if (num_fields!=5) {
					proxy_error("Incorrect number of fields, please report a bug\n");
				} else {
					MYSQL_ROW row;
					while ((row = mysql_fetch_row(mmsd->result))) {
						AWS_Aurora_replica_host_status_entry *arhse = new AWS_Aurora_replica_host_status_entry(row[0], row[1], row[2], row[3], row[4]);
						ase->add_host_status(arhse);
						AWS_Aurora_replica_host_status_entry *arhse_l = new AWS_Aurora_replica_host_status_entry(row[0], row[1], row[2], row[3], row[4]);
						ase_l->add_host_status(arhse_l);
					}
				}
				mysql_free_result(mmsd->result);
				mmsd->result=NULL;
			}

			if (lasts_ase[ase_idx]) {
				AWS_Aurora_status_entry * l_ase = lasts_ase[ase_idx];
				delete l_ase;
			}
			lasts_ase[ase_idx] = ase_l;
			GloMyMon->evaluate_aws_aurora_results(wHG, rHG, &lasts_ase[0], ase_idx, max_lag_ms, add_lag_ms, min_lag_ms, lag_num_checks);

			// Auto-purge servers that disappear from REPLICA_HOST_STATUS
			// Only process if autopurge is enabled and query was successful with results
			if (autopurge_missing_checks > 0 && mmsd->interr == 0 && ase->host_statuses->size() > 0) {
				GloMyMon->aws_aurora_autopurge_servers(wHG, rHG, ase, autopurge_missing_checks, autopurge_counter, domain_name);
			}

			for (auto h : *(ase_l->host_statuses)) {
				for (auto h2 : *(ase->host_statuses)) {
					if (strcmp(h2->server_id, h->server_id) == 0) {
						h2->estimated_lag_ms = h->estimated_lag_ms;
					}
				}
			}
			// remember that we call evaluate_aws_aurora_results()
			// *before* shifting ase_idx
			ase_idx++;
			if (ase_idx == N_L_ASE) {
				ase_idx = 0;
			}

//__end_process_aws_aurora_result:
			if (mmsd->mysql_error_msg) {
			}
			pthread_mutex_lock(&GloMyMon->aws_aurora_mutex);
			//auto it =
			// TODO : complete this
			std::map<std::string, AWS_Aurora_monitor_node *>::iterator it2;
			it2 = GloMyMon->AWS_Aurora_Hosts_Map.find(s);
			AWS_Aurora_monitor_node *node=NULL;
			if (it2!=GloMyMon->AWS_Aurora_Hosts_Map.end()) {
				node=it2->second;
				node->add_entry(ase);
			} else {
				node = new AWS_Aurora_monitor_node(mmsd->hostname,mmsd->port,mmsd->writer_hostgroup);
				node->add_entry(ase);
				GloMyMon->AWS_Aurora_Hosts_Map.insert(std::make_pair(s,node));
			}
			// clean up
			if (l<110) {
			} else {
				free(s);
			}
			pthread_mutex_unlock(&GloMyMon->aws_aurora_mutex);

		}
		if (mmsd->interr || mmsd->async_exit_status) { // check failed
		} else {
			if (crc==false) {
				if (mmsd->mysql) {
					GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
				}
			}
		}
__fast_exit_monitor_aws_aurora_HG_thread:
	if (mmsd->mysql) {
		// if we reached here we didn't put the connection back
		if (mmsd->mysql_error_msg) {
#ifdef DEBUG
			proxy_error("Error after %lldms: server %s:%d , mmsd %p , MYSQL %p , FD %d : %s\n", (mmsd->t2-mmsd->t1)/1000, mmsd->hostname, mmsd->port, mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
#else
			proxy_error("Error after %lldms on server %s:%d : %s\n", (mmsd->t2-mmsd->t1)/1000, mmsd->hostname, mmsd->port, mmsd->mysql_error_msg);
#endif // DEBUG
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
			GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
		} else {
			if (crc) {
				bool rc=mmsd->set_wait_timeout();
				if (rc) {
					GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
				} else {
					proxy_error("Error after %lldms: mmsd %p , MYSQL %p , FD %d : %s\n", (mmsd->t2-mmsd->t1)/1000, mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
					MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
					GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
				}
			} else { // really not sure how we reached here, drop it
				proxy_error("Error after %lldms: mmsd %p , MYSQL %p , FD %d : %s\n", (mmsd->t2-mmsd->t1)/1000, mmsd, mmsd->mysql, mmsd->mysql->net.fd, mmsd->mysql_error_msg);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
				GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
			}
		}
	}
	}
__exit_monitor_AWS_Aurora_thread_HG_now:
	if (mmsd) {
		delete (mmsd);
		mmsd = NULL;
	for (unsigned int i=0; i<N_L_ASE; i++) {
		if (lasts_ase[i]) {
			delete lasts_ase[i];
			lasts_ase[i] = NULL;
		}
	}
	}

	free(hpa);
	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr=NULL;
	}
	for (unsigned int i=0; i<N_L_ASE; i++) {
		if (lasts_ase[i]) {
			AWS_Aurora_status_entry * ase = lasts_ase[i];
			delete ase;
		}
	}
	proxy_info("Stopping Monitor thread for AWS Aurora writer HG %u\n", wHG);
	return NULL;
}


void * MySQL_Monitor::monitor_aws_aurora() {
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth()) return NULL;	// quick exit during shutdown/restart
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();

	uint64_t last_raw_checksum = 0;

	// ADD here an unordered map , Writer HG => next time at
	// when empty, a new map is populated
	// when next_loop_at = 0 , the tables is emptied so to be populated again

	unsigned int *hgs_array = NULL;
	pthread_t *pthreads_array = NULL;
	unsigned int hgs_num = 0;

	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true) {

		unsigned int glover;

		if (!GloMTH) return NULL;	// quick exit during shutdown/restart

		// if variables has changed, triggers new checks
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
		}

		// if list of servers or HG or options has changed, triggers new checks
		pthread_mutex_lock(&aws_aurora_mutex);
		uint64_t new_raw_checksum = AWS_Aurora_Hosts_resultset->raw_checksum();
		pthread_mutex_unlock(&aws_aurora_mutex);
		if (new_raw_checksum != last_raw_checksum) {
			proxy_info("Detected new/changed definition for AWS Aurora monitoring\n");
			last_raw_checksum = new_raw_checksum;
			if (pthreads_array) {
				// wait all threads to terminate
				for (unsigned int i=0; i < hgs_num; i++) {
					pthread_join(pthreads_array[i], NULL);
					proxy_info("Stopped Monitor thread for AWS Aurora writer HG %u\n", hgs_array[i]);
				}
				free(pthreads_array);
				free(hgs_array);
				pthreads_array = NULL;
				hgs_array = NULL;
			}
			hgs_num = 0;
			pthread_mutex_lock(&aws_aurora_mutex);
			// scan all the writer HGs
			unsigned int num_rows = AWS_Aurora_Hosts_resultset->rows_count;
			if (num_rows) {
				unsigned int *tmp_hgs_array = (unsigned int *)malloc(sizeof(unsigned int)*num_rows);
				for (std::vector<SQLite3_row *>::iterator it = AWS_Aurora_Hosts_resultset->rows.begin() ; it != AWS_Aurora_Hosts_resultset->rows.end(); ++it) {
					SQLite3_row *r=*it;
					int wHG = atoi(r->fields[0]);
					bool found = false;
					// very simple search. Far from optimal, but assuming very few HGs it is fast enough
					for (unsigned int i=0; i < hgs_num; i++) {
						if (tmp_hgs_array[i] == (unsigned int)wHG) {
							found = true;
						}
					}
					if (found == false) {
						// new wHG found
						tmp_hgs_array[hgs_num]=wHG;
						hgs_num++;
					}
				}
				proxy_info("Activating Monitoring of %u AWS Aurora clusters\n", hgs_num);
				hgs_array = (unsigned int *)malloc(sizeof(unsigned int)*hgs_num);
				pthreads_array = (pthread_t *)malloc(sizeof(pthread_t)*hgs_num);
				for (unsigned int i=0; i < hgs_num; i++) {
					hgs_array[i] = tmp_hgs_array[i];
					proxy_info("Starting Monitor thread for AWS Aurora writer HG %u\n", hgs_array[i]);
					if (pthread_create(&pthreads_array[i], NULL, monitor_AWS_Aurora_thread_HG, &hgs_array[i]) != 0) {
						// LCOV_EXCL_START
						proxy_error("Thread creation\n");
						assert(0);
						// LCOV_EXCL_STOP
					}
				}
				free(tmp_hgs_array);
			}
			pthread_mutex_unlock(&aws_aurora_mutex);
		}

		usleep(10000);
	}
	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr=NULL;
	}
	for (unsigned int i=0;i<num_threads; i++) {
		WorkItem<MySQL_Monitor_State_Data> *item=NULL;
		GloMyMon->queue->add(item);
	}
	return NULL;
}

/**
* @brief Runs an async query + store_result on the monitor connection.
*
* @param mmsd        Monitor state data holding the connection, timing, and result.
* @param query       SQL text to execute.
* @param worker_stop Per-worker shutdown signal.
*
* @return 0 on success, 1 on timeout/query-error, 2 if global or worker shutdown was requested.
*/
int MySQL_Monitor::aws_rds_bgd_async_query(MySQL_Monitor_State_Data *mmsd, const char *query, std::atomic_bool& worker_stop) {
	mmsd->t1 = monotonic_time();
	mmsd->interr = 0;
	mmsd->async_exit_status = mysql_query_start(&mmsd->interr, mmsd->mysql, query);
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status = wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		const unsigned long long now = monotonic_time();
		if (now > mmsd->t1 + mmsd->aws_aurora_check_timeout_ms * 1000) {
			mmsd->mysql_error_msg = strdup("timeout check");
			return 1;
		}
		if (shutdown == true || worker_stop.load()) {
			return 2;
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status = mysql_query_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	mmsd->async_exit_status = mysql_store_result_start(&mmsd->result, mmsd->mysql);
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status = wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		const unsigned long long now = monotonic_time();
		if (now > mmsd->t1 + mmsd->aws_aurora_check_timeout_ms * 1000) {
			mmsd->mysql_error_msg = strdup("timeout check");
			return 1;
		}
		if (shutdown == true || worker_stop.load()) {
			return 2;
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status = mysql_store_result_cont(&mmsd->result, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) { // query failed (may be ER_NO_SUCH_TABLE 1146)
		mmsd->mysql_error_msg = strdup(mysql_error(mmsd->mysql));
		return 1;
	}
	return 0;
}

/**
* @brief Flag servers as switchover-in-progress so the read_only monitor skips them.
*/
static void aws_rds_bgd_set_bgd_in_progress(AWS_RDS_BGD_State& st) {
	if (st.bgd_in_progress_set) {
		return;
	}

	GloMyMon->set_aws_rds_bgd_server_in_progress(st, true);
	st.bgd_in_progress_set = true;
	proxy_info("AWS RDS BGD [wHG=%u rHG=%u]: switchover in progress, suspending read_only monitor checks on writer/reader hostgroups until SWITCHOVER_COMPLETED\n",
		st.writer_hg, st.reader_hg);
}

/**
* @brief Clear the switchover-in-progress flag from the aws_rds_bgd_server_status map
*/
static void aws_rds_bgd_clear_bgd_in_progress(AWS_RDS_BGD_State& st) {
	if (!st.bgd_in_progress_set) {
		return;
	}

	GloMyMon->set_aws_rds_bgd_server_in_progress(st, false);
	st.bgd_in_progress_set = false;
	proxy_info("AWS RDS BGD [wHG=%u rHG=%u]: switchover completed, resuming read_only monitor checks on writer/reader hostgroups\n",
		st.writer_hg, st.reader_hg);
}

/**
* @brief Set the deployment's switchover status and persist it in runtime table.
*/
static void aws_rds_bgd_set_status(AWS_RDS_BGD_State& st, AWS_RDS_BGD_Status status) {
	if (st.bgd_status == status) {
		return;
	}

	proxy_info("AWS RDS BGD [wHG=%u rHG=%u]: switchover status '%s' -> '%s'\n",
		st.writer_hg, st.reader_hg,
		aws_rds_bgd_status_str(st.bgd_status), aws_rds_bgd_status_str(status));

	st.bgd_status = status;
	MyHGM->aws_rds_bgd_set_runtime_status(st.writer_hg, static_cast<int>(status));

	if (status == AWS_RDS_BGD_Status::NONE) {
		aws_rds_bgd_clear_bgd_in_progress(st);
	}
}

/**
* @brief Load one BGD worker's configuration from the published host rows.
*
* @details Copies the cluster rows, verifies their checksum, copies configuration fields from
*   the first row, and builds the probe host list. FSM fields retain their defaults and must not
*   replace the corresponding fields in the live state.
*
* @param writer_hg        Writer hostgroup identifying the deployment.
* @param current_checksum Per-cluster checksum captured for this refresh.
* @param candidate        State populated from the published rows.
*
* @return true when the checksum matches and the rows contain a blue writer; false otherwise.
*/
bool MySQL_Monitor::aws_rds_bgd_load_worker_config(int writer_hg, uint64_t current_checksum, AWS_RDS_BGD_State& candidate) {
	SQLite3_result result(AWS_RDS_BGD_HOSTS_COLUMNS);
	std::shared_ptr<SQLite3_result> hosts_resultset;

	pthread_mutex_lock(&aws_rds_bgd_hosts_mutex);
	hosts_resultset = AWS_RDS_BGD_Hosts_resultset;
	pthread_mutex_unlock(&aws_rds_bgd_hosts_mutex);

	if (hosts_resultset) {
		for (SQLite3_row* row : hosts_resultset->rows) {
			if (atoi(row->fields[AWS_RDS_BGD_WRITER_HOSTGROUP]) == writer_hg) {
				result.add_row(row);
			}
		}
	}
	if (result.raw_checksum() != current_checksum) {
		return false;
	}

	candidate.writer_hg = writer_hg;
	bool first_row = true;

	for (SQLite3_row* row : result.rows) {
		unsigned int reader_hg = atoi(row->fields[AWS_RDS_BGD_READER_HOSTGROUP]);
		int green_writer_hg = row->fields[AWS_RDS_BGD_GREEN_WRITER_HOSTGROUP]
			&& row->fields[AWS_RDS_BGD_GREEN_WRITER_HOSTGROUP][0]
			? atoi(row->fields[AWS_RDS_BGD_GREEN_WRITER_HOSTGROUP]) : -1;
		int green_reader_hg = row->fields[AWS_RDS_BGD_GREEN_READER_HOSTGROUP]
			&& row->fields[AWS_RDS_BGD_GREEN_READER_HOSTGROUP][0]
			? atoi(row->fields[AWS_RDS_BGD_GREEN_READER_HOSTGROUP]) : -1;
		unsigned int check_interval_ms = atoi(row->fields[AWS_RDS_BGD_CHECK_INTERVAL_MS]);
		unsigned int check_timeout_ms = atoi(row->fields[AWS_RDS_BGD_CHECK_TIMEOUT_MS]);
		int writer_is_also_reader = atoi(row->fields[AWS_RDS_BGD_WRITER_IS_ALSO_READER]);

		if (first_row) {
			candidate.reader_hg = reader_hg;
			candidate.green_writer_hg = green_writer_hg;
			candidate.green_reader_hg = green_reader_hg;
			candidate.check_interval_ms = check_interval_ms;
			candidate.check_timeout_ms = check_timeout_ms;
			candidate.writer_is_also_reader = writer_is_also_reader;
			first_row = false;
		}

		char* srv_type = row->fields[AWS_RDS_BGD_SRV_TYPE];
		if (srv_type[0] == 'B' && atoi(row->fields[AWS_RDS_BGD_IS_WRITER]) != 0) {
			candidate.probe_hosts.push_back(AWS_RDS_BGD_Probe_Host {
				row->fields[AWS_RDS_BGD_HOSTNAME],
				atoi(row->fields[AWS_RDS_BGD_PORT]),
				atoi(row->fields[AWS_RDS_BGD_USE_SSL])
			});
		}
	}

	if (first_row || candidate.probe_hosts.empty()) {
		proxy_error("AWS RDS BGD [wHG=%d]: no blue writer available for topology checks\n", writer_hg);
		return false;
	}

	return true;
}

/**
* @brief Replace only configuration-derived fields in a live BGD worker state.
*
* @param st        Live worker state.
* @param candidate Parsed configuration to apply.
*/
void MySQL_Monitor::aws_rds_bgd_apply_cluster_config(AWS_RDS_BGD_State& st, AWS_RDS_BGD_State& candidate) {
	st.reader_hg = candidate.reader_hg;
	st.green_writer_hg = candidate.green_writer_hg;
	st.green_reader_hg = candidate.green_reader_hg;
	st.writer_is_also_reader = candidate.writer_is_also_reader;
	st.check_interval_ms = candidate.check_interval_ms;
	st.check_timeout_ms = candidate.check_timeout_ms;
	st.probe_hosts = candidate.probe_hosts;
}

/**
* @brief Run the monitor loop for one AWS RDS BGD writer hostgroup.
*
* @param arg Pointer to the worker state owned by the parent monitor thread.
*
* @return nullptr when the worker exits.
*/
void* monitor_RDS_BGD_thread_HG(void* arg) {
	AWS_RDS_BGD_Worker* worker = static_cast<AWS_RDS_BGD_Worker*>(arg);
	unsigned int wHG = worker->writer_hg;
	unsigned int cur_host_idx = 0;
	set_thread_name("MonitorRdsBgdHG", GloVars.set_thread_name);
	proxy_info("Started Monitor thread for AWS RDS writer HG %u\n", wHG);

	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth())
		return NULL;

	AWS_RDS_BGD_State st;
	st.writer_hg = wHG;

	MyHGM->aws_rds_bgd_set_runtime_status(wHG, static_cast<int>(AWS_RDS_BGD_Status::NONE));

	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime = monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version = GloMTH->get_global_version();
	mysql_thr->refresh_variables();

	unsigned long long t1 = 0;
	unsigned long long next_loop_at = 0;
	bool crc = false;
	uint64_t last_checksum = 0;
	size_t rnd;
	bool found_pingable_host = false;
	MySQL_Monitor_State_Data *mmsd = NULL;
	RDS_BGD_Topology_Monitor_State topology_state = TOPOLOGY_TABLE_CHECK;

	t1 = monotonic_time();

	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true
		&& worker->worker_stop.load()==false) {
		unsigned int glover;
		t1 = monotonic_time();
		bool poll_success = false;

		if (!GloMTH)
			goto __exit_monitor_RDS_BGD_thread_HG_now;

		// if variables changed, refresh and force a new check
		glover = GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version = glover;
			mysql_thr->refresh_variables();
			next_loop_at = 0;
		}

		uint64_t current_checksum = worker->current_checksum.load();
		if (current_checksum != last_checksum) {
			if (!GloMyMon->aws_rds_bgd_refresh_worker_config(st, current_checksum, topology_state, next_loop_at)) {
				usleep(50000);
				continue;
			}
			last_checksum = current_checksum;
			if (cur_host_idx >= st.probe_hosts.size()) {
				cur_host_idx = 0;
			}
		}

		if (st.probe_hosts.empty()) {
			next_loop_at = t1 + (st.check_interval_ms ? st.check_interval_ms : 1000) * 1000;
			usleep(50000);
			continue;
		}

		if (t1 < next_loop_at) {
			unsigned long long st = next_loop_at - t1;
			if (st > 50000) {
				st = 50000;
			}
			usleep(st);
			continue;
		}

		// Determine the host to probe. If the FSM pinned a host (the green IP, during a
		// switchover), poll it directly and skip ping/random selection; otherwise pick a
		// pingable host, starting at a random position.
		const char* poll_host;
		int poll_port;
		bool poll_use_ssl;
		if (!st.next_check_host.empty()) {
			bool found_writer = false;
			for (const auto& p : st.bg_map) {
				if (p.is_writer) {
					poll_host = st.next_check_host.c_str();
					poll_port = p.port;
					poll_use_ssl = (p.green_use_ssl >= 0) ? p.green_use_ssl : p.blue_use_ssl;
					found_writer = true;
					break;
				}
			}
			if (!found_writer) {
				// Highly unlikely: next_check_host is set but bg_map has no writer pair.
				// Clear the green pin and fall through to blue host selection.
				st.next_check_host.clear();
				st.next_check_host_failures = 0;
			}
		}

		if (st.next_check_host.empty()) {
			found_pingable_host = false;
			rnd = (size_t) rand();
			rnd %= st.probe_hosts.size();
			for (size_t i = 0; found_pingable_host == false && i < st.probe_hosts.size(); i++) {
				size_t host_idx = (rnd + i) % st.probe_hosts.size();
				AWS_RDS_BGD_Probe_Host& host = st.probe_hosts[host_idx];
				if (GloMyMon->server_responds_to_ping(host.hostname.data(), host.port)) {
					found_pingable_host = true;
					cur_host_idx = host_idx;
				} else {
					MyHGM->p_update_mysql_error_counter(
						p_mysql_error_type::proxysql, wHG, host.hostname.data(), host.port,
						ER_PROXYSQL_AWS_NO_PINGABLE_SRV
					);
				}
			}
			if (found_pingable_host == false) {
				proxy_error("No node is pingable for AWS RDS cluster with writer HG %u\n", wHG);
				next_loop_at = t1 + st.check_interval_ms * 1000;
				continue;
			}
			poll_host = st.probe_hosts[cur_host_idx].hostname.c_str();
			poll_port = st.probe_hosts[cur_host_idx].port;
			poll_use_ssl = st.probe_hosts[cur_host_idx].use_ssl;
		}

		mmsd = new MySQL_Monitor_State_Data(
			MON_AWS_RDS_BGD, (char*)poll_host, poll_port, poll_use_ssl
		);
		mmsd->writer_hostgroup = wHG;
		mmsd->aws_aurora_check_timeout_ms = st.check_timeout_ms;
		mmsd->mysql = GloMyMon->My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port, mmsd);
		mmsd->t1 = t1;

		crc = false;
		if (mmsd->mysql == NULL) { // need a new connection
			bool rc = mmsd->create_new_connection();
			if (mmsd->mysql) {
				GloMyMon->My_Conn_Pool->conn_register(mmsd);
			}
			crc = true;
			if (rc == false) {
				proxy_error("Error on AWS RDS check for %s:%d. Unable to create a connection.\n", mmsd->hostname, mmsd->port);
				MyHGM->p_update_mysql_error_counter(
					p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port,
					ER_PROXYSQL_AWS_HEALTH_CHECK_CONN_TIMEOUT
				);
				goto __end_of_loop;
			}
		}

		if (topology_state == TOPOLOGY_TABLE_CHECK) {
			// State TOPOLOGY_TABLE_CHECK: confirm mysql.rds_topology exists. Once seen
			// we advance to TOPOLOGY_METADATA_FETCH and skip this check on subsequent
			// iterations, until a fetch reports the table is gone.

			int qrc = GloMyMon->aws_rds_bgd_async_query(mmsd, QUERY_AWS_RDS_TOPOLOGY_TABLE_CHECK, worker->worker_stop);
			if (qrc == 2) {
				goto __exit_monitor_RDS_BGD_thread_HG_now;
			}
			if (qrc != 0) {
				proxy_error(
					"AWS RDS topology availability check failed for %s:%d : %s\n",
					mmsd->hostname, mmsd->port, mmsd->mysql_error_msg ? mmsd->mysql_error_msg : "unknown"
				);
				goto __end_of_loop;
			}
			bool table_available = (mmsd->result && mysql_num_rows(mmsd->result) > 0);
			if (mmsd->result) {
				mysql_free_result(mmsd->result);
				mmsd->result = NULL;
			}
			if (!table_available) {
				// no blue/green deployment or multi-az cluster discovery in progress, or the
				// post-switchover topology has fully drained; run any pending deferred cleanup.
				GloMyMon->aws_rds_bgd_handle_topology_absent(st);
				proxy_debug(PROXY_DEBUG_MONITOR, 5,
					"mysql.rds_topology not present on %s:%d (RDS writer HG %u); skipping\n",
					mmsd->hostname, mmsd->port, wHG);
				goto __end_of_loop;
			}
			topology_state = TOPOLOGY_METADATA_FETCH;
		} else if (topology_state == TOPOLOGY_METADATA_FETCH) {
			// State TOPOLOGY_METADATA_FETCH: fetch topology metadata. The column set
			// differs by RDS type (the Multi-AZ Cluster topology table may not expose
			// 'role'/'status' at all), so dump all columns and detect what is present.

			int qrc = GloMyMon->aws_rds_bgd_async_query(mmsd, QUERY_AWS_RDS_TOPOLOGY_DISCOVERY, worker->worker_stop);
			if (qrc == 2) {
				goto __exit_monitor_RDS_BGD_thread_HG_now;
			}
			if (qrc != 0) {
				unsigned int err = mmsd->mysql ? mysql_errno(mmsd->mysql) : 0;
				if (err == 1146) {
					// the table vanished (ER_NO_SUCH_TABLE), e.g. a blue/green deployment
					// was cancelled or a post-switchover topology fully drained: re-check its
					// existence on the next iteration and return to the baseline poll interval.
					topology_state = TOPOLOGY_TABLE_CHECK;
					st.next_check_interval_ms = 0;
					GloMyMon->aws_rds_bgd_handle_topology_absent(st);
					proxy_debug(PROXY_DEBUG_MONITOR, 5,
						"mysql.rds_topology vanished on %s:%d (RDS writer HG %u); rechecking availability\n",
						mmsd->hostname, mmsd->port, wHG);
				} else {
					proxy_error(
						"AWS RDS topology fetch failed for %s:%d : %s\n",
						mmsd->hostname, mmsd->port, mmsd->mysql_error_msg ? mmsd->mysql_error_msg : "unknown"
					);
				}
				goto __end_of_loop;
			}

			// the BGD thread only monitors blue/green hostgroups; parse the topology
			// (shared with the read_only path) and hand the struct to the handler.
			if (mmsd->result && mysql_num_rows(mmsd->result) > 0) {
				poll_success = true;
				AWS_RDS_Topology_Result topo = GloMyMon->parse_aws_rds_topology(mmsd->result);
				proxy_debug(PROXY_DEBUG_MONITOR, 5,
					"AWS RDS BGD [wHG=%u]: topology probe on %s:%d (blue_green=%d, nodes=%zu)\n",
					wHG, mmsd->hostname, mmsd->port, topo.blue_green ? 1 : 0, topo.nodes.size());
				GloMyMon->handle_aws_rds_bgd(st, topo);
			} else {
				poll_success = true;
				// Query succeeded with no rows: mysql.rds_topology has drained (blue-reader
				// DNS fully propagated). Run post-switchover cleanup.
				GloMyMon->aws_rds_bgd_handle_topology_absent(st);
			}

			if (mmsd->result) {
				mysql_free_result(mmsd->result);
				mmsd->result = NULL;
			}
		}

__end_of_loop:
		if (!st.next_check_host.empty()) {
			if (poll_success) {
				st.next_check_host_failures = 0;
			} else {
				st.next_check_host_failures++;
				if (st.next_check_host_failures >= 3) {
					proxy_warning("AWS RDS BGD [wHG=%u rHG=%u]: green probe host %s unreachable after %u attempts, falling back to blue and clearing DNS pins\n",
						wHG, st.reader_hg, st.next_check_host.c_str(), st.next_check_host_failures);
					st.next_check_host.clear();
					st.next_check_host_failures = 0;
					for (const auto& p : st.bg_map) {
						GloMyMon->dns_cache->remove(p.blue_host);
						GloMyMon->My_Conn_Pool->purge_connections(p.blue_host.c_str(), p.port);
					}
				}
			}
		}

		mmsd->t2 = monotonic_time();
		// the FSM tightens the interval to 100ms while a switchover is in flight
		// (st.next_check_interval_ms); otherwise fall back to the configured baseline.
		unsigned int eff = st.next_check_interval_ms ? st.next_check_interval_ms : st.check_interval_ms;
		next_loop_at = t1 + (eff * 1000);
		if (mmsd->t2 > t1) {
			next_loop_at -= (mmsd->t2 - t1);
		}
		if (mmsd->mysql) {
			if (mmsd->mysql_error_msg) {
				GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
			} else if (crc) {
				if (mmsd->set_wait_timeout()) {
					GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
				} else {
					GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
				}
			} else {
				GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
			}
		}
		delete mmsd;
		mmsd = NULL;
	}

__exit_monitor_RDS_BGD_thread_HG_now:
	if (st.bgd_status != AWS_RDS_BGD_Status::NONE) {
		GloMyMon->handle_aws_rds_bgd_post_switchover(st, true);
	}

	if (mmsd) {
		if (mmsd->mysql) {
			GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
		}
		delete mmsd;
		mmsd = NULL;
	}

	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr = NULL;
	}

	proxy_info("Stopping Monitor thread for AWS RDS writer HG %u\n", wHG);
	return NULL;
}

// Split "<host>.<domain>" into the host (part before the first dot) and the remaining domain.
static void aws_rds_bgd_split_hostname(const std::string& hostname, std::string& host, std::string& domain) {
	size_t dot = hostname.find('.');
	if (dot == std::string::npos) {
		host = hostname;
		domain.clear();
		return;
	}
	host = hostname.substr(0, dot);
	domain = hostname.substr(dot + 1);
}

// Given a green host "<blue_host>-green-<random>", return "<blue_host>";
// returns empty when the "-green-" suffix is absent.
static std::string aws_rds_bgd_strip_green_host_suffix(const std::string& green_host) {
	size_t pos = green_host.find("-green-");
	if (pos == std::string::npos) {
		return "";
	}
	return green_host.substr(0, pos);
}

// True when the green hostname is the blue/green TARGET counterpart of the blue hostname, i.e.
// green "<blue_host>-green-<rand>.<domain>" maps to blue "<blue_host>.<domain>".
static bool aws_rds_bgd_match_host(const std::string& blue_hostname, const std::string& green_hostname) {
	std::string b_host, b_domain, g_host, g_domain;
	aws_rds_bgd_split_hostname(blue_hostname, b_host, b_domain);
	aws_rds_bgd_split_hostname(green_hostname, g_host, g_domain);
	std::string g_host_stripped = aws_rds_bgd_strip_green_host_suffix(g_host);
	if (g_host_stripped.empty()) {
		return false;
	}
	return g_host_stripped == b_host && g_domain == b_domain;
}

/**
* @brief Build the blue-to-green host mapping for a BGD worker.
*
* @details Builds the map only when it is empty. The topology exposes only primaries, so the
*   writer pair is always present; reader pairs are added when green_reader_hostgroup is configured.
*
* @param st   Worker-owned BGD state.
* @param topo Parsed topology used to identify the green target.
*/
void MySQL_Monitor::aws_rds_bgd_build_map(AWS_RDS_BGD_State& st, AWS_RDS_Topology_Result& topo) {
	if (!st.bg_map.empty()) {
		return;
	}

	AWS_RDS_Topology_Node* target = topo.target();
	if (!target || target->endpoint.empty()) {
		return;
	}

	std::string green_writer_host = target->endpoint;

	MyHGM->wrlock();

	// blue writer: the writer_hostgroup member whose name matches the green TARGET.
	MyHGC* whgc = MyHGM->MyHGC_find(st.writer_hg);
	if (whgc && whgc->mysrvs) {
		for (unsigned int j = 0; j < whgc->mysrvs->cnt(); j++) {
			MySrvC* s = whgc->mysrvs->idx(j);
			if (s->get_status() == MYSQL_SERVER_STATUS_OFFLINE_HARD
				|| s->get_status() == MYSQL_SERVER_STATUS_OFFLINE_SOFT) {
				continue;
			}
			if (aws_rds_bgd_match_host(s->address, green_writer_host)) {
				AWS_RDS_BlueGreenPair p;
				p.blue_host = s->address;
				p.port = s->port;
				p.green_host = green_writer_host;
				p.blue_weight = s->weight;
				p.blue_max_conns = s->max_connections;
				p.blue_use_ssl = s->use_ssl;
				p.is_writer = true;

				// read the green writer's use_ssl config
				if (st.green_writer_hg >= 0) {
					MyHGC* gwhgc = MyHGM->MyHGC_find((unsigned int)st.green_writer_hg);
					if (gwhgc && gwhgc->mysrvs) {
						for (unsigned int k = 0; k < gwhgc->mysrvs->cnt(); k++) {
							MySrvC* gs = gwhgc->mysrvs->idx(k);
							if (strcasecmp(gs->address, green_writer_host.c_str()) != 0 || gs->port != p.port) {
								continue;
							}

							p.green_offline =
								gs->get_status() == MYSQL_SERVER_STATUS_OFFLINE_HARD
								|| gs->get_status() == MYSQL_SERVER_STATUS_OFFLINE_SOFT;
							if (!p.green_offline) {
								p.green_use_ssl = gs->use_ssl;
							}
							break;
						}
					}
				}

				proxy_debug(PROXY_DEBUG_MONITOR, 7,
					"AWS RDS BGD [wHG=%u]: mapped blue writer '%s:%d' <-> green '%s'\n",
					st.writer_hg, p.blue_host.c_str(), p.port, p.green_host.c_str());
				st.bg_map.push_back(std::move(p));
				break;
			}
		}
	}

	// reader pairs: match blue readers to user-added green readers by name.
	if (st.green_reader_hg >= 0) {
		std::vector<std::string> green_reader_hosts;
		MyHGC* grhgc = MyHGM->MyHGC_find((unsigned int)st.green_reader_hg);
		if (grhgc && grhgc->mysrvs) {
			for (unsigned int j = 0; j < grhgc->mysrvs->cnt(); j++) {
				MySrvC* s = grhgc->mysrvs->idx(j);
				if (s->get_status() == MYSQL_SERVER_STATUS_OFFLINE_HARD
					|| s->get_status() == MYSQL_SERVER_STATUS_OFFLINE_SOFT) {
					continue;
				}
				green_reader_hosts.push_back(s->address);
			}
		}

		MyHGC* rhgc = MyHGM->MyHGC_find(st.reader_hg);
		if (rhgc && rhgc->mysrvs) {
			for (unsigned int j = 0; j < rhgc->mysrvs->cnt(); j++) {
				MySrvC* s = rhgc->mysrvs->idx(j);
				if (s->get_status() == MYSQL_SERVER_STATUS_OFFLINE_HARD
					|| s->get_status() == MYSQL_SERVER_STATUS_OFFLINE_SOFT) {
					continue;
				}
				for (const std::string& green_reader_host : green_reader_hosts) {
					if (aws_rds_bgd_match_host(s->address, green_reader_host)) {
						AWS_RDS_BlueGreenPair p;
						p.blue_host = s->address;
						p.port = s->port;
						p.green_host = green_reader_host;
						p.blue_weight = s->weight;
						p.blue_max_conns = s->max_connections;
						p.blue_use_ssl = s->use_ssl;
						p.is_writer = false;
						proxy_debug(PROXY_DEBUG_MONITOR, 7,
							"AWS RDS BGD [wHG=%u]: mapped blue reader '%s:%d' <-> green '%s'\n",
							st.writer_hg, p.blue_host.c_str(), p.port, p.green_host.c_str());
						st.bg_map.push_back(std::move(p));
						break;
					}
				}
			}
		}
	}

	MyHGM->wrunlock();
}

/**
* @brief Resolve the green IPs and pin the worker's probe to the green writer's IP.
*
* @details Resolves each pair's green host (DNS_Cache first, then a live lookup tracking TTL),
*   then sets 'st.next_check_host' to the green writer's IP. From then on the worker polls the
*   green primary BY IP: green stays reachable through the entire cutover (blue has a connectivity
*   gap), and the green IP survives the post-COMPLETED name swap (it becomes the promoted primary),
*   whereas the green DNS name is retired. 'next_check_host' is cleared at COMPLETED.
*
* @param st Worker-owned BGD state.
*/
void MySQL_Monitor::aws_rds_bgd_resolve_green_ips(AWS_RDS_BGD_State& st) {
	int ai_family = mysql_resolution_family_to_ai_family(mysql_thread___resolution_family);
	for (auto &p : st.bg_map) {
		if (p.green_offline) {
			continue;
		}

		// Always check the cache first: a green host that is a monitored server may be there.
		size_t n = 0;
		std::string ip = MySQL_Monitor::dns_lookup(p.green_host, false, &n);
		if (!ip.empty()) {
			p.green_ip = ip;
			p.green_ip_ttl = 0;
			proxy_debug(PROXY_DEBUG_MONITOR, 7,
				"AWS RDS BGD [wHG=%u rHG=%u]: green '%s' IP %s (DNS_Cache)\n",
				st.writer_hg, st.reader_hg, p.green_host.c_str(), p.green_ip.c_str());
			continue;
		}
		// Cache miss (green is not a monitored server): resolve DNS now and track its TTL.
		if (p.green_ip.empty() || (p.green_ip_ttl != 0 && monotonic_time() > p.green_ip_ttl)) {
			std::vector<std::string> ips = dns_resolve(p.green_host, ai_family);
			if (!ips.empty()) {
				p.green_ip = ips.front();
				p.green_ip_ttl = monotonic_time()
					+ (1000ULL * (unsigned long long)mysql_thread___monitor_local_dns_cache_ttl);
				proxy_debug(PROXY_DEBUG_MONITOR, 7,
					"AWS RDS BGD [wHG=%u rHG=%u]: green '%s' IP %s (resolved, ttl=%lus)\n",
					st.writer_hg, st.reader_hg, p.green_host.c_str(), p.green_ip.c_str(),
					(unsigned long)mysql_thread___monitor_local_dns_cache_ttl);
			}
		}
	}

	// Pin the worker's next probe to the green writer's IP (observe the switchover from green).
	for (const AWS_RDS_BlueGreenPair& p : st.bg_map) {
		if (p.is_writer && !p.green_offline && !p.green_ip.empty()) {
			if (st.next_check_host != p.green_ip) {
				st.next_check_host = p.green_ip;
				proxy_info("AWS RDS BGD [wHG=%u rHG=%u]: pinning rds_topology probe to green IP %s\n",
					st.writer_hg, st.reader_hg, p.green_ip.c_str());
			}
			break;
		}
	}
}

/**
* @brief Add the green writer to green_writer_hostgroup, when that hostgroup is configured.
*
* @param st Worker-owned BGD state.
*/
void MySQL_Monitor::aws_rds_bgd_add_green_writer_in_hg(AWS_RDS_BGD_State& st) {
	if (st.green_writer_hg < 0) {
		return;
	}
	for (AWS_RDS_BlueGreenPair& p : st.bg_map) {
		if (!p.is_writer) {
			continue;
		}

		srv_info_t srv_info { p.green_host, (uint16_t)p.port, "AWS RDS BGD green writer" };
		srv_opts_t srv_opts { -1, -1, -1 };
		MyHGM->wrlock();
		int rc = MyHGM->create_new_server_in_hg((uint32_t)st.green_writer_hg, srv_info, srv_opts);
		if (rc == 0) {
			MySrvC* s = MyHGM->find_server_in_hg((unsigned int)st.green_writer_hg, p.green_host, p.port);
			if (s) {
				p.green_use_ssl = s->use_ssl;
				p.green_offline = false;
			}
			MyHGM->publish_mysql_servers_to_runtime();
		}
		MyHGM->wrunlock();
		break;
	}
}

/**
* @brief Find the writer pair in a blue/green map.
*
* @param bg_map Blue/green host mapping.
* @param writer Writer address populated when a pair is found.
*
* @return true when the map contains a writer pair; false otherwise.
*/
bool MySQL_Monitor::aws_rds_bgd_find_writer(std::vector<AWS_RDS_BlueGreenPair>& bg_map, srv_addr_t& writer) {
	for (AWS_RDS_BlueGreenPair& p : bg_map) {
		if (p.is_writer) {
			writer = srv_addr_t { p.blue_host, p.port };
			return true;
		}
	}
	return false;
}

/**
* @brief Apply a changed configuration to one running BGD worker.
*
* @details Before writer post-processing, applies the configuration and schedules mapping
*   reconciliation after the next topology poll. At or after post-processing, rolls back the
*   deployment and restarts its topology FSM without replacing the worker thread.
*
* @param st               Worker-owned BGD state.
* @param current_checksum Per-cluster checksum captured for this refresh.
* @param topology_state   Current topology query state.
* @param next_loop_at     Next scheduled worker iteration.
*
* @return true when the captured configuration was applied; false when it must be retried.
*/
bool MySQL_Monitor::aws_rds_bgd_refresh_worker_config(
	AWS_RDS_BGD_State& st, uint64_t current_checksum,
	RDS_BGD_Topology_Monitor_State& topology_state, unsigned long long& next_loop_at
) {
	AWS_RDS_BGD_State candidate;
	if (!aws_rds_bgd_load_worker_config(st.writer_hg, current_checksum, candidate)) {
		return false;
	}

	// Changes at or after writer post-processing require a full rollback and FSM restart.
	if (st.bgd_status >= AWS_RDS_BGD_Status::WRITER_SWITCHOVER_POST_PROCESSING) {
		AWS_RDS_BGD_Status old_status = st.bgd_status;
		handle_aws_rds_bgd_post_switchover(st, true);
		aws_rds_bgd_apply_cluster_config(st, candidate);
		topology_state = TOPOLOGY_TABLE_CHECK;
		next_loop_at = 0;
		proxy_info(
			"AWS RDS BGD [wHG=%u rHG=%u]: applied checksum %llu with full rollback from %s\n",
			st.writer_hg, st.reader_hg, (unsigned long long)current_checksum,
			aws_rds_bgd_status_str(old_status));
		return true;
	}

	AWS_RDS_BGD_Status status = st.bgd_status;
	unsigned int old_reader_hg = st.reader_hg;
	bool refresh_in_progress = st.bgd_in_progress_set;
	bool hostgroups_changed = old_reader_hg != candidate.reader_hg;

	// Clear the in-progress marker from the old reader hostgroup before applying the new configuration.
	if (refresh_in_progress && hostgroups_changed) {
		aws_rds_bgd_clear_bgd_in_progress(st);
	}

	// Apply the new configuration.
	aws_rds_bgd_apply_cluster_config(st, candidate);
	st.next_check_host.clear();
	st.next_check_host_failures = 0;
	next_loop_at = 0;
	// Rebuild bg_map from the next topology probe result.
	st.config_refresh_pending = true;

	// Apply the in-progress marker to the new reader hostgroup after the refresh.
	if (refresh_in_progress && hostgroups_changed) {
		aws_rds_bgd_set_bgd_in_progress(st);
	}

	proxy_info(
		"AWS RDS BGD [wHG=%u rHG=%u]: applied checksum %llu with in-place refresh at %s\n",
		st.writer_hg, st.reader_hg, (unsigned long long)current_checksum,
		aws_rds_bgd_status_str(status));
	return true;
}

/**
* @brief Rebuild the mapping and reconcile writer state after a configuration refresh.
*
* @details Called only when config_refresh_pending is set.
*
* @param st       Worker-owned BGD state.
* @param topology Fresh topology used to rebuild the mapping.
*/
void MySQL_Monitor::aws_rds_bgd_config_refresh_action(AWS_RDS_BGD_State& st, AWS_RDS_Topology_Result& topology) {
	srv_addr_t old_writer;
	bool had_old_writer = aws_rds_bgd_find_writer(st.bg_map, old_writer);
	st.bg_map.clear();
	aws_rds_bgd_build_map(st, topology);

	srv_addr_t new_writer;
	bool has_new_writer = aws_rds_bgd_find_writer(st.bg_map, new_writer);
	aws_rds_bgd_add_green_writer_in_hg(st);

	// Reapply the in-progress demotion after the configuration reload restores configured placement.
	if (st.bgd_status == AWS_RDS_BGD_Status::WRITER_SWITCHOVER_IN_PROGRESS) {
		bool writer_changed =
			had_old_writer != has_new_writer ||
			(had_old_writer && (old_writer.host != new_writer.host || old_writer.port != new_writer.port));
		if (writer_changed && had_old_writer) {
			MyHGM->read_only_action_v2(std::list<read_only_server_t> {
				read_only_server_t { old_writer.host, (port_t)old_writer.port, 0 }
			}, true);
		}
		if (has_new_writer) {
			MyHGM->read_only_action_v2(std::list<read_only_server_t> {
				read_only_server_t { new_writer.host, (port_t)new_writer.port, 1 }
			}, true);
		}
	}
}

// Map a raw mysql.rds_topology TARGET status string onto BGD phase enum.
static AWS_RDS_BGD_Status aws_rds_bgd_status_from_topology(const std::string& status) {
	if (strcasecmp(status.c_str(), BGD_STATUS_AVAILABLE) == 0) {
		return AWS_RDS_BGD_Status::AVAILABLE;
	} else if (strcasecmp(status.c_str(), BGD_STATUS_INITIATED) == 0) {
		return AWS_RDS_BGD_Status::WRITER_SWITCHOVER_INITIATED;
	} else if (strcasecmp(status.c_str(), BGD_STATUS_IN_PROGRESS) == 0) {
		return AWS_RDS_BGD_Status::WRITER_SWITCHOVER_IN_PROGRESS;
	} else if (strcasecmp(status.c_str(), BGD_STATUS_POST_PROC) == 0) {
		return AWS_RDS_BGD_Status::WRITER_SWITCHOVER_POST_PROCESSING;
	} else if (strcasecmp(status.c_str(), BGD_STATUS_COMPLETED) == 0) {
		return AWS_RDS_BGD_Status::WRITER_SWITCHOVER_COMPLETED;
	} else {
		return AWS_RDS_BGD_Status::NONE;
	}
}

// Human-readable name for a phase enum, for logging and (later) the runtime status column.
const char* aws_rds_bgd_status_str(AWS_RDS_BGD_Status s) {
	switch (s) {
		case AWS_RDS_BGD_Status::NONE:
			return "NONE";
		case AWS_RDS_BGD_Status::AVAILABLE:
			return "AVAILABLE";
		case AWS_RDS_BGD_Status::WRITER_SWITCHOVER_INITIATED:
			return "WRITER_SWITCHOVER_INITIATED";
		case AWS_RDS_BGD_Status::WRITER_SWITCHOVER_IN_PROGRESS:
			return "WRITER_SWITCHOVER_IN_PROGRESS";
		case AWS_RDS_BGD_Status::WRITER_SWITCHOVER_POST_PROCESSING:
			return "WRITER_SWITCHOVER_POST_PROCESSING";
		case AWS_RDS_BGD_Status::WRITER_SWITCHOVER_COMPLETED:
			return "WRITER_SWITCHOVER_COMPLETED";
		case AWS_RDS_BGD_Status::READER_SWITCHOVER_IN_PROGRESS:
			return "READER_SWITCHOVER_IN_PROGRESS";
		case AWS_RDS_BGD_Status::SWITCHOVER_COMPLETED:
			return "SWITCHOVER_COMPLETED";
	}
	return "UNKNOWN";
}

/**
* @brief Run the status-driven blue/green switchover FSM for one deployment.
*
* @details Invoked each poll cycle by the BGD worker after it fetches the
*   mysql.rds_topology result. Dispatches on the deployment's switchover status
*   (AVAILABLE -> SWITCHOVER_INITIATED -> IN_PROGRESS -> IN_POST_PROCESSING ->
*   COMPLETED): builds the blue<->green map, pre-resolves green IPs, repoints the
*   blue hostnames onto the green IPs in the DNS cache, drains blue free
*   connections, and shuns/enforces reader handling. State carried across cycles
*   lives in @p st.
*
* @param st        BGD switchover state (worker-owned, mutated here).
* @param topology  Parsed mysql.rds_topology result for this cycle.
*/
void MySQL_Monitor::handle_aws_rds_bgd(AWS_RDS_BGD_State& st, AWS_RDS_Topology_Result& topology) {
	if (!topology.blue_green) {
		st.next_check_interval_ms = 0;
		aws_rds_bgd_set_status(st, AWS_RDS_BGD_Status::NONE);
		return;
	}

	AWS_RDS_Topology_Node* target = topology.target();
	if (!target || target->status.empty()) {
		st.next_check_interval_ms = 0;
		aws_rds_bgd_set_status(st, AWS_RDS_BGD_Status::NONE);
		return;
	}

	AWS_RDS_BGD_Status topology_status = aws_rds_bgd_status_from_topology(target->status);

	// Once we advance to READER_SWITCHOVER_IN_PROGRESS phase, AWS keeps reporting
	// WRITER_SWITCHOVER_COMPLETED (a single green row) until mysql.rds_topology drains. Ignore
	// those repeats: the deferred cleanup fires from aws_rds_bgd_handle_topology_absent() when
	// the table empties/vanishes, not from a status change here.
	if (topology_status == AWS_RDS_BGD_Status::WRITER_SWITCHOVER_COMPLETED
		&& st.bgd_status == AWS_RDS_BGD_Status::READER_SWITCHOVER_IN_PROGRESS) {
		return;
	}

	// Detect backwards transition: the topology status moved to an earlier
	// phase than what we've already processed. This happens when a user
	// cancels the switchover from the AWS side, reverting to AVAILABLE,
	// or when AWS aborts the switchover due to an error. Roll back all
	// accumulated side effects, then re-enter the target state's setup.
	if (topology_status < st.bgd_status) {
		handle_aws_rds_bgd_post_switchover(st, true);
		if (topology_status == AWS_RDS_BGD_Status::AVAILABLE) {
			aws_rds_bgd_set_status(st, topology_status);
			st.next_check_interval_ms = 250;
			aws_rds_bgd_build_map(st, topology);
			aws_rds_bgd_resolve_green_ips(st);
			aws_rds_bgd_add_green_writer_in_hg(st);
		}
		return;
	}

	// Rebuild a refreshed worker's mapping only after receiving this current topology result.
	if (st.config_refresh_pending) {
		aws_rds_bgd_config_refresh_action(st, topology);
		st.config_refresh_pending = false;
	}

	if (topology_status == st.bgd_status) {
		// Refresh or retry green IP resolution on every eligible same-phase observation.
		if (topology_status >= AWS_RDS_BGD_Status::AVAILABLE
			&& topology_status <= AWS_RDS_BGD_Status::WRITER_SWITCHOVER_POST_PROCESSING) {
			aws_rds_bgd_resolve_green_ips(st);
		}

		// Retry pinning pairs whose green IP became available while remaining in POST_PROCESSING.
		if (topology_status == AWS_RDS_BGD_Status::WRITER_SWITCHOVER_POST_PROCESSING) {
			aws_rds_bgd_pin_green_ips(st);
		}
		return;
	}

	aws_rds_bgd_set_status(st, topology_status);

	if (st.bgd_status == AWS_RDS_BGD_Status::AVAILABLE) {
		st.next_check_interval_ms = 250;

		aws_rds_bgd_build_map(st, topology);
		aws_rds_bgd_resolve_green_ips(st);
		aws_rds_bgd_add_green_writer_in_hg(st);
	}
	else if (st.bgd_status == AWS_RDS_BGD_Status::WRITER_SWITCHOVER_INITIATED
		|| st.bgd_status == AWS_RDS_BGD_Status::WRITER_SWITCHOVER_IN_PROGRESS) {
		st.next_check_interval_ms = 100;

		aws_rds_bgd_build_map(st, topology);
		aws_rds_bgd_resolve_green_ips(st);
		aws_rds_bgd_add_green_writer_in_hg(st);
		aws_rds_bgd_set_bgd_in_progress(st);

		if (st.bgd_status == AWS_RDS_BGD_Status::WRITER_SWITCHOVER_IN_PROGRESS) {
			// Demote the blue writer (RO=1)
			for (const AWS_RDS_BlueGreenPair& p : st.bg_map) {
				if (p.is_writer) {
					auto srv = read_only_server_t{ p.blue_host, (port_t)p.port, 1 };
					MyHGM->read_only_action_v2(std::list<read_only_server_t>{srv}, true);
					break;
				}
			}
		}
	}
	else if (st.bgd_status == AWS_RDS_BGD_Status::WRITER_SWITCHOVER_POST_PROCESSING) {
		st.next_check_interval_ms = 100;

		// Run setup here too: the thread may observe POST_PROCESSING directly, without having
		// seen AVAILABLE/INITIATED first. All three are idempotent, so the repoint/shun logic
		// below always runs against a built map, resolved green IPs, and an added green writer.
		aws_rds_bgd_build_map(st, topology);
		aws_rds_bgd_resolve_green_ips(st);
		aws_rds_bgd_add_green_writer_in_hg(st);
		aws_rds_bgd_set_bgd_in_progress(st);

		// Repoint each mapped blue host onto its green IP and drain existing
		// connections so new backend work resolves to green.
		aws_rds_bgd_pin_green_ips(st);

		// Blue readers without a green counterpart must stop serving reads.

		srv_addr_t writer;
		for (const AWS_RDS_BlueGreenPair& p : st.bg_map) {
			if (p.is_writer) {
				writer = srv_addr_t{ p.blue_host, p.port };
				break;
			}
		}

		std::vector<srv_addr_t> blue_readers;
		MyHGM->wrlock();
		MyHGC* rhgc = MyHGM->MyHGC_lookup(st.reader_hg);
		if (rhgc && rhgc->mysrvs) {
			for (unsigned int j = 0; j < rhgc->mysrvs->cnt(); j++) {
				MySrvC* s = rhgc->mysrvs->idx(j);
				if (s->get_status() == MYSQL_SERVER_STATUS_OFFLINE_SOFT
					|| s->get_status() == MYSQL_SERVER_STATUS_OFFLINE_HARD) {
					continue;
				}
				if (writer.host == s->address && writer.port == s->port) {
					continue;
				}
				blue_readers.push_back(srv_addr_t{ std::string(s->address), s->port });
			}
		}
		MyHGM->wrunlock();

		std::vector<srv_addr_t> unmapped_readers;
		for (const srv_addr_t& br : blue_readers) {
			bool mapped = false;
			for (const AWS_RDS_BlueGreenPair& p : st.bg_map) {
				if (p.blue_host == br.host && p.port == br.port) {
					mapped = true;
					break;
				}
			}
			if (!mapped) {
				unmapped_readers.push_back(br);
			}
		}

		bool writer_is_also_reader = (st.writer_is_also_reader != 0);
		if (!unmapped_readers.empty() && unmapped_readers.size() == blue_readers.size()) {
			// All blue readers would be transitioned to SHUNNED_AWS_BGD, leaving the reader HG empty.
			// Temporarily enforce writer_is_also_reader until the reader switchover completes.
			writer_is_also_reader = true;
		}

		aws_rds_bgd_hostgroup_action(st.bgd_status, writer, writer_is_also_reader, st.reader_hg, unmapped_readers);

		st.shunned_readers.insert(st.shunned_readers.end(), unmapped_readers.begin(), unmapped_readers.end());
	}
	else if (st.bgd_status == AWS_RDS_BGD_Status::WRITER_SWITCHOVER_COMPLETED) {
		// Writer switchover done, but the topology table lingers with a single green row until the blue
		// readers' DNS propagates and it drains. Defer reader teardown: advance to READER_SWITCHOVER phase
		// and let the drain (aws_rds_bgd_handle_topology_absent) trigger it.
		aws_rds_bgd_set_status(st, AWS_RDS_BGD_Status::READER_SWITCHOVER_IN_PROGRESS);

		// Drop the writer's DNS_Cache entry: this clears the IP pin and lets regular DNS
		// resolution take over from here. Readers stay pinned until their DNS propagates.
		for (const AWS_RDS_BlueGreenPair& p : st.bg_map) {
			if (p.is_writer) {
				dns_cache->remove(p.blue_host);
				break;
			}
		}

		// release BGD monitor worker from fast-polling
		st.next_check_interval_ms = 0;
	}
	else {
		// unrecognized status: take no action, stay at baseline interval
		st.next_check_interval_ms = 0;
	}
}

/**
* @brief Pin green IPs and drain existing blue-host connections.
*
* @param st BGD switchover state.
*/
void MySQL_Monitor::aws_rds_bgd_pin_green_ips(AWS_RDS_BGD_State& st) {
	for (AWS_RDS_BlueGreenPair& pair : st.bg_map) {
		if (pair.green_ip_pinned) {
			continue;
		}

		if (pair.green_ip.empty()) {
			proxy_debug(PROXY_DEBUG_MONITOR, 7,
				"AWS RDS BGD [wHG=%u rHG=%u]: green host '%s' remains unresolved; "
				"deferring pin/drain for blue '%s:%d'\n",
				st.writer_hg, st.reader_hg, pair.green_host.c_str(), pair.blue_host.c_str(), pair.port);
			continue;
		}

		dns_cache->pin(pair.blue_host, pair.green_ip);
		MyHGM->wrlock();
		MyHGM->drain_server_connections(pair.blue_host.c_str(), pair.port);
		MyHGM->wrunlock();
		My_Conn_Pool->purge_connections(pair.blue_host.c_str(), pair.port);
		pair.green_ip_pinned = true;

		proxy_info(
			"AWS RDS BGD [wHG=%u rHG=%u]: repointed blue '%s' to green IP %s\n",
			st.writer_hg, st.reader_hg, pair.blue_host.c_str(), pair.green_ip.c_str());
	}
}

/**
* @brief Apply BGD hostgroup changes for the current switchover status.
*
* @details POST_PROCESSING configures the writer placement and shuns unmapped readers.
*   SWITCHOVER_COMPLETED unshuns readers and removes the writer from reader HG when
*   writer_is_also_reader is false. Runtime mysql_servers and checksum are re-generated
*   when server hostgroup membership changes.
*
* @param bgd_status Current BGD FSM status driving the action.
* @param writer Writer server to configure.
* @param writer_is_also_reader Whether the writer should also remain in reader_hg.
* @param reader_hg Reader hostgroup for reader shun/unshun and optional writer membership.
* @param readers Reader servers to shun or unshun.
*/
void MySQL_Monitor::aws_rds_bgd_hostgroup_action(
	AWS_RDS_BGD_Status bgd_status,
	srv_addr_t& writer, bool writer_is_also_reader,
	unsigned int reader_hg, std::vector<srv_addr_t>& readers)
{
	bool changed = false;
	bool shun_readers = false;

	MyHGM->wrlock();

	if (bgd_status == AWS_RDS_BGD_Status::WRITER_SWITCHOVER_POST_PROCESSING) {
		changed |= MyHGM->aws_rds_bgd_configure_writer(writer.host.c_str(), writer.port, writer_is_also_reader);
		shun_readers = true;
	} else if (bgd_status == AWS_RDS_BGD_Status::SWITCHOVER_COMPLETED) {
		changed |= MyHGM->aws_rds_bgd_configure_writer(writer.host.c_str(), writer.port, writer_is_also_reader);
	} else {
		MyHGM->wrunlock();
		return;
	}

	for (srv_addr_t& s : readers) {
		MyHGM->aws_rds_bgd_set_shun_server(reader_hg, s.host.c_str(), s.port, shun_readers);
	}

	if (changed) {
		MyHGM->publish_mysql_servers_to_runtime();
	}

	MyHGM->wrunlock();
}

/**
* @brief Run deferred switchover teardown or rollback cleanup.
*
* @details Restores post-switchover reader handling, unshuns readers, drops DNS pins,
*   and clears BGD switchover state. Normal post-switchover cleanup also drains
*   connections from green hosts; rollback leaves green rows and connections unchanged.
*
*   When rollback is false (normal post-switchover), the caller must be in
*   READER_SWITCHOVER_IN_PROGRESS; the function advances through
*   SWITCHOVER_COMPLETED before clearing to NONE.
*
*   When rollback is true (topology disappeared or worker exit mid-switchover),
*   the function accepts any non-NONE bgd_status, restores the blue writer to the
*   writer hostgroup if it was demoted, then resets switchover state.
*
* @param st       BGD switchover state.
* @param rollback True if called due to a rollback/cancellation, false for normal completion.
*/
void MySQL_Monitor::handle_aws_rds_bgd_post_switchover(AWS_RDS_BGD_State& st, bool rollback) {
	if (st.bgd_status == AWS_RDS_BGD_Status::NONE) {
		return;
	}

	if (!rollback && st.bgd_status != AWS_RDS_BGD_Status::READER_SWITCHOVER_IN_PROGRESS) {
		return;
	}

	if (rollback) {
		proxy_info("AWS RDS BGD [wHG=%u rHG=%u]: rolling back from %s\n",
			st.writer_hg, st.reader_hg, aws_rds_bgd_status_str(st.bgd_status));

		// Restore the blue writer to the writer hostgroup.
		// If writer exists in writer hostgroup, this is a no-op.
		if (st.bgd_status == AWS_RDS_BGD_Status::WRITER_SWITCHOVER_IN_PROGRESS
			|| st.bgd_status == AWS_RDS_BGD_Status::WRITER_SWITCHOVER_POST_PROCESSING) {
			for (const AWS_RDS_BlueGreenPair& p : st.bg_map) {
				if (p.is_writer) {
					auto srv = read_only_server_t{ p.blue_host, (port_t)p.port, 0 };
					MyHGM->read_only_action_v2(std::list<read_only_server_t>{srv}, true);
					break;
				}
			}
		}
	} else {
		aws_rds_bgd_set_status(st, AWS_RDS_BGD_Status::SWITCHOVER_COMPLETED);
		proxy_info("AWS RDS BGD [wHG=%u rHG=%u]: running post-switchover cleanup\n", st.writer_hg, st.reader_hg);
	}

	// Restore the writer's original reader role based on writer_is_also_reader config and
	// unshun the previously shunned blue readers.
	srv_addr_t writer;
	for (const AWS_RDS_BlueGreenPair& p : st.bg_map) {
		if (p.is_writer) {
			writer = srv_addr_t{ p.blue_host, p.port };
			break;
		}
	}
	bool writer_is_also_reader = (st.writer_is_also_reader != 0);
	aws_rds_bgd_hostgroup_action(AWS_RDS_BGD_Status::SWITCHOVER_COMPLETED, writer, writer_is_also_reader, st.reader_hg, st.shunned_readers);

	// Drop DNS cache + purge connections for the previously shunned readers
	// so their blue names re-resolve to the promoted (green) instances.
	if (!st.shunned_readers.empty()) {
		for (const srv_addr_t& br : st.shunned_readers) {
			dns_cache->remove(br.host);
			My_Conn_Pool->purge_connections(br.host.c_str(), br.port);
		}
		st.shunned_readers.clear();
	}

	// Drop DNS pins for all mapped pairs
	for (const AWS_RDS_BlueGreenPair& p : st.bg_map) {
		dns_cache->remove(p.blue_host);
		My_Conn_Pool->purge_connections(p.blue_host.c_str(), p.port);
		if (!p.green_ip.empty()) {
			My_Conn_Pool->purge_connections(p.green_ip.c_str(), p.port);
		}
	}

	if (!rollback) {
		aws_rds_bgd_drain_green_hg(st);
	}

	// state cleanup
	st.bg_map.clear();
	st.config_refresh_pending = false;
	st.next_check_host.clear();
	st.next_check_interval_ms = 0;
	aws_rds_bgd_set_status(st, AWS_RDS_BGD_Status::NONE);

	proxy_info(
		"AWS RDS BGD [wHG=%u rHG=%u]: switchover cleanup complete; state cleared\n",
		st.writer_hg, st.reader_hg);
}

/**
* @brief Drain connections from green hosts after switchover.
*
* @details Drains connections from every green host that is neither OFFLINE_SOFT nor
*   OFFLINE_HARD. Server rows and statuses are left unchanged.
*
* @param st Switchover state.
*/
void MySQL_Monitor::aws_rds_bgd_drain_green_hg(AWS_RDS_BGD_State& st) {
	struct hg_srv_t {
		int hostgroup;
		srv_addr_t server;
	};
	std::vector<hg_srv_t> targets;

	MyHGM->wrlock();

	for (int hg : { st.green_writer_hg, st.green_reader_hg }) {
		if (hg < 0) {
			continue;
		}
		MyHGC* hgc = MyHGM->MyHGC_find(hg);
		if (!hgc || !hgc->mysrvs) {
			continue;
		}
		for (unsigned int j = 0; j < hgc->mysrvs->cnt(); j++) {
			MySrvC* s = hgc->mysrvs->idx(j);
			if (s->get_status() == MYSQL_SERVER_STATUS_OFFLINE_SOFT
				|| s->get_status() == MYSQL_SERVER_STATUS_OFFLINE_HARD) {
				continue;
			}

			targets.push_back(hg_srv_t{
				hg, srv_addr_t{ std::string(s->address), s->port } });
		}
	}

	for (const hg_srv_t& target : targets) {
		MyHGM->drain_server_connections(
			target.server.host.c_str(), target.server.port);
	}

	MyHGM->wrunlock();

	for (const hg_srv_t& target : targets) {
		dns_cache->remove(target.server.host);
		My_Conn_Pool->purge_connections(
			target.server.host.c_str(), target.server.port);

		proxy_info(
			"AWS RDS BGD [wHG=%u rHG=%u]: connections drained from green HG %d server '%s:%d'\n",
			st.writer_hg, st.reader_hg, target.hostgroup, target.server.host.c_str(),
			target.server.port);
	}
}

/**
* @brief Handle an absent, empty, or vanished mysql.rds_topology table.
*
* @details Routes to deferred cleanup when bgd_status is READER_SWITCHOVER_IN_PROGRESS;
*   for any other non-NONE state, runs rollback cleanup to reverse accumulated side
*   effects before resetting to NONE.
*
* @param st BGD switchover state.
*/
void MySQL_Monitor::aws_rds_bgd_handle_topology_absent(AWS_RDS_BGD_State& st) {
	if (st.bgd_status == AWS_RDS_BGD_Status::READER_SWITCHOVER_IN_PROGRESS) {
		handle_aws_rds_bgd_post_switchover(st);
	} else if (st.bgd_status != AWS_RDS_BGD_Status::NONE) {
		handle_aws_rds_bgd_post_switchover(st, true);
	}
}


/**
* @brief Check whether a server is flagged as BGD switchover-in-progress.
*
* @param hostname Server hostname.
* @param port     Server port.
*
* @return true if the server is flagged IN_PROGRESS.
*/
bool MySQL_Monitor::is_aws_rds_bgd_server_in_progress(const std::string& hostname, int port) {
	std::string key = hostname + ":::" + std::to_string(port);
	pthread_mutex_lock(&aws_rds_bgd_mutex);
	auto it = aws_rds_bgd_server_status.find(key);
	bool r = (it != aws_rds_bgd_server_status.end()
	       && it->second == AWS_RDS_BGD_Server_Status::IN_PROGRESS);
	pthread_mutex_unlock(&aws_rds_bgd_mutex);
	return r;
}

/**
* @brief Flag/unflag every server in BGD hostgroups as switchover-in-progress.
*
* @details Called by the BGD worker at switchover initiation (INITIATED / IN_PROGRESS /
*   POST_PROCESSING) and cleared after SWITCHOVER_COMPLETED. Saves the marked servers in the
*   worker state so cleanup does not depend on the current hostgroup configuration.
*
* @param st          BGD worker state.
* @param in_progress true to flag servers, false to clear.
*/
void MySQL_Monitor::set_aws_rds_bgd_server_in_progress(AWS_RDS_BGD_State& st, bool in_progress) {
	if (in_progress) {
		st.read_only_check_disabled.clear();

		MyHGM->wrlock();
		unsigned int hgs[2] = { st.writer_hg, st.reader_hg };
		for (unsigned int i = 0; i < 2; i++) {
			MyHGC* myhgc = MyHGM->MyHGC_find(hgs[i]);
			if (myhgc == nullptr || myhgc->mysrvs == nullptr) {
				continue;
			}
			for (unsigned int j = 0; j < myhgc->mysrvs->cnt(); j++) {
				MySrvC* s = myhgc->mysrvs->idx(j);
				st.read_only_check_disabled.push_back(std::string(s->address) + ":::" + std::to_string(s->port));
			}
		}
		MyHGM->wrunlock();
	}

	pthread_mutex_lock(&aws_rds_bgd_mutex);
	if (in_progress) {
		for (const auto& k : st.read_only_check_disabled) {
			aws_rds_bgd_server_status[k] = AWS_RDS_BGD_Server_Status::IN_PROGRESS;
		}
	} else {
		for (const auto& k : st.read_only_check_disabled) {
			aws_rds_bgd_server_status.erase(k);
		}
	}
	pthread_mutex_unlock(&aws_rds_bgd_mutex);

	if (!in_progress) {
		st.read_only_check_disabled.clear();
	}
}

/**
* @brief AWS RDS BGD monitor thread entry point.
*
* @details Maintains one worker (monitor_RDS_BGD_thread_HG) per active writer hostgroup. The parent starts
*   and stops workers and signals configuration changes. Each worker selects a pingable probe host,
*   probes 'mysql.rds_topology', and runs the switchover state machine.
*/
void * MySQL_Monitor::monitor_aws_rds_bgd() {
	// Wait for GloMTH to be initialized
	if (!wait_for_glo_mth())
		return NULL;

	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime = monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version = GloMTH->get_global_version();
	mysql_thr->refresh_variables();

	uint64_t last_checksum = 0;
	std::unordered_map<int, std::unique_ptr<AWS_RDS_BGD_Worker>> workers;

	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true) {
		unsigned int glover;
		if (!GloMTH)
			break;

		glover = GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version = glover;
			mysql_thr->refresh_variables();
		}

		uint64_t new_checksum = 0;
		std::shared_ptr<SQLite3_result> hosts_resultset;
		std::unordered_map<int, uint64_t> cluster_checksums;

		pthread_mutex_lock(&aws_rds_bgd_hosts_mutex);
		new_checksum = AWS_RDS_BGD_Hosts_checksum;
		if (new_checksum != last_checksum && AWS_RDS_BGD_Hosts_resultset) {
			hosts_resultset = AWS_RDS_BGD_Hosts_resultset;
			cluster_checksums = AWS_RDS_BGD_Cluster_checksum;
		}
		pthread_mutex_unlock(&aws_rds_bgd_hosts_mutex);

		std::unordered_map<int, uint64_t> active_cluster_checksums;
		if (hosts_resultset) {
			for (SQLite3_row* row : hosts_resultset->rows) {
				char* srv_type = row->fields[AWS_RDS_BGD_SRV_TYPE];
				if (srv_type && srv_type[0] == 'B'
					&& atoi(row->fields[AWS_RDS_BGD_IS_WRITER]) != 0) {
					int writer_hg = atoi(row->fields[AWS_RDS_BGD_WRITER_HOSTGROUP]);
					auto checksum_it = cluster_checksums.find(writer_hg);
					if (checksum_it != cluster_checksums.end()) {
						active_cluster_checksums[writer_hg] = checksum_it->second;
					}
				}
			}
		}

		if (new_checksum != last_checksum) {
			proxy_info("Detected changed definition for AWS RDS Blue Green monitoring\n");
			last_checksum = new_checksum;
			std::vector<int> stopped_workers;

			for (auto& [writer_hg, worker] : workers) {
				auto cluster_it = active_cluster_checksums.find(writer_hg);
				if (cluster_it == active_cluster_checksums.end()) {
					worker->worker_stop.store(true);
					stopped_workers.push_back(writer_hg);
					proxy_info(
						"AWS RDS BGD [wHG=%d]: stopping worker; deployment is inactive, removed, or has no blue writer\n",
						writer_hg);
					continue;
				}

				uint64_t old_cluster_checksum = worker->current_checksum.load();
				if (old_cluster_checksum != cluster_it->second) {
					worker->current_checksum.store(cluster_it->second);
					proxy_info(
						"AWS RDS BGD [wHG=%d]: signaling config refresh, checksum %llu -> %llu\n",
						writer_hg, (unsigned long long)old_cluster_checksum,
						(unsigned long long)cluster_it->second);
				}
			}

			for (auto& [writer_hg, checksum] : active_cluster_checksums) {
				if (workers.find(writer_hg) != workers.end()) {
					continue;
				}

				std::unique_ptr<AWS_RDS_BGD_Worker> worker(new AWS_RDS_BGD_Worker);
				worker->writer_hg = writer_hg;
				worker->current_checksum.store(checksum);
				AWS_RDS_BGD_Worker* worker_arg = worker.get();
				workers.emplace(writer_hg, std::move(worker));
				proxy_info("Starting Monitor thread for AWS RDS writer HG %d\n", writer_hg);
				if (pthread_create(&worker_arg->thread, NULL, monitor_RDS_BGD_thread_HG, worker_arg) != 0) {
					// LCOV_EXCL_START
					proxy_error("Thread creation\n");
					assert(0);
					// LCOV_EXCL_STOP
				}
			}

			for (int writer_hg : stopped_workers) {
				auto worker_it = workers.find(writer_hg);
				if (worker_it == workers.end()) {
					continue;
				}
				pthread_join(worker_it->second->thread, NULL);
				proxy_info("Stopped Monitor thread for AWS RDS writer HG %d\n", writer_hg);
				workers.erase(worker_it);
			}
		}

		usleep(10000);
	}
	for (auto& [writer_hg, worker] : workers) {
		worker->worker_stop.store(true);
	}
	for (auto& [writer_hg, worker] : workers) {
		pthread_join(worker->thread, NULL);
		proxy_info("Stopped Monitor thread for AWS RDS writer HG %d\n", writer_hg);
	}
	workers.clear();
	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr = NULL;
	}
	return NULL;
}

unsigned int MySQL_Monitor::estimate_lag(char* server_id, AWS_Aurora_status_entry** aase, unsigned int idx, unsigned int add_lag_ms, unsigned int min_lag_ms, unsigned int lag_num_checks) {
	assert(aase);
	assert(server_id);
	assert(idx >= 0 && idx < N_L_ASE);

	if (lag_num_checks > N_L_ASE) lag_num_checks = N_L_ASE;
	if (lag_num_checks <= 0) lag_num_checks = 1;

	unsigned int mlag = 0;
	unsigned int lag = 0;

	for (unsigned int i = 1; i <= lag_num_checks; i++) {
		if (!aase[idx] || !aase[idx]->host_statuses)
			break;
		for (auto hse : *(aase[idx]->host_statuses)) {
			if (strcmp(server_id, hse->server_id)==0 && (unsigned int)hse->replica_lag_ms != 0) {
				unsigned int ms = std::max(((unsigned int)hse->replica_lag_ms + add_lag_ms), min_lag_ms);
				if (ms > mlag) mlag = ms;
				if (!lag) lag = ms;
			}
		}
		if (idx == 0) idx = N_L_ASE;
		idx--;
	}

	return mlag;
}

void print_aws_aurora_status_entry(AWS_Aurora_status_entry* aase) {
	if (aase && aase->start_time) {
		if (aase->host_statuses->size()) {
			for (AWS_Aurora_replica_host_status_entry* hse : *aase->host_statuses) {
				if (hse) {
					fprintf(stderr,"%s %s %s %f %f\n", hse->server_id, hse->session_id, hse->last_update_timestamp, hse->replica_lag_ms , hse->cpu);
				}
			}
		}
	}
}

void MySQL_Monitor::aws_aurora_autopurge_servers(unsigned int wHG, unsigned int rHG, AWS_Aurora_status_entry *ase, unsigned int threshold, std::map<std::string, int>& autopurge_counter, const std::string& domain_name) {
	bool server_purged = false;

	std::set<std::string> present_servers;
	for (auto h : *(ase->host_statuses)) {
		present_servers.insert(h->server_id);
	}

	MyHGM->wrlock();

	// Writer hostgroup
	MyHGC *whgc = MyHGM->MyHGC_lookup(wHG);
	if (whgc && whgc->mysrvs) {
		for (unsigned int j = 0; j < whgc->mysrvs->cnt(); j++) {
			MySrvC *mysrvc = whgc->mysrvs->idx(j);
			if (mysrvc->get_status() == MYSQL_SERVER_STATUS_OFFLINE_HARD) continue;

			std::string server_id(mysrvc->address);
			size_t pos = server_id.rfind(domain_name);
			if (pos != std::string::npos) {
				server_id.erase(pos);
			}

			std::string srv_key = std::to_string(wHG) + ":" + server_id;
			if (present_servers.find(server_id) == present_servers.end()) {
				if (++autopurge_counter[srv_key] >= (int)threshold) {
					proxy_warning("Auto-purging server %s:%d from hostgroup %u (absent from REPLICA_HOST_STATUS for %d checks)\n",
						mysrvc->address, mysrvc->port, wHG, autopurge_counter[srv_key]);
					MyHGM->remove_server_in_hg(wHG, mysrvc->address, mysrvc->port);
					autopurge_counter.erase(srv_key);
					server_purged = true;
				}
			} else {
				autopurge_counter.erase(srv_key);
			}
		}
	}

	// Reader hostgroup
	if (rHG > 0) {
		MyHGC *rhgc = MyHGM->MyHGC_lookup(rHG);
		if (rhgc && rhgc->mysrvs) {
			for (unsigned int j = 0; j < rhgc->mysrvs->cnt(); j++) {
				MySrvC *mysrvc = rhgc->mysrvs->idx(j);
				if (mysrvc->get_status() == MYSQL_SERVER_STATUS_OFFLINE_HARD) continue;

				std::string server_id(mysrvc->address);
				size_t pos = server_id.rfind(domain_name);
				if (pos != std::string::npos) {
					server_id.erase(pos);
				}

				std::string srv_key = std::to_string(rHG) + ":" + server_id;
				if (present_servers.find(server_id) == present_servers.end()) {
					if (++autopurge_counter[srv_key] >= (int)threshold) {
						proxy_warning("Auto-purging server %s:%d from hostgroup %u (absent from REPLICA_HOST_STATUS for %d checks)\n",
							mysrvc->address, mysrvc->port, rHG, autopurge_counter[srv_key]);
						MyHGM->remove_server_in_hg(rHG, mysrvc->address, mysrvc->port);
						autopurge_counter.erase(srv_key);
						server_purged = true;
					}
				} else {
					autopurge_counter.erase(srv_key);
				}
			}
		}
	}

	// when server are removed from HG, update AWS_Aurora_Hosts_resultset
	if (server_purged) {
		MyHGM->update_aws_aurora_hosts_monitor_resultset(true);
	}

	MyHGM->wrunlock();
}

void MySQL_Monitor::evaluate_aws_aurora_results(unsigned int wHG, unsigned int rHG, AWS_Aurora_status_entry **lasts_ase, unsigned int ase_idx, unsigned int max_latency_ms, unsigned int add_lag_ms, unsigned int min_lag_ms, unsigned int lag_num_checks) {
#ifdef TEST_AURORA
	unsigned int i = 0;
	bool verbose = false;
	unsigned int action_yes = 0;
	unsigned int action_no = 0;
	unsigned int enabling = 0;
	unsigned int disabling = 0;
	if (rand() % 500 == 0) {
		verbose = true;
		bool ev = false;
		if (rand() % 1000 == 0) {
			ev = true;
		}
		for (i=0; i < N_L_ASE; i++) {
			AWS_Aurora_status_entry *aase = lasts_ase[i];
			if (ev == true || i == ase_idx) {
				print_aws_aurora_status_entry(aase);
			}
		}
	}
#endif // TEST_AURORA
	unsigned int prev_ase_idx = ase_idx;
	if (prev_ase_idx == 0) prev_ase_idx = N_L_ASE;
	prev_ase_idx--;
	AWS_Aurora_status_entry *aase = lasts_ase[ase_idx];
	AWS_Aurora_status_entry *prev_aase = lasts_ase[prev_ase_idx];
	if (aase && aase->start_time) {
		if ( aase->host_statuses->size() ) {
			for (std::vector<AWS_Aurora_replica_host_status_entry *>::iterator it3 = aase->host_statuses->begin(); it3!=aase->host_statuses->end(); ++it3) {
				AWS_Aurora_replica_host_status_entry *hse = *it3;
				bool run_action = true;
				bool enable = true;
				bool is_writer = false;
				bool rla_rc = true;
				unsigned int current_lag_ms = estimate_lag(hse->server_id, lasts_ase, ase_idx, add_lag_ms, min_lag_ms, lag_num_checks);
				hse->estimated_lag_ms = current_lag_ms;
				if (current_lag_ms > max_latency_ms) {
					enable = false;
				}
				if (strcmp(hse->session_id,"MASTER_SESSION_ID")==0) {
					is_writer = true;
				}
				// we also try to determine if a change needs to be made
				if (prev_aase && prev_aase->start_time) {
					if ( prev_aase->host_statuses->size() ) {
						for (std::vector<AWS_Aurora_replica_host_status_entry *>::iterator it4 = prev_aase->host_statuses->begin(); it4!=prev_aase->host_statuses->end(); ++it4) {
							AWS_Aurora_replica_host_status_entry *prev_hse = *it4;
							if (strcmp(prev_hse->server_id,hse->server_id)==0) {
								bool prev_enabled = true;

								unsigned int prev_lag_ms = estimate_lag(hse->server_id, lasts_ase, prev_ase_idx, add_lag_ms, min_lag_ms, lag_num_checks);
								if (prev_lag_ms > max_latency_ms) {
									prev_enabled = false;
								}
								if (prev_enabled == enable) {
									// the previous status should be the same
									// do not run any action
									run_action = false;
								}
							}
						}
					}
				}
				if (run_action) {
#ifdef TEST_AURORA
					action_yes++;
					(enable ? enabling++ : disabling++);
					rla_rc = MyHGM->aws_aurora_replication_lag_action(wHG, rHG, hse->server_id, current_lag_ms, enable, is_writer, verbose);
#else
					rla_rc = MyHGM->aws_aurora_replication_lag_action(wHG, rHG, hse->server_id, current_lag_ms, enable, is_writer);
#endif // TEST_AURORA
				} else {
#ifdef TEST_AURORA
					action_no++;
#endif // TEST_AURORA
					if (is_writer ) {
						// if the server is a writer we run it anyway. This will perform some sanity check
						rla_rc = MyHGM->aws_aurora_replication_lag_action(wHG, rHG, hse->server_id, current_lag_ms, enable, is_writer);
					}
				}
				//if (is_writer == true && rla_rc == false) {
				if (rla_rc == false) {
				if (is_writer == true) {
					// the server is not configured as a writer
#ifdef TEST_AURORA
					proxy_info("Calling update_aws_aurora_set_writer for %s\n", hse->server_id);
#endif // TEST_AURORA
					MyHGM->update_aws_aurora_set_writer(wHG, rHG, hse->server_id);
					time_t __timer;
					char lut[30];
					struct tm __tm_info;
					time(&__timer);
					localtime_r(&__timer, &__tm_info);
					strftime(lut, 25, "%Y-%m-%d %H:%M:%S", &__tm_info);
					char *q1 = (char *)"INSERT INTO mysql_server_aws_aurora_failovers VALUES (%d, '%s', '%s')";
					char *q2 = (char *)malloc(strlen(q1)+strlen(lut)+strlen(hse->server_id));
					sprintf(q2, q1, wHG, hse->server_id, lut);
					monitordb->execute(q2);
					free(q2);
				} else {
#ifdef TEST_AURORA
					proxy_info("Calling update_aws_aurora_set_reader for %s\n", hse->server_id);
#endif // TEST_AURORA
					MyHGM->update_aws_aurora_set_reader(wHG, rHG, hse->server_id);
				}
				}
			}
		}
	}
#ifdef TEST_AURORA
	if (verbose) {
		proxy_info("replication_lag_actions: YES=%u , NO=%u , enabling=%u , disabling=%u\n", action_yes, action_no, enabling, disabling);
	}
#endif // TEST_AURORA
}

std::string MySQL_Monitor::dns_lookup(const std::string& hostname, bool return_hostname_if_lookup_fails, size_t* ip_count) {
	
	static thread_local std::shared_ptr<DNS_Cache> dns_cache_thread;

	// if IP was provided, no need to do lookup
	if (hostname.empty() || validate_ip(hostname))
		return hostname;

	if (!dns_cache_thread && GloMyMon)
		dns_cache_thread = GloMyMon->dns_cache;

	std::string ip;

	if (dns_cache_thread) {
		ip = dns_cache_thread->lookup(trim(hostname), ip_count) ;

		if (ip.empty() && return_hostname_if_lookup_fails) {
			ip = hostname;
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "DNS cache lookup was a miss. (Hostname:[%s])\n", hostname.c_str());
		}
	}

	return ip;
}

std::string MySQL_Monitor::dns_lookup(const char* hostname, bool return_hostname_if_lookup_fails, size_t* ip_count) {
	return MySQL_Monitor::dns_lookup(std::string(hostname), return_hostname_if_lookup_fails, ip_count);
}

bool MySQL_Monitor::timeout_validate_ip_change(const MySQL_Monitor_State_Data* mmsd) const {
	if (!mmsd || !mmsd->mysql || !mmsd->hostname || !dns_cache) {
		return false;
	}

	if (mmsd->port == 0 || validate_ip(mmsd->hostname)) {
		return false;
	}

	const std::string connected_ip = get_connected_peer_ip_from_socket(mmsd->mysql->net.fd);
	if (connected_ip.empty()) {
		return false;
	}

	return !dns_cache->is_ip_valid(mmsd->hostname, connected_ip);
}

bool MySQL_Monitor::update_dns_cache_from_mysql_conn(const MYSQL* mysql)
{
	assert(mysql);

	// if port==0, UNIX socket is used
	if (mysql->port == 0)
		return false;

	const std::string& hostname = mysql->host;
		
	// if IP was provided, no need to update dns cache
	if (hostname.empty() || validate_ip(hostname))
		return false;

	bool result = false;

	const std::string& ip_addr = get_connected_peer_ip_from_socket(mysql->net.fd);
	
	if (ip_addr.empty() == false) {
		result = _dns_cache_update(hostname, { ip_addr });
	}

	return result;
}

bool MySQL_Monitor::_dns_cache_update(const std::string &hostname, std::vector<std::string>&& ip_address) {
	static thread_local std::shared_ptr<DNS_Cache> dns_cache_thread;

	if (!dns_cache_thread && GloMyMon)
		dns_cache_thread = GloMyMon->dns_cache;

	if (dns_cache_thread) {
		// Render the IP list for the debug log BEFORE moving the vector
		// into add_if_not_exist; reading the moved-from vector would yield
		// "valid but unspecified" content (typically empty).
		const std::string ip_list_for_log = debug_iplisttostring(ip_address);
		if (dns_cache_thread->add_if_not_exist(trim(hostname), std::move(ip_address))) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Direct DNS cache update. (Hostname:[%s] IP:[%s])\n", hostname.c_str(), ip_list_for_log.c_str());
			return true;
		}
	}

	return false;
}

void MySQL_Monitor::trigger_dns_cache_update() {
	if (GloMyMon) {
		GloMyMon->force_dns_cache_update = true;
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Triggering DNS cache update sequence.\n");
	}
}

// DNS_Cache::add(), add_if_not_exist(), get_next_ip(), lookup(), remove(),
// clear(), and empty() moved to lib/DNS_Cache.cpp.

#define NEXT_IMMEDIATE(new_st) do { async_state_machine_=new_st; goto __again; } while (0)

short MySQL_Monitor_State_Data::next_event(MDB_ASYNC_ST new_st, int status) {

	short wait_events = 0;

	if (status & MYSQL_WAIT_READ)
		wait_events |= POLLIN;
	if (status & MYSQL_WAIT_WRITE)
		wait_events |= POLLOUT;
	if (status & MYSQL_WAIT_EXCEPT)
		wait_events |= POLLPRI;

#ifdef DEBUG
	int fd;

	if (wait_events) {
		fd = mysql_get_socket(mysql);
	} else {
		fd = -1;
	}
	proxy_debug(PROXY_DEBUG_NET, 8, "fd=%d, wait_events=%d , old_ST=%d, new_ST=%d\n", fd, wait_events, async_state_machine_, new_st);
#endif /* DEBUG */
	
	async_state_machine_ = new_st;
	return wait_events;
}

static int
mysql_status(short event) {
	int status = 0;
	if (event & POLLIN) 
		status |= MYSQL_WAIT_READ;
	if (event & POLLOUT) 
		status |= MYSQL_WAIT_WRITE;
	if (event & POLLPRI) 
		status |= MYSQL_WAIT_EXCEPT;
	return status;
}

class Monitor_Poll {
public:
	class Process_Ready_Task_Callback_Args {
	public:
		using process_ready_tasks_cb = bool (MySQL_Monitor::*)(const std::vector<MySQL_Monitor_State_Data*>& mmsds);

		Process_Ready_Task_Callback_Args(unsigned int min_tasks_to_process, unsigned int max_task_to_send, float percentage,
			process_ready_tasks_cb callback, MySQL_Monitor* mysql_monitor) :
			min_task_to_process_(min_tasks_to_process), max_task_to_send_(max_task_to_send),
			process_task_percentage_(percentage / 100.00), process_ready_tasks_cb_(callback),
			mysql_monitor_(mysql_monitor) {
			assert(mysql_monitor_);
			assert(process_ready_tasks_cb_);
			assert(process_task_percentage_ != 0);
			assert(min_tasks_to_process != 0);
		}
		~Process_Ready_Task_Callback_Args() = default;

	private:
		inline
		bool process_ready_tasks(const std::vector<MySQL_Monitor_State_Data*>& mmsds) {
			return (mysql_monitor_->*process_ready_tasks_cb_)(mmsds);
		}

		friend class Monitor_Poll;
		unsigned int min_task_to_process_;
		unsigned int max_task_to_send_;
		float process_task_percentage_;
		process_ready_tasks_cb process_ready_tasks_cb_;
		MySQL_Monitor* mysql_monitor_;
	};

	explicit Monitor_Poll(unsigned int capacity, bool owns_task_memory = false) {
		len_ = 0;
		owns_task_memory_ = owns_task_memory; // if true, this object takes ownership of task memory and will delete unprocessed tasks on destruction
		capacity_ = capacity;
		fds_ = (struct pollfd*)malloc(capacity_ * sizeof(struct pollfd));
		mmsds_ = (MySQL_Monitor_State_Data**)malloc(capacity_ * sizeof(MySQL_Monitor_State_Data*));
	}

	~Monitor_Poll() {
		if (owns_task_memory_) {
			cleanup_unprocessed_tasks(); // free remaining unprocessed tasks
		}
		free(fds_);
		free(mmsds_);
	}

	void expand(unsigned int more) {
		if ((len_ + more) > capacity_) {
			unsigned int new_size = near_pow_2(len_ + more);
			fds_ = (struct pollfd*)realloc(fds_, new_size * sizeof(struct pollfd));
			mmsds_ = (MySQL_Monitor_State_Data**)realloc(mmsds_, new_size * sizeof(MySQL_Monitor_State_Data*));
			capacity_ = new_size;
		}
	}

	void add(short _events, MySQL_Monitor_State_Data* mmsd) {
		assert(mmsd);
		assert(_events);
		if (len_ == capacity_) {
			expand(1);
		}
		fds_[len_].fd = -1; // will be set in event_loop phase 1
		fds_[len_].events = _events;
		fds_[len_].revents = 0;
		mmsds_[len_] = mmsd;
		len_++;
		mmsd->init_async();
	}

	void remove_index_fast(unsigned int i) {
		if ((int)i == -1) return;

		if (i != (len_ - 1)) {
			fds_[i].fd = fds_[len_ - 1].fd;
			fds_[i].events = fds_[len_ - 1].events;
			fds_[i].revents = fds_[len_ - 1].revents;
			mmsds_[i] = mmsds_[len_ - 1];
		}
		len_--;
	}

	int find_index(int fd) {
		unsigned int i;
		for (i = 0; i < len_; i++) {
			if (fds_[i].fd == fd) {
				return i;
			}
		}
		return -1;
	}

	bool event_loop(int poll_timeout_ms, Process_Ready_Task_Callback_Args& process_ready_task_callback_arg) {

		if (len_ == 0) return false;

		// Snapshot the number of tasks that are currently queued for this event loop iteration.
		// len_ will change as tasks complete and are removed below.
		const unsigned int total_tasks = len_;

		// Number of tasks to send in each batch.
		const unsigned int send_batch_size = process_ready_task_callback_arg.max_task_to_send_;

		// Determine how many tasks to process before flushing the ready queue to the callback.
		unsigned int tasks_to_process_count = total_tasks * process_ready_task_callback_arg.process_task_percentage_;

		// if number of task to process is less than minimum task to process, overwrite it
		if (tasks_to_process_count < process_ready_task_callback_arg.min_task_to_process_) {
			tasks_to_process_count = process_ready_task_callback_arg.min_task_to_process_;
		}

		std::vector<MySQL_Monitor_State_Data*> ready_tasks;
		ready_tasks.reserve(tasks_to_process_count);

		auto cleanup_ready_tasks = [&ready_tasks, this]() {
			for (auto* task : ready_tasks) {
				if (task->mysql) {
					GloMyMon->My_Conn_Pool->destroy_mysql_connection(task);
				}
				if (owns_task_memory_) {
					delete task;
				}
			}
			ready_tasks.clear();
		};

		unsigned int total_sent = 0;
		while (len_) {

			if (GloMyMon->shutdown) {
				proxy_error("Monitor event loop interrupted by shutdown with %u tasks remaining. Connections will be cleaned up.\n", len_);
				cleanup_ready_tasks();
				return false;
			}

			// Phase 1: proactively arm inactive sockets by initializing their poll entries
			// and triggering the first async step for up to `min_task_to_send` tasks.
			unsigned int sockets_armed = 0;
			for (unsigned int idx = 0; idx < len_ && sockets_armed < send_batch_size; ++idx) {
				struct pollfd& poll_entry = fds_[idx];

				// Skip already-armed entries
				if (poll_entry.fd != -1)
					continue;

				// Arm socket
				poll_entry.fd = mysql_get_socket(mmsds_[idx]->mysql);
				assert(poll_entry.fd != -1);
				poll_entry.revents = 0;

				// Kick off the task state machine
				mmsds_[idx]->task_handler(-1, poll_entry.events);
				++sockets_armed;
			}
			total_sent += sockets_armed;

			proxy_debug(PROXY_DEBUG_MONITOR, 7,
				"Phase 1: armed %u sockets (this batch), total armed=%u, total tasks=%u\n",
				sockets_armed, total_sent, total_tasks);
			
			// If we sent all tasks, use the caller poll timeout; otherwise poll immediately (timeout=0)
			int poll_timeout = (total_sent == total_tasks) ? poll_timeout_ms : 0;
			int rc = poll(fds_, len_, poll_timeout);
			if (rc == -1) {
				if (errno == EINTR) {
					continue;
				} else {
					proxy_error("Monitor event loop poll() failed with error %d (%s) with %u tasks remaining. Aborting monitoring cycle.\n", errno, strerror(errno), len_);
					cleanup_ready_tasks();
					return false;
				}
			}

			// Phase 2: collect completed tasks and batch deliver to the callback once the
			// tasks_to_process_count threshold is met (or no tasks remain).
			for (unsigned int i = 0; i < len_;) {

				if (mmsds_[i]->task_handler(fds_[i].revents, fds_[i].events) != MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_PENDING) {

					ready_tasks.push_back(mmsds_[i]);
					remove_index_fast(i);

					tasks_to_process_count--;

					// Flush the batch when threshold reached or no more tasks remain.
					if (tasks_to_process_count == 0 || len_ == 0) {
						proxy_debug(PROXY_DEBUG_MONITOR, 7, "Phase 2: Starting processing of %zu ready tasks\n", ready_tasks.size());

						// it is responsibility of the callback to ensure all tasks passed to it are processed (either successfully or unsuccessfully) and cleaned up. 
						if (process_ready_task_callback_arg.process_ready_tasks(ready_tasks) == false) {
							ready_tasks.clear();
							proxy_error("Monitor event loop process_ready_tasks() failed. %u tasks remaining unprocessed in poll.\n", len_);
							return false;
						}
						ready_tasks.clear();

						// Recompute threshold against the current remaining queue length.
						tasks_to_process_count = len_ * process_ready_task_callback_arg.process_task_percentage_;
						if (tasks_to_process_count < process_ready_task_callback_arg.min_task_to_process_) {
							tasks_to_process_count = process_ready_task_callback_arg.min_task_to_process_;
						}
					}
					continue; 
				} else {
					// Not ready yet; ensure we keep polling for its events.
					if (fds_[i].fd != -1)
						assert(fds_[i].events != 0);
				}

				fds_[i].revents = 0;
				i++;
			}
		}
		assert(ready_tasks.empty());
		return true;
	}

	inline 
	unsigned int count() const {
		return len_;
	}

private:
	static unsigned int near_pow_2(unsigned int n) {
		unsigned int i = 1;
		while (i < n) i <<= 1;
		return i ? i : n;
	}

	// Deletes any task objects that were not processed
	inline
	void cleanup_unprocessed_tasks() {
		if (len_ == 0) return;
		for (unsigned int i = 0; i < len_; ++i) {
			if (mmsds_[i]->mysql) {
				GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsds_[i]);
			}
			delete mmsds_[i];
			mmsds_[i] = nullptr;
		}
		len_ = 0;
	}

	unsigned int len_;
	unsigned int capacity_;
	struct pollfd* fds_;
	MySQL_Monitor_State_Data** mmsds_;
	bool owns_task_memory_;
};

MySQL_Monitor_State_Data_Task_Result MySQL_Monitor_State_Data::task_handler(short event_, short& wait_event) {
	assert(task_handler_);

	if (event_ != -1) {
		if (task_result_ == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT ||
			task_result_ == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT_STALE_IP) {
			return task_result_;
		}
#ifdef DEBUG
		const unsigned long long now = (GloMyMon->proxytest_forced_timeout == false) ? monotonic_time() : ULLONG_MAX;
#else
		const unsigned long long now = monotonic_time();
#endif
		if (task_expiry_time_ > 0 && now > task_expiry_time_) {
#ifdef DEBUG
			mark_task_as_timeout((GloMyMon->proxytest_forced_timeout == false) ? now : monotonic_time());
#else
			mark_task_as_timeout(now);
#endif
			return MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT;
		}
	}

	task_result_ = (event_ != 0) ? (this->*task_handler_)(event_, wait_event) :
		MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_PENDING;

	return task_result_;
}

MySQL_Monitor_State_Data_Task_Result MySQL_Monitor_State_Data::ping_handler(short event_, short& wait_event) {
	MySQL_Monitor_State_Data_Task_Result result = MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_PENDING;
	int status = 0;

__again:
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "async_state_machine=%d\n", async_state_machine_);
	switch (async_state_machine_) {
	case ASYNC_PING_START:
		t1 = monotonic_time();
		task_expiry_time_ = t1 + (unsigned long long)task_timeout_ * 1000;
		interr = 0;
		if (mysql_error_msg) {
			free(mysql_error_msg);
			mysql_error_msg = NULL;
		}
		status = mysql_ping_start(&interr, mysql);
		if (status) {
			wait_event = next_event(ASYNC_PING_CONT, status);
		} else {
			NEXT_IMMEDIATE(ASYNC_PING_END);
		}
		break;
	case ASYNC_PING_CONT:
		status = mysql_ping_cont(&interr, mysql, mysql_status(event_));
	
		if (status) {
			wait_event = next_event(ASYNC_PING_CONT, status);
		} else {
			NEXT_IMMEDIATE(ASYNC_PING_END);
		}
		break;
	case ASYNC_PING_END:
		t2 = monotonic_time();
		if (interr) {
			mysql_error_msg = strdup(mysql_error(mysql));

			// In the case of SSL-based connection to the backend server, any connection-related errors will cause 
			// all subsequent calls to the backend servers to fail. This is because OpenSSL maintains a thread-based error 
			// queue that must be cleared after an error occurs to ensure the next call executes successfully.
			MYSQL_OPENSSL_ERROR_CLEAR(mysql);
			NEXT_IMMEDIATE(ASYNC_PING_FAILED);
		} else {
			NEXT_IMMEDIATE(ASYNC_PING_SUCCESSFUL);
		}
		break;
	case ASYNC_PING_SUCCESSFUL:
		result = MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_SUCCESS;
		break;
	case ASYNC_PING_FAILED:
		result = MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_FAILED;
		break;
	case ASYNC_PING_TIMEOUT:
		result = MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT;
		break;
	default:
		assert(0);
		break;
	}

	return result;
}


void* monitor_ping_process_ready_task_thread(const std::vector<MySQL_Monitor_State_Data*>& ready_mmsds) {
	if (ready_mmsds.empty()) return NULL;

	SQLite3DB* monitor_db = ready_mmsds.front()->mondb;
	const char* query1 = "INSERT OR REPLACE INTO mysql_server_ping_log VALUES (?1, ?2, ?3, ?4, ?5)";
	std::string query32s = "INSERT OR REPLACE INTO mysql_server_ping_log VALUES " + generate_multi_rows_query(32, 5);
	const char* query32 = query32s.c_str();

	auto [rc1, statement1_unique] = monitor_db->prepare_v2(query1);
	ASSERT_SQLITE_OK(rc1, monitor_db);
	auto [rc2, statement32_unique] = monitor_db->prepare_v2(query32);
	ASSERT_SQLITE_OK(rc2, monitor_db);
	sqlite3_stmt* statement1 = statement1_unique.get();
	sqlite3_stmt* statement32 = statement32_unique.get();
	int rc;

	size_t row_idx = 0;
	size_t max_bulk_row_idx = (ready_mmsds.size() / 32) * 32;

	for (const auto& mmsd : ready_mmsds) {
		const auto task_result = mmsd->get_task_result();
		assert(task_result != MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_PENDING);

		std::string server_version{};
		if (mmsd->mysql && mmsd->mysql->server_version)
			server_version = std::string(mmsd->mysql->server_version);

		if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_SUCCESS) {
			__sync_fetch_and_add(&GloMyMon->ping_check_OK, 1);
			GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
		} else {
			__sync_fetch_and_add(&GloMyMon->ping_check_ERR, 1);
			if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT) {
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql,
					mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_PING_TIMEOUT);
				proxy_error("Timeout on ping check for %s:%d after %lldms.\n",
					mmsd->hostname, mmsd->port, (mmsd->t2 - mmsd->t1) / 1000);
			} else {
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql,
					mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
				proxy_error("Error after %lldms on server %s:%d : %s\n",
					(mmsd->t2 - mmsd->t1) / 1000, mmsd->hostname, mmsd->port,
					(mmsd->mysql_error_msg ? mmsd->mysql_error_msg : ""));
			}
			GloMyMon->My_Conn_Pool->destroy_mysql_connection(mmsd);
		}

		if (GloMyMon->shutdown)
			return NULL;

		unsigned long long time_now = realtime_time();
		time_now = time_now - (mmsd->t2 - mmsd->t1);
		unsigned long long duration = (mmsd->mysql_error_msg ? 0 : mmsd->t2 - mmsd->t1);
		const char* errmsg = mmsd->mysql_error_msg;

		size_t idx = row_idx % 32;

		if (row_idx < max_bulk_row_idx) {
			// --- bulk insert path ---
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 5) + 1, mmsd->hostname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitor_db);
			rc = (*proxy_sqlite3_bind_int)(statement32, (idx * 5) + 2, mmsd->port); ASSERT_SQLITE_OK(rc, monitor_db);
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 5) + 3, time_now); ASSERT_SQLITE_OK(rc, monitor_db);
			rc = (*proxy_sqlite3_bind_int64)(statement32, (idx * 5) + 4, duration); ASSERT_SQLITE_OK(rc, monitor_db);
			rc = (*proxy_sqlite3_bind_text)(statement32, (idx * 5) + 5, errmsg, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitor_db);

			// execute when we reach 32 rows
			if (idx == 31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc = (*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, monitor_db);
				rc = (*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, monitor_db);
			}
		} else {
			// --- single insert path ---
			rc = (*proxy_sqlite3_bind_text)(statement1, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitor_db);
			rc = (*proxy_sqlite3_bind_int)(statement1, 2, mmsd->port); ASSERT_SQLITE_OK(rc, monitor_db);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 3, time_now); ASSERT_SQLITE_OK(rc, monitor_db);
			rc = (*proxy_sqlite3_bind_int64)(statement1, 4, duration); ASSERT_SQLITE_OK(rc, monitor_db);
			rc = (*proxy_sqlite3_bind_text)(statement1, 5, errmsg, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, monitor_db);
			SAFE_SQLITE3_STEP2(statement1);
			rc = (*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, monitor_db);
			rc = (*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, monitor_db);
		}

		if (strcasestr(server_version.c_str(), (const char*)SERVER_VERSION_READYSET) != NULL)
			ReadySet_Servers.insert(ServerInfo(mmsd->hostname, mmsd->port));
		else if (!ReadySet_Servers.empty())
			ReadySet_Servers.erase(ServerInfo(mmsd->hostname, mmsd->port));

		row_idx++;
	}

	return NULL;
}

bool MySQL_Monitor::monitor_ping_process_ready_tasks(const std::vector<MySQL_Monitor_State_Data*>& ready_mmsds) {
	// Ensure no null tasks are dispatched to the thread pool
	if (!ready_mmsds.empty()) {
		WorkItem<MySQL_Monitor_State_Data>* item = new WorkItem<MySQL_Monitor_State_Data>(ready_mmsds, monitor_ping_process_ready_task_thread);
		queue->add(item);
	}
	return true;
}

void MySQL_Monitor::monitor_ping_async(SQLite3_result* resultset) {
	assert(resultset);

	Monitor_Poll monitor_poll(resultset->rows_count, true);

	for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
		const SQLite3_row* r = *it;
		std::unique_ptr<MySQL_Monitor_State_Data> mmsd(
			new MySQL_Monitor_State_Data(MON_PING, r->fields[0], atoi(r->fields[1]), atoi(r->fields[2])));

		mmsd->mondb = monitordb;
		mmsd->mysql = My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port, mmsd.get());

		if (mmsd->mysql) {
			// Register the task; don't dispatch it yet.
			monitor_poll.add((POLLIN | POLLOUT | POLLPRI), mmsd.release());
		} else {
			WorkItem<MySQL_Monitor_State_Data>* item
				= new WorkItem<MySQL_Monitor_State_Data>(mmsd.release(), monitor_ping_thread);
			queue->add(item);
		}

		if (shutdown) return;
	}

	Monitor_Poll::Process_Ready_Task_Callback_Args args(5, 30, 50, &MySQL_Monitor::monitor_ping_process_ready_tasks, this);

	if (monitor_poll.event_loop(10, args) == false) {
		return;
	}
}

MySQL_Monitor_State_Data_Task_Result MySQL_Monitor_State_Data::generic_handler(short event_, short& wait_event) {
	MySQL_Monitor_State_Data_Task_Result result_ret = MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_PENDING;
	int status = 0;

__again:
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "async_state_machine=%d\n", async_state_machine_);
	switch (async_state_machine_) {
	case ASYNC_QUERY_START:
		assert(!query_.empty());
		t1 = monotonic_time();
		task_expiry_time_ = t1 + (unsigned long long)task_timeout_ * 1000;
		interr = 0;
		if (mysql_error_msg) {
			free(mysql_error_msg);
			mysql_error_msg = NULL;
		}
		if (result) {
			mysql_free_result(result);
			result = NULL;
		}
		status = mysql_real_query_start(&interr, mysql, query_.c_str(), query_.size());
		if (status) {
			wait_event = next_event(ASYNC_QUERY_CONT, status);
		} else {
			NEXT_IMMEDIATE(ASYNC_QUERY_END);
		}
		break;
	case ASYNC_QUERY_CONT:
		status = mysql_real_query_cont(&interr, mysql, mysql_status(event_));

		if (status) {
			wait_event = next_event(ASYNC_QUERY_CONT, status);
		} else {
			NEXT_IMMEDIATE(ASYNC_QUERY_END);
		}
		break;
	case ASYNC_QUERY_END:
		t2 = monotonic_time();
		if (interr) {
			mysql_error_msg = strdup(mysql_error(mysql));

			// In the case of SSL-based connection to the backend server, any connection-related errors will cause 
			// all subsequent calls to the backend servers to fail. This is because OpenSSL maintains a thread-based error 
			// queue that must be cleared after an error occurs to ensure the next call executes successfully.
			MYSQL_OPENSSL_ERROR_CLEAR(mysql);
			NEXT_IMMEDIATE(ASYNC_QUERY_FAILED);
		} else {
			NEXT_IMMEDIATE(ASYNC_QUERY_SUCCESSFUL);
		}
		break;
	case ASYNC_QUERY_SUCCESSFUL:
		NEXT_IMMEDIATE(ASYNC_STORE_RESULT_START);
		break;
	case ASYNC_QUERY_FAILED:
		result_ret = MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_FAILED;
		break;
	case ASYNC_QUERY_TIMEOUT:
		result_ret = MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT;
		break;
	case ASYNC_STORE_RESULT_START:
		status = mysql_store_result_start(&result, mysql);

		if (status) {
			wait_event = next_event(ASYNC_STORE_RESULT_CONT, status);
		} else {
			NEXT_IMMEDIATE(ASYNC_STORE_RESULT_END);
		}
		break;
	case ASYNC_STORE_RESULT_CONT:
		status = mysql_store_result_cont(&result, mysql, mysql_status(event_));

		if (status) {
			wait_event = next_event(ASYNC_STORE_RESULT_CONT, status);
		} else {
			NEXT_IMMEDIATE(ASYNC_STORE_RESULT_END);
		}
		break;
	case ASYNC_STORE_RESULT_END:
		t2 = monotonic_time();
		if (mysql_errno(mysql)) {
			mysql_error_msg = strdup(mysql_error(mysql));

			// In the case of SSL-based connection to the backend server, any connection-related errors will cause 
			// all subsequent calls to the backend servers to fail. This is because OpenSSL maintains a thread-based error 
			// queue that must be cleared after an error occurs to ensure the next call executes successfully.
			MYSQL_OPENSSL_ERROR_CLEAR(mysql);
			NEXT_IMMEDIATE(ASYNC_STORE_RESULT_FAILED);
		} else {
			NEXT_IMMEDIATE(ASYNC_STORE_RESULT_SUCCESSFUL);
		}
		break;
	case ASYNC_STORE_RESULT_FAILED:
		result_ret = MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_FAILED;
		break;
	case ASYNC_STORE_RESULT_TIMEOUT:
		result_ret = MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT;
		break;
	case ASYNC_STORE_RESULT_SUCCESSFUL:
		result_ret = MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_SUCCESS;
		break;
	default:
		assert(0);
		break;
	}

	return result_ret;
}

bool MySQL_Monitor::monitor_read_only_process_ready_tasks(const std::vector<MySQL_Monitor_State_Data*>& mmsds) {
	std::list<read_only_server_t> mysql_servers;

	for (auto& mmsd : mmsds) {
		string originating_server_hostname = mmsd->hostname;
		const auto task_result = mmsd->get_task_result();
		const bool stale_ip_timeout = task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT_STALE_IP;

		assert(task_result != MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_PENDING);

		// AWS RDS blue/green topology discovery is a standalone task: it does not
		// write a read_only log entry. Classify the result and move on.
		if (mmsd->get_task_type() == MON_AWS_RDS_TOPOLOGY_DISCOVERY) {
			if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_SUCCESS) {
				__sync_fetch_and_add(&read_only_check_OK, 1);
				if (mmsd->interr == 0 && mmsd->result) {
					process_aws_rds_topology(mmsd);
				}
				if (mmsd->result) {
					mysql_free_result(mmsd->result);
					mmsd->result = NULL;
				}
				My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
			} else {
				__sync_fetch_and_add(&read_only_check_ERR, 1);
				unsigned int err = mmsd->mysql ? mysql_errno(mmsd->mysql) : 0;
				if (err == 1146) {
					// mysql.rds_topology absent (no active blue/green deployment); expected, skip quietly
					proxy_debug(PROXY_DEBUG_MONITOR, 5,
						"mysql.rds_topology not present on %s:%d; skipping blue/green discovery\n",
						mmsd->hostname, mmsd->port);
				} else {
					MyHGM->p_update_mysql_error_counter(
						p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port,
						err ? err : ER_PROXYSQL_READ_ONLY_CHECK_TIMEOUT
					);
					proxy_error(
						"Error on AWS RDS blue/green topology discovery for %s:%d : %s\n",
						mmsd->hostname, mmsd->port, (mmsd->mysql_error_msg ? mmsd->mysql_error_msg : "")
					);
				}
				My_Conn_Pool->destroy_mysql_connection(mmsd);
			}
			continue;
		}

		if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_SUCCESS) {
			__sync_fetch_and_add(&read_only_check_OK, 1);
			My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
		} else {
			__sync_fetch_and_add(&read_only_check_ERR, 1);
			if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT) {
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_READ_ONLY_CHECK_TIMEOUT);
				proxy_error("Timeout on read_only check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_read_only_timeout.\n", mmsd->hostname, mmsd->port, (mmsd->t2 - mmsd->t1) / 1000);
			} else {
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
#ifdef DEBUG
				proxy_error("Error after %lldms: server %s:%d , mmsd %p , MYSQL %p , FD %d : %s\n", (mmsd->t2 - mmsd->t1) / 1000, mmsd->hostname, mmsd->port, mmsd, mmsd->mysql, mmsd->mysql->net.fd, (mmsd->mysql_error_msg ? mmsd->mysql_error_msg : ""));
#else
				proxy_error("Got error: mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, (mmsd->mysql_error_msg ? mmsd->mysql_error_msg : ""));
#endif
			}

			My_Conn_Pool->destroy_mysql_connection(mmsd);
		}

		if (shutdown == true) {
			return false;
		}

		const char* query = (char*)"INSERT OR REPLACE INTO mysql_server_read_only_log VALUES (?1 , ?2 , ?3 , ?4 , ?5 , ?6)";
		auto [rc1, statement_unique] = mmsd->mondb->prepare_v2(query);
		ASSERT_SQLITE_OK(rc1, mmsd->mondb);
		sqlite3_stmt* statement = statement_unique.get();
		int rc;
		int read_only = 1; // as a safety mechanism , read_only=1 is the default
		bool valid_result = true;
		rc = (*proxy_sqlite3_bind_text)(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		rc = (*proxy_sqlite3_bind_int)(statement, 2, mmsd->port); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		unsigned long long time_now = realtime_time();
		time_now = time_now - (mmsd->t2 - mmsd->t1);
		rc = (*proxy_sqlite3_bind_int64)(statement, 3, time_now); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		rc = (*proxy_sqlite3_bind_int64)(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2 - mmsd->t1)); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		if (mmsd->interr == 0 && mmsd->result) {
			int num_fields = 0;
			int k = 0;
			MYSQL_FIELD* fields = mysql_fetch_fields(mmsd->result);
			int j = -1;
			num_fields = mysql_num_fields(mmsd->result);
			fields = mysql_fetch_fields(mmsd->result);
			if (fields && num_fields == 1) {
				for (k = 0; k < num_fields; k++) {
					if (strcmp((char*)"read_only", (char*)fields[k].name) == 0) {
						j = k;
					}
				}
				if (j > -1) {
					MYSQL_ROW row = mysql_fetch_row(mmsd->result);
					if (row) {
VALGRIND_DISABLE_ERROR_REPORTING;
						if (row[j]) {
							if (!strcmp(row[j], "0") || !strcasecmp(row[j], "OFF"))
								read_only = 0;
						}
VALGRIND_ENABLE_ERROR_REPORTING;
					}
				}

				rc = (*proxy_sqlite3_bind_int64)(statement, 5, read_only); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			} else {
				valid_result = false;
				rc = (*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
				proxy_error("mysql_fetch_fields returns NULL, or mysql_num_fields is incorrect. Server %s:%d . See bug #1994\n", mmsd->hostname, mmsd->port);
				proxy_info("Dumping read_only result for server %s:%d, query: %s\n", mmsd->hostname, mmsd->port, mmsd->get_query());
				dump_mysql_result(stderr, mmsd->result);
			}
			mysql_free_result(mmsd->result);
			mmsd->result = NULL;
		} else {
			rc = (*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		}
		if (mmsd->result) {
			// make sure it is clear
			mysql_free_result(mmsd->result);
			mmsd->result = NULL;
		}
		rc = (*proxy_sqlite3_bind_text)(statement, 6, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		SAFE_SQLITE3_STEP2(statement);
		rc = (*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);
		rc = (*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);

		if (!valid_result || stale_ip_timeout) {
			// Ignore; do not infer backend state.
		} else if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_SUCCESS) {
			//MyHGM->read_only_action_v2(mmsd->hostname, mmsd->port, read_only); // default behavior
			mysql_servers.push_back( std::tuple<std::string,int,int> { mmsd->hostname, mmsd->port, read_only });
		} else {
			char* error = NULL;
			int cols = 0;
			int affected_rows = 0;
			SQLite3_result* resultset = NULL;
			char* new_query = NULL;
			SQLite3DB* mondb = mmsd->mondb;
			new_query = (char*)"SELECT 1 FROM (SELECT hostname,port,read_only,error FROM mysql_server_read_only_log WHERE hostname='%s' AND port='%d' ORDER BY time_start_us DESC LIMIT %d) a WHERE read_only IS NULL AND SUBSTR(error,1,7) = 'timeout' GROUP BY hostname,port HAVING COUNT(*)=%d";
			char* buff = (char*)malloc(strlen(new_query) + strlen(mmsd->hostname) + 32);
			int max_failures = mysql_thread___monitor_read_only_max_timeout_count;
			sprintf(buff, new_query, mmsd->hostname, mmsd->port, max_failures, max_failures);
			mondb->execute_statement(buff, &error, &cols, &affected_rows, &resultset);
			if (!error) {
				if (resultset) {
					if (resultset->rows_count) {
						// disable host
						proxy_error("Server %s:%d missed %d read_only checks. Assuming read_only=1\n", mmsd->hostname, mmsd->port, max_failures);
						MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_READ_ONLY_CHECKS_MISSED);
						//MyHGM->read_only_action_v2(mmsd->hostname, mmsd->port, read_only); // N timeouts reached
						mysql_servers.push_back( std::tuple<std::string,int,int> { mmsd->hostname, mmsd->port, read_only });
					}
					delete resultset;
					resultset = NULL;
				}
			} else {
				proxy_error("Error on %s : %s\n", buff, error);
			}
			free(buff);
		}
	}

	//executing readonly actions
	MyHGM->read_only_action_v2(mysql_servers);

	return true;
}

void MySQL_Monitor::monitor_read_only_async(SQLite3_result* resultset, bool do_discovery_check) {
	assert(resultset);

	std::vector<std::unique_ptr<MySQL_Monitor_State_Data>> mmsds;
	mmsds.reserve(resultset->rows_count);
	Monitor_Poll monitor_poll(resultset->rows_count);

	for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
		const SQLite3_row* r = *it;

		if (is_aws_rds_bgd_server_in_progress(r->fields[0], atoi(r->fields[1]))) {
			proxy_debug(PROXY_DEBUG_MONITOR, 5,
				"Skipping read_only check for '%s:%d' because AWS RDS BGD switchover is in progress\n",
				r->fields[0], atoi(r->fields[1]));
			continue;
		}

		bool rc_ping = server_responds_to_ping(r->fields[0], atoi(r->fields[1]));
		if (rc_ping) { // only if server is responding to pings
			MySQL_Monitor_State_Data_Task_Type task_type = MON_READ_ONLY;

			if (r->fields[3]) {
				if (strcasecmp(r->fields[3], (char*)"innodb_read_only") == 0) {
					task_type = MON_INNODB_READ_ONLY;
				} else if (strcasecmp(r->fields[3], (char*)"super_read_only") == 0) {
					task_type = MON_SUPER_READ_ONLY;
				} else if (strcasecmp(r->fields[3], (char*)"read_only&innodb_read_only") == 0) {
					task_type = MON_READ_ONLY__AND__INNODB_READ_ONLY;
				} else if (strcasecmp(r->fields[3], (char*)"read_only|innodb_read_only") == 0) {
					task_type = MON_READ_ONLY__OR__INNODB_READ_ONLY;
				}

			}

			std::unique_ptr<MySQL_Monitor_State_Data> mmsd(
				new MySQL_Monitor_State_Data(task_type, r->fields[0], atoi(r->fields[1]), atoi(r->fields[2])));

			mmsd->reader_hostgroup = atoi(r->fields[4]); // set reader_hostgroup
			mmsd->mondb = monitordb;
			mmsd->mysql = My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port, mmsd.get());

			if (mmsd->mysql) {
				// Register the task; don't dispatch it yet.
				monitor_poll.add((POLLIN|POLLOUT|POLLPRI), mmsd.get());
				mmsds.push_back(std::move(mmsd));
			} else {
				WorkItem<MySQL_Monitor_State_Data>* item =
					new WorkItem<MySQL_Monitor_State_Data>(mmsd.release(), monitor_read_only_thread);
				queue->add(item);
			}

			// On discovery cycles, enqueue an additional standalone topology-discovery
			// task for AWS RDS endpoints. The read_only check above is unaffected.
			string hostname = r->fields[0];
			if (do_discovery_check && hostname.find(AWS_ENDPOINT_SUFFIX_STRING) != std::string::npos) {
				std::unique_ptr<MySQL_Monitor_State_Data> tmmsd(
					new MySQL_Monitor_State_Data(MON_AWS_RDS_TOPOLOGY_DISCOVERY, r->fields[0], atoi(r->fields[1]), atoi(r->fields[2])));
				tmmsd->reader_hostgroup = atoi(r->fields[4]);
				tmmsd->mondb = monitordb;
				tmmsd->mysql = My_Conn_Pool->get_connection(tmmsd->hostname, tmmsd->port, tmmsd.get());
				if (tmmsd->mysql) {
					monitor_poll.add((POLLIN|POLLOUT|POLLPRI), tmmsd.get());
					mmsds.push_back(std::move(tmmsd));
				} else {
					WorkItem<MySQL_Monitor_State_Data>* item =
						new WorkItem<MySQL_Monitor_State_Data>(tmmsd.release(), monitor_read_only_thread);
					queue->add(item);
				}
			}
		}

		if (shutdown) return;
	}

	Monitor_Poll::Process_Ready_Task_Callback_Args args(5, 30, 50, &MySQL_Monitor::monitor_read_only_process_ready_tasks, this);

	if (monitor_poll.event_loop(mysql_thread___monitor_read_only_timeout, args) == false) {
#ifdef DEBUG
		for (auto& mmsd : mmsds) {
			if (mmsd->mysql) {
				// DEBUG: Cleanup after failure - must destroy (not just close) to unregister
				// from debug tracking. If MYSQL* is reused later, conn_register() could
				// assert on finding the same pointer still in the tracking pool.
				My_Conn_Pool->destroy_mysql_connection(mmsd.get());
			}
		}
#endif
		return;
	}
}

bool MySQL_Monitor::monitor_group_replication_process_ready_tasks(const std::vector<MySQL_Monitor_State_Data*>& mmsds) {
	for (auto& mmsd : mmsds) {
		const auto task_result = mmsd->get_task_result();
		const bool stale_ip_timeout = task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT_STALE_IP;

		assert(task_result != MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_PENDING);

		if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_SUCCESS) {
			My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
		} else {

			if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT) {
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_GR_HEALTH_CHECK_TIMEOUT);
				proxy_error("Timeout on group replication health check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_groupreplication_healthcheck_timeout. Assuming viable_candidate=NO and read_only=YES\n", mmsd->hostname, mmsd->port, (mmsd->t2 - mmsd->t1) / 1000);
			} else {
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
#ifdef DEBUG
				proxy_error("Error after %lldms: server %s:%d , mmsd %p , MYSQL %p , FD %d : %s\n", (mmsd->t2 - mmsd->t1) / 1000, mmsd->hostname, mmsd->port, mmsd, mmsd->mysql, mmsd->mysql->net.fd, (mmsd->mysql_error_msg ? mmsd->mysql_error_msg : ""));
#else
				proxy_error("Got error: mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, (mmsd->mysql_error_msg ? mmsd->mysql_error_msg : ""));
#endif
			}
			My_Conn_Pool->destroy_mysql_connection(mmsd);
		}

		if (shutdown == true) {
			return false;
		}

		// TODO : complete this
		char buf[128];
		char* s = NULL;
		int l = strlen(mmsd->hostname);
		if (l < 110) {
			s = buf;
		} else {
			s = (char*)malloc(l + 16);
		}
		sprintf(s, "%s:%d", mmsd->hostname, mmsd->port);
		bool viable_candidate = false;
		bool read_only = true;
		int num_timeouts = 0;
		long long transactions_behind = -1;
		if (mmsd->interr == 0 && mmsd->result) {
			int num_fields = 0;
			int num_rows = 0;
			MYSQL_FIELD* fields = mysql_fetch_fields(mmsd->result);
			num_fields = mysql_num_fields(mmsd->result);
			num_rows = mysql_num_rows(mmsd->result);
			if (fields == NULL || num_fields != 3 || num_rows != 1) {
				proxy_error("mysql_fetch_fields returns NULL, or mysql_num_fields is incorrect. Server %s:%d . See bug #1994\n", mmsd->hostname, mmsd->port);
				if (mmsd->mysql_error_msg == NULL) {
					mmsd->mysql_error_msg = strdup("Unknown error");
				}
				continue;
			}
			MYSQL_ROW row = mysql_fetch_row(mmsd->result);
			if (row[0] && !strcasecmp(row[0], "YES")) {
				viable_candidate = true;
			}
			if (row[1] && !strcasecmp(row[1], "NO")) {
				read_only = false;
			}
			if (row[2]) {
				transactions_behind = atol(row[2]);
			}
		}
		if (mmsd->result) {
			// make sure it is clear
			mysql_free_result(mmsd->result);
			mmsd->result = NULL;
		}

		unsigned long long time_now = realtime_time();
		time_now = time_now - (mmsd->t2 - mmsd->t1);
		pthread_mutex_lock(&group_replication_mutex);
		//auto it =
		// TODO : complete this
		std::map<std::string, MyGR_monitor_node*>::iterator it2;
		it2 = Group_Replication_Hosts_Map.find(s);
		MyGR_monitor_node* node = NULL;
		if (it2 != Group_Replication_Hosts_Map.end()) {
			node = it2->second;
			node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2 - mmsd->t1), transactions_behind, viable_candidate, read_only, mmsd->mysql_error_msg);
		} else {
			node = new MyGR_monitor_node(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup);
			node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2 - mmsd->t1), transactions_behind, viable_candidate, read_only, mmsd->mysql_error_msg);
			Group_Replication_Hosts_Map.insert(std::make_pair(s, node));
		}

		if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT) {
			num_timeouts = node->get_timeout_count();
			proxy_warning("%s:%d : group replication health check timeout count %d. Max threshold %d.\n",
				mmsd->hostname, mmsd->port, num_timeouts, mmsd->max_transactions_behind_count);
		}

		// NOTE: Previously 'lag_counts' was only updated for 'read_only'
		// because 'writers' were never selected for being set 'OFFLINE' due to
		// replication lag. Since the change of this behavior to 'SHUNNING'
		// with replication lag, no matter it's 'read_only' value, 'lag_counts'
		// is computed everytime.
		int lag_counts = node->get_lag_behind_count(mmsd->max_transactions_behind);
		pthread_mutex_unlock(&group_replication_mutex);

		// NOTE: we update MyHGM outside the mutex group_replication_mutex
		if (stale_ip_timeout) {
			// Logged/counted; do not change GR state for stale DNS targets.
		} else if (mmsd->mysql_error_msg) { // there was an error checking the status of the server, surely we need to reconfigure GR
			if (num_timeouts == 0) {
				// it wasn't a timeout, reconfigure immediately
				MyHGM->update_group_replication_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, mmsd->mysql_error_msg);
			} else {
				// it was a timeout. Check if we are having consecutive timeout
				if (num_timeouts == mysql_thread___monitor_groupreplication_healthcheck_max_timeout_count) {
					proxy_error("Server %s:%d missed %d group replication checks. Number retries %d, Assuming offline\n",
						mmsd->hostname, mmsd->port, num_timeouts, num_timeouts);
					MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_GR_HEALTH_CHECKS_MISSED);
					MyHGM->update_group_replication_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, mmsd->mysql_error_msg);
				} else {
					// not enough timeout
				}
			}
		} else {
			if (viable_candidate == false) {
				MyHGM->update_group_replication_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char*)"viable_candidate=NO");
			} else {
				if (read_only == true) {
					MyHGM->update_group_replication_set_read_only(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char*)"read_only=YES");
				} else {
					// the node is a writer
					// TODO: for now we don't care about the number of writers
					MyHGM->update_group_replication_set_writer(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup);
				}

				// NOTE: Replication lag action should takes place **after** the
				// servers have been placed in the correct hostgroups, otherwise
				// during the reconfiguration of the servers due to 'update_group_replication_set_writer'
				// there would be a small window in which the 'SHUNNED' server
				// will be treat as 'ONLINE' letting some new connections to
				// take places, before it becomes 'SHUNNED' again.
				bool enable = true;
				if (lag_counts >= mysql_thread___monitor_groupreplication_max_transactions_behind_count) {
					enable = false;
				}
				MyHGM->group_replication_lag_action(
					mmsd->writer_hostgroup, mmsd->hostname, mmsd->port, lag_counts, read_only, enable
				);
			}
		}

		// clean up
		if (l < 110) {
		} else {
			free(s);
		}
	}

	return true;
}

void MySQL_Monitor::monitor_group_replication_async() {
	std::vector<std::unique_ptr<MySQL_Monitor_State_Data>> mmsds;

	pthread_mutex_lock(&group_replication_mutex);
	assert(Group_Replication_Hosts_resultset);
	mmsds.reserve(Group_Replication_Hosts_resultset->rows_count);
	Monitor_Poll monitor_poll(Group_Replication_Hosts_resultset->rows_count);

	for (std::vector<SQLite3_row*>::iterator it = Group_Replication_Hosts_resultset->rows.begin(); it != Group_Replication_Hosts_resultset->rows.end(); ++it) {
		const SQLite3_row* r = *it;
		bool rc_ping = server_responds_to_ping(r->fields[1], atoi(r->fields[2]));
		if (rc_ping) { // only if server is responding to pings
			std::unique_ptr<MySQL_Monitor_State_Data> mmsd(
				new MySQL_Monitor_State_Data(MON_GROUP_REPLICATION, r->fields[1], atoi(r->fields[2]), atoi(r->fields[3])));

			mmsd->writer_hostgroup = atoi(r->fields[0]);
			mmsd->writer_is_also_reader = atoi(r->fields[4]);
			mmsd->max_transactions_behind = atoi(r->fields[5]);
			mmsd->max_transactions_behind_count = mysql_thread___monitor_groupreplication_max_transactions_behind_count;
			mmsd->mondb = monitordb;
			mmsd->mysql = My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port, mmsd.get());

			if (mmsd->mysql) {
				// Register the task; don't dispatch it yet.
				monitor_poll.add((POLLIN|POLLOUT|POLLPRI), mmsd.get());
				mmsds.push_back(std::move(mmsd));
			} else {
				WorkItem<MySQL_Monitor_State_Data>* item =
					new WorkItem<MySQL_Monitor_State_Data>(mmsd.release(), monitor_group_replication_thread);
				queue->add(item);
			}
		}

		if (shutdown) {
			pthread_mutex_unlock(&group_replication_mutex);
			return;
		}
	}
	pthread_mutex_unlock(&group_replication_mutex);

	Monitor_Poll::Process_Ready_Task_Callback_Args args(5, 30, 50, &MySQL_Monitor::monitor_group_replication_process_ready_tasks, this);

	if (monitor_poll.event_loop(mysql_thread___monitor_groupreplication_healthcheck_timeout, args) == false) {
#ifdef DEBUG
		for (auto& mmsd : mmsds) {
			if (mmsd->mysql) {
				// DEBUG: Cleanup after failure - must destroy (not just close) to unregister
				// from debug tracking. If MYSQL* is reused later, conn_register() could
				// assert on finding the same pointer still in the tracking pool.
				My_Conn_Pool->destroy_mysql_connection(mmsd.get());
			}
		}
#endif
		return;
	}
}

bool MySQL_Monitor::monitor_group_replication_process_ready_tasks_2(
	const vector<MySQL_Monitor_State_Data*>& mmsds
) {
	for (MySQL_Monitor_State_Data* mmsd : mmsds) {
		const MySQL_Monitor_State_Data_Task_Result task_result = mmsd->get_task_result();
		assert(task_result != MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_PENDING);
		async_gr_mon_actions_handler(mmsd);
	}

	return true;
}

void MySQL_Monitor::monitor_gr_async_actions_handler(
	const vector<unique_ptr<MySQL_Monitor_State_Data>>& mmsds
) {
	Monitor_Poll monitor_poll(mmsds.size());

	for (const unique_ptr<MySQL_Monitor_State_Data>& mmsd : mmsds) {
		// Register the task; don't dispatch it yet.
		monitor_poll.add((POLLIN|POLLOUT|POLLPRI), mmsd.get());
	}

	Monitor_Poll::Process_Ready_Task_Callback_Args args(
		mmsds.size(), mmsds.size(), 100, &MySQL_Monitor::monitor_group_replication_process_ready_tasks_2, this
	);

	if (monitor_poll.event_loop(mysql_thread___monitor_groupreplication_healthcheck_timeout, args) == false) {
#ifdef DEBUG
		for (auto& mmsd : mmsds) {
			if (mmsd->mysql) {
				// DEBUG: Cleanup after failure - must destroy (not just close) to unregister
				// from debug tracking. If MYSQL* is reused later, conn_register() could
				// assert on finding the same pointer still in the tracking pool.
				My_Conn_Pool->destroy_mysql_connection(mmsd.get());
			}
		}
#endif
		return;
	}
}


bool MySQL_Monitor::monitor_replication_lag_process_ready_tasks(const std::vector<MySQL_Monitor_State_Data*>& mmsds) {
	std::list<replication_lag_server_t> mysql_servers;

	for (auto& mmsd : mmsds) {

		const auto task_result = mmsd->get_task_result();

		assert(task_result != MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_PENDING);

		string server_version = "";
		if (mmsd->mysql && mmsd->mysql->server_version) server_version = string(mmsd->mysql->server_version);

		if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_SUCCESS) {
			__sync_fetch_and_add(&replication_lag_check_OK, 1);
			My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
		} else {
			__sync_fetch_and_add(&replication_lag_check_ERR, 1);
			if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT) {
				proxy_error("Timeout on replication lag health check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_replication_lag_timeout.\n", mmsd->hostname, mmsd->port, (mmsd->t2 - mmsd->t1) / 1000);
			}
			else if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_FAILED) {
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
#ifdef DEBUG
				proxy_error("Error after %lldms: server %s:%d , mmsd %p , MYSQL %p , FD %d : %s\n", (mmsd->t2 - mmsd->t1) / 1000, mmsd->hostname, mmsd->port, mmsd, mmsd->mysql, mmsd->mysql->net.fd, (mmsd->mysql_error_msg ? mmsd->mysql_error_msg : ""));
#else
				proxy_error("Error after %lldms on server %s:%d : %s\n", (mmsd->t2 - mmsd->t1) / 1000, mmsd->hostname, mmsd->port, (mmsd->mysql_error_msg ? mmsd->mysql_error_msg : ""));
#endif
			}
			My_Conn_Pool->destroy_mysql_connection(mmsd);
		}

		if (shutdown == true) {
			return false;
		}

		if (strcasestr(server_version.c_str(), (const char *)SERVER_VERSION_READYSET) == NULL) {
			const char* query = (char*)"INSERT OR REPLACE INTO mysql_server_replication_lag_log VALUES (?1 , ?2 , ?3 , ?4 , ?5 , ?6)";
			auto [rc1, statement_unique] = mmsd->mondb->prepare_v2(query);
			ASSERT_SQLITE_OK(rc1, mmsd->mondb);
			sqlite3_stmt* statement = statement_unique.get();
			int rc;
			// 'replication_lag' to be feed to 'replication_lag_action'
			int repl_lag = -2;
			bool override_repl_lag = true;
			rc = (*proxy_sqlite3_bind_text)(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			rc = (*proxy_sqlite3_bind_int)(statement, 2, mmsd->port); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			unsigned long long time_now = realtime_time();
			time_now = time_now - (mmsd->t2 - mmsd->t1);
			rc = (*proxy_sqlite3_bind_int64)(statement, 3, time_now); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			rc = (*proxy_sqlite3_bind_int64)(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2 - mmsd->t1)); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			if (mmsd->interr == 0 && mmsd->result) {
				int num_fields = 0;
				int k = 0;
				MYSQL_FIELD* fields = NULL;
				int j = -1;
				num_fields = mysql_num_fields(mmsd->result);
				fields = mysql_fetch_fields(mmsd->result);
#ifdef TEST_REPLICATIONLAG
				if (fields && num_fields == 1)
#else
				if (
					fields && (
						(num_fields == 1 && mmsd->use_percona_heartbeat == true)
						||
						(num_fields > 30 && mmsd->use_percona_heartbeat == false)
						)
					) 
#endif
				{
					for (k = 0; k < num_fields; k++) {
						if (fields[k].name) {
							if (
								strcmp("Seconds_Behind_Master", fields[k].name)==0
								|| strcmp("Seconds_Behind_Source", fields[k].name)==0
							) {
								j = k;
							}
						}
					}
					if (j > -1) {
						MYSQL_ROW row = mysql_fetch_row(mmsd->result);
						if (row) {
							repl_lag = -1; // this is old behavior
							override_repl_lag = true;
							if (row[j]) { // if Seconds_Behind_Master is not NULL
								repl_lag = atoi(row[j]);
								override_repl_lag = false;
							} else {
								MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_SRV_NULL_REPLICATION_LAG);
							}
						}
					}
					if (/*repl_lag >= 0 ||*/ override_repl_lag == false) {
						rc = (*proxy_sqlite3_bind_int64)(statement, 5, repl_lag); ASSERT_SQLITE_OK(rc, mmsd->mondb);
					} else {
						rc = (*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
					}
				} else {
					proxy_error("mysql_fetch_fields returns NULL, or mysql_num_fields is incorrect. Server %s:%d . See bug #1994\n", mmsd->hostname, mmsd->port);
					rc = (*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
				}
				mysql_free_result(mmsd->result);
				mmsd->result = NULL;
			} else {
				rc = (*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
				// 'replication_lag_check' timed out, we set 'repl_lag' to '-3' to avoid server to be 're-enabled'.
				repl_lag = -3;
			}
			rc = (*proxy_sqlite3_bind_text)(statement, 6, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			SAFE_SQLITE3_STEP2(statement);
			rc = (*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			rc = (*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			//MyHGM->replication_lag_action(mmsd->hostgroup_id, mmsd->hostname, mmsd->port, repl_lag);
			mysql_servers.push_back( replication_lag_server_t { mmsd->hostgroup_id, mmsd->hostname, mmsd->port, repl_lag, override_repl_lag });
		} else { // readyset
			const char* query = (char*)"INSERT OR REPLACE INTO readyset_status_log VALUES (?1 , ?2 , ?3 , ?4 , ?5 , ?6)";
			auto [rc2, statement_unique2] = mmsd->mondb->prepare_v2(query);
			ASSERT_SQLITE_OK(rc2, mmsd->mondb);
			sqlite3_stmt* statement = statement_unique2.get();
			int rc;
			unordered_map<string,string> status_output = {};
			enum MySerStatus status = MYSQL_SERVER_STATUS_SHUNNED; // default status
			rc = (*proxy_sqlite3_bind_text)(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			rc = (*proxy_sqlite3_bind_int)(statement, 2, mmsd->port); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			unsigned long long time_now = realtime_time();
			time_now = time_now - (mmsd->t2 - mmsd->t1);
			rc = (*proxy_sqlite3_bind_int64)(statement, 3, time_now); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			rc = (*proxy_sqlite3_bind_int64)(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2 - mmsd->t1)); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			if (mmsd->interr == 0 && mmsd->result) {
				int num_fields=0;
				MYSQL_FIELD * fields=NULL;
				num_fields = mysql_num_fields(mmsd->result);
				fields = mysql_fetch_fields(mmsd->result);
				if ( fields && (num_fields == 2) ) {
					int num_rows = mysql_num_rows(mmsd->result);
					for (int i = 0; i < num_rows; i++) {
						MYSQL_ROW row = mysql_fetch_row(mmsd->result);
						string Variable_name = string(row[0]);
						string Value = (row[1] == NULL ? string("") : string(row[1]) );
						status_output[Variable_name] = Value;
						if (Variable_name == "Status") {
							if (strcasecmp(Value.c_str(), (const char *)"Online") == 0) {
								status = MYSQL_SERVER_STATUS_ONLINE; // set to ONLINE
							} else if (strncasecmp(Value.c_str(), (const char *)"Maintenance", strlen("Maintenance")) == 0) {
								status = MYSQL_SERVER_STATUS_OFFLINE_SOFT; // set to OFFLINE_SOFT
							} else {
								status = MYSQL_SERVER_STATUS_SHUNNED; // set to SHUNNED
							}
						}
					}
					nlohmann::json json_output = status_output; // directly assign the map to the json object
					std::string json_string = json_output.dump();
					rc=(*proxy_sqlite3_bind_text)(statement, 5, json_string.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
				} else {
					proxy_error("mysql_fetch_fields returns NULL, or mysql_num_fields is incorrect. Server %s:%d . See bug #1994\n", mmsd->hostname, mmsd->port);
					rc=(*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
				}

				mysql_free_result(mmsd->result);
				mmsd->result=NULL;
			} else {
				rc=(*proxy_sqlite3_bind_null)(statement, 5); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			}
			rc=(*proxy_sqlite3_bind_text)(statement, 6, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			SAFE_SQLITE3_STEP2(statement);
			rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, mmsd->mondb);
			MyHGM->set_Readyset_status(mmsd->hostname, mmsd->port, status);
		}
	}

	//executing replication lag action
	MyHGM->replication_lag_action(mysql_servers);

	return true;
}

void MySQL_Monitor::monitor_replication_lag_async(SQLite3_result* resultset) {
	assert(resultset);

	std::vector<std::unique_ptr<MySQL_Monitor_State_Data>> mmsds;
	mmsds.reserve(resultset->rows_count);
	Monitor_Poll monitor_poll(resultset->rows_count);

	for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
		const SQLite3_row* r = *it;
		bool rc_ping = server_responds_to_ping(r->fields[1], atoi(r->fields[2]));
		if (rc_ping) { // only if server is responding to pings

			std::unique_ptr<MySQL_Monitor_State_Data> mmsd(
				new MySQL_Monitor_State_Data(MySQL_Monitor_State_Data_Task_Type::MON_REPLICATION_LAG, 
					r->fields[1], atoi(r->fields[2]), atoi(r->fields[4]), atoi(r->fields[0])));

			mmsd->mondb = monitordb;
			mmsd->mysql = My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port, mmsd.get());

			if (mmsd->mysql) {
				// Register the task; don't dispatch it yet.
				monitor_poll.add((POLLIN|POLLOUT|POLLPRI), mmsd.get());
				mmsds.push_back(std::move(mmsd));
			} else {
				WorkItem<MySQL_Monitor_State_Data>* item =
					new WorkItem<MySQL_Monitor_State_Data>(mmsd.release(), monitor_replication_lag_thread);
				queue->add(item);
			}
		}

		if (shutdown) return;
	}

	Monitor_Poll::Process_Ready_Task_Callback_Args args(5, 30, 50, &MySQL_Monitor::monitor_replication_lag_process_ready_tasks, this);

	if (monitor_poll.event_loop(mysql_thread___monitor_replication_lag_timeout, args) == false) {
#ifdef DEBUG
		for (auto& mmsd : mmsds) {
			if (mmsd->mysql) {
				// DEBUG: Cleanup after failure - must destroy (not just close) to unregister
				// from debug tracking. If MYSQL* is reused later, conn_register() could
				// assert on finding the same pointer still in the tracking pool.
				My_Conn_Pool->destroy_mysql_connection(mmsd.get());
			}
		}
#endif
		return;
	}
}

bool MySQL_Monitor::monitor_galera_process_ready_tasks(const std::vector<MySQL_Monitor_State_Data*>& mmsds) {
	for (auto& mmsd : mmsds) {
		const auto task_result = mmsd->get_task_result();
		const bool stale_ip_timeout = task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT_STALE_IP;

		assert(task_result != MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_PENDING);

		if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_SUCCESS) {

#ifdef TEST_GALERA
			if (rand() % 3 == 0) { // drop the connection once every 3 checks
				My_Conn_Pool->destroy_mysql_connection(mmsd);
			} else {
				My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
			}
#else
			My_Conn_Pool->put_connection(mmsd->hostname, mmsd);
#endif
		} else {
			if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT) {
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_GALERA_HEALTH_CHECK_CONN_TIMEOUT);
				proxy_error("Timeout on Galera health check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_galera_healthcheck_timeout.\n", mmsd->hostname, mmsd->port, (mmsd->t2 - mmsd->t1) / 1000);
			}
			else if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_FAILED) {
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, mysql_errno(mmsd->mysql));
#ifdef DEBUG
				proxy_error("Error after %lldms: server %s:%d , mmsd %p , MYSQL %p , FD %d : %s\n", (mmsd->t2 - mmsd->t1) / 1000, mmsd->hostname, mmsd->port, mmsd, mmsd->mysql, mmsd->mysql->net.fd, (mmsd->mysql_error_msg ? mmsd->mysql_error_msg : ""));
#else
				proxy_error("Got error: mmsd %p , MYSQL %p , FD %d : %s\n", mmsd, mmsd->mysql, mmsd->mysql->net.fd, (mmsd->mysql_error_msg ? mmsd->mysql_error_msg : ""));
#endif
			}
			My_Conn_Pool->destroy_mysql_connection(mmsd);
		}

		if (shutdown == true) {
			return false;
		}

		// TODO : complete this
		char buf[128];
		char* s = NULL;
		int l = strlen(mmsd->hostname);
		if (l < 110) {
			s = buf;
		} else {
			s = (char*)malloc(l + 16);
		}
		sprintf(s, "%s:%d", mmsd->hostname, mmsd->port);
		bool primary_partition = false;
		bool read_only = true;
		bool wsrep_desync = true;
		int wsrep_local_state = 0;
		bool wsrep_reject_queries = true;
		bool wsrep_sst_donor_rejects_queries = true;
		long long wsrep_local_recv_queue = 0;
		bool pxc_maint_mode = false;
		int num_timeouts = 0;
		MYSQL_FIELD* fields = NULL;
		if (mmsd->interr == 0 && mmsd->result) {
			int num_fields = 0;
			int num_rows = 0;
			num_fields = mysql_num_fields(mmsd->result);
			fields = mysql_fetch_fields(mmsd->result);
			num_rows = mysql_num_rows(mmsd->result);
			if (fields == NULL || num_fields != 8 || num_rows != 1) {
				proxy_error("mysql_fetch_fields returns NULL, or mysql_num_fields is incorrect. Server %s:%d . See bug #1994\n", mmsd->hostname, mmsd->port);
				if (mmsd->mysql_error_msg == NULL) {
					mmsd->mysql_error_msg = strdup("Unknown error");
				}

				if (mmsd->result) {
					mysql_free_result(mmsd->result);
					mmsd->result = NULL;
				}
				continue;
			}
			MYSQL_ROW row = mysql_fetch_row(mmsd->result);
			if (row[0]) {
				wsrep_local_state = atoi(row[0]);
			}
			if (row[1]) {
				if (!strcasecmp(row[1], "NO") || !strcasecmp(row[1], "OFF") || !strcasecmp(row[1], "0")) {
					read_only = false;
				}
			}
			if (row[2]) {
				wsrep_local_recv_queue = atoll(row[2]);
			}
			if (row[3]) {
				if (!strcasecmp(row[3], "NO") || !strcasecmp(row[3], "OFF") || !strcasecmp(row[3], "0")) {
					wsrep_desync = false;
				}
			}
			if (row[4]) {
				if (!strcasecmp(row[4], "NONE")) {
					wsrep_reject_queries = false;
				}
			}
			if (row[5]) {
				if (!strcasecmp(row[5], "NO") || !strcasecmp(row[5], "OFF") || !strcasecmp(row[5], "0")) {
					wsrep_sst_donor_rejects_queries = false;
				}
			}
			if (row[6]) {
				if (!strcasecmp(row[6], "Primary")) {
					primary_partition = true;
				}
			}
			if (row[7]) {
				std::string s(row[7]);
				std::transform(s.begin(), s.end(), s.begin(), ::toupper);
				if (!strncmp("DISABLED", s.c_str(), 8)) {
					pxc_maint_mode = false;
				} else {
					pxc_maint_mode = true;
				}
			}
			mysql_free_result(mmsd->result);
			mmsd->result = NULL;
		}

		unsigned long long time_now = realtime_time();
		time_now = time_now - (mmsd->t2 - mmsd->t1);
		pthread_mutex_lock(&galera_mutex);

		// TODO : complete this
		std::map<std::string, Galera_monitor_node*>::iterator it2;
		it2 = Galera_Hosts_Map.find(s);
		Galera_monitor_node* node = NULL;
		if (it2 != Galera_Hosts_Map.end()) {
			node = it2->second;
			node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2 - mmsd->t1), wsrep_local_recv_queue, primary_partition, read_only, wsrep_local_state, wsrep_desync, wsrep_reject_queries, wsrep_sst_donor_rejects_queries, pxc_maint_mode, mmsd->mysql_error_msg);
		} else {
			node = new Galera_monitor_node(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup);
			node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2 - mmsd->t1), wsrep_local_recv_queue, primary_partition, read_only, wsrep_local_state, wsrep_desync, wsrep_reject_queries, wsrep_sst_donor_rejects_queries, pxc_maint_mode, mmsd->mysql_error_msg);
			Galera_Hosts_Map.insert(std::make_pair(s, node));
		}
		if (task_result == MySQL_Monitor_State_Data_Task_Result::TASK_RESULT_TIMEOUT) {
			// it was a timeout . Let's count the number of consecutive timeouts
			int max_num_timeout = 10;
			if (mysql_thread___monitor_galera_healthcheck_max_timeout_count < max_num_timeout) {
				max_num_timeout = mysql_thread___monitor_galera_healthcheck_max_timeout_count;
			}
			unsigned long long start_times[max_num_timeout];
			bool timeouts[max_num_timeout];
			for (int i = 0; i < max_num_timeout; i++) {
				start_times[i] = 0;
				timeouts[i] = false;
			}
			for (int i = 0; i < Galera_Nentries; i++) {
				if (node->last_entries[i].start_time) {
					int smallidx = 0;
					for (int j = 0; j < max_num_timeout; j++) {
						//find the smaller value
						if (j != smallidx) {
							if (start_times[j] < start_times[smallidx]) {
								smallidx = j;
							}
						}
					}
					if (start_times[smallidx] < node->last_entries[i].start_time) {
						start_times[smallidx] = node->last_entries[i].start_time;
						timeouts[smallidx] = false;
						if (node->last_entries[i].error) {
							if (strncasecmp(node->last_entries[i].error, (char*)"timeout", 7) == 0) {
								timeouts[smallidx] = true;
							}
						}
					}
				}
			}
			for (int i = 0; i < max_num_timeout; i++) {
				if (timeouts[i]) {
					num_timeouts++;
				}
			}
		}

		pthread_mutex_unlock(&galera_mutex);

		// NOTE: we update MyHGM outside the mutex galera_mutex
		if (stale_ip_timeout) {
			// Logged/counted; do not change Galera state for stale DNS targets.
		} else if (mmsd->mysql_error_msg) { // there was an error checking the status of the server, surely we need to reconfigure Galera
			if (num_timeouts == 0) {
				// it wasn't a timeout, reconfigure immediately
				MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, mmsd->mysql_error_msg);
			} else {
				// it was a timeout. Check if we are having consecutive timeout
				if (num_timeouts == mysql_thread___monitor_galera_healthcheck_max_timeout_count) {
					proxy_error("Server %s:%d missed %d Galera checks. Assuming offline\n", mmsd->hostname, mmsd->port, num_timeouts);
					MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, mmsd->hostgroup_id, mmsd->hostname, mmsd->port, ER_PROXYSQL_GALERA_HEALTH_CHECKS_MISSED);
					MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, mmsd->mysql_error_msg);
				} else {
					// not enough timeout
				}
			}
		} else {
			if (fields) { // if we didn't get any error, but fileds is NULL, we are likely hitting bug #1994
				if (primary_partition == false || wsrep_desync == true || (wsrep_local_state != 4 && (wsrep_local_state != 2 || wsrep_sst_donor_rejects_queries))) {
					if (primary_partition == false) {
						MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char*)"primary_partition=NO");
					} else {
						if (wsrep_desync == true) {
							MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char*)"wsrep_desync=YES");
						} else {
							char msg[80];
							snprintf(msg, sizeof(msg), "wsrep_local_state=%d", wsrep_local_state);
							MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, msg);
						}
					}
				} else {

					if (wsrep_reject_queries) {
						MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char*)"wsrep_reject_queries=true");
					} else {
						if (pxc_maint_mode) {
							MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char*)"pxc_maint_mode=YES", true);
						} else {
							if (read_only == true) {
								if (wsrep_local_recv_queue > mmsd->max_transactions_behind) {
									MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char*)"slave is lagging");
								} else {
									MyHGM->update_galera_set_read_only(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char*)"read_only=YES");
								}
							} else {
								// the node is a writer
								// TODO: for now we don't care about the number of writers
								MyHGM->update_galera_set_writer(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup);
							}
						}
					}
				}
			} else {
				proxy_error("mysql_fetch_fields returns NULL. Server %s:%d . See bug #1994\n", mmsd->hostname, mmsd->port);
			}
		}

		// clean up
		if (l < 110) {
		} else {
			free(s);
		}

		if (mmsd->result) {
			mysql_free_result(mmsd->result);
			mmsd->result = NULL;
		}
	}

	return true;
}

void MySQL_Monitor::monitor_galera_async() {

	std::vector<std::unique_ptr<MySQL_Monitor_State_Data>> mmsds;
	std::set<std::string> checked_servers;
	pthread_mutex_lock(&galera_mutex);
	assert(Galera_Hosts_resultset);
	mmsds.reserve(Galera_Hosts_resultset->rows_count);
	Monitor_Poll monitor_poll(Galera_Hosts_resultset->rows_count);

	for (std::vector<SQLite3_row*>::iterator it = Galera_Hosts_resultset->rows.begin(); it != Galera_Hosts_resultset->rows.end(); ++it) {
		const SQLite3_row* r = *it;
		// r->fields[0] = writer_hostgroup, r->fields[1] = hostname, r->fields[2] = port
		auto ret = checked_servers.insert(std::string(r->fields[0]) + ":" + std::string(r->fields[1]) + ":" + std::string(r->fields[2]));
		if (ret.second == false) // duplicate server entry
			continue;

		bool rc_ping = server_responds_to_ping(r->fields[1], atoi(r->fields[2]));
		if (rc_ping) { // only if server is responding to pings

			std::unique_ptr<MySQL_Monitor_State_Data> mmsd(new MySQL_Monitor_State_Data(MySQL_Monitor_State_Data_Task_Type::MON_GALERA,
				r->fields[1], atoi(r->fields[2]), atoi(r->fields[3])));
			
			mmsd->mysql = My_Conn_Pool->get_connection(r->fields[1], atoi(r->fields[2]), NULL);
			mmsd->writer_hostgroup = atoi(r->fields[0]);
			mmsd->writer_is_also_reader = atoi(r->fields[4]);
			mmsd->max_transactions_behind = atoi(r->fields[5]);
			mmsd->mondb = monitordb;

			if (mmsd->mysql) {
				// Register the task; don't dispatch it yet.
				monitor_poll.add((POLLIN|POLLOUT|POLLPRI), mmsd.get());
				mmsds.push_back(std::move(mmsd));
			} else {
				WorkItem<MySQL_Monitor_State_Data>* item =
					new WorkItem<MySQL_Monitor_State_Data>(mmsd.release(), monitor_galera_thread);
				queue->add(item);
			}
		}

		if (shutdown) {
			pthread_mutex_unlock(&galera_mutex);
			return;
		}
	}
	pthread_mutex_unlock(&galera_mutex);

	Monitor_Poll::Process_Ready_Task_Callback_Args args(5, 30, 50, &MySQL_Monitor::monitor_galera_process_ready_tasks, this);

	if (monitor_poll.event_loop(mysql_thread___monitor_galera_healthcheck_timeout, args) == false) {
#ifdef DEBUG
		for (auto& mmsd : mmsds) {
			if (mmsd->mysql) {
				// DEBUG: Cleanup after failure - must destroy (not just close) to unregister
				// from debug tracking. If MYSQL* is reused later, conn_register() could
				// assert on finding the same pointer still in the tracking pool.
				My_Conn_Pool->destroy_mysql_connection(mmsd.get());
			}
		}
#endif
		return;
	}
}

template class WorkItem<MySQL_Monitor_State_Data>;
template class WorkItem<DNS_Resolve_Data>;
