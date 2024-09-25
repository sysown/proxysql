#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "MySQL_HostGroups_Manager.h"
#include "proxysql.h"
#include "cpp.h"

#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"

#include <memory>
#include <pthread.h>
#include <string>

#include "prometheus/counter.h"
#include "prometheus/detail/builder.h"
#include "prometheus/family.h"
#include "prometheus/gauge.h"

#include "prometheus_helpers.h"
#include "proxysql_utils.h"

#define char_malloc (char *)malloc
#define itostr(__s, __i)  { __s=char_malloc(32); sprintf(__s, "%lld", __i); }

#include "thread.h"
#include "wqueue.h"

#include "ev.h"

#include <functional>
#include <mutex>
#include <type_traits>

using std::function;


#define SAFE_SQLITE3_STEP(_stmt) do {\
  do {\
    rc=(*proxy_sqlite3_step)(_stmt);\
    if (rc!=SQLITE_DONE) {\
      assert(rc==SQLITE_LOCKED);\
      usleep(100);\
    }\
  } while (rc!=SQLITE_DONE);\
} while (0)

extern ProxySQL_Admin *GloAdmin;

extern MySQL_Threads_Handler *GloMTH;

extern MySQL_Monitor *GloMyMon;

class MySrvConnList;
class MySrvC;
class MySrvList;
class MyHGC;

const int MYSQL_ERRORS_STATS_FIELD_NUM = 11;

struct ev_io * new_connector(char *address, uint16_t gtid_port, uint16_t mysql_port);
void * GTID_syncer_run();

static int wait_for_mysql(MYSQL *mysql, int status) {
	struct pollfd pfd;
	int timeout, res;

	pfd.fd = mysql_get_socket(mysql);
	pfd.events =
		(status & MYSQL_WAIT_READ ? POLLIN : 0) |
		(status & MYSQL_WAIT_WRITE ? POLLOUT : 0) |
		(status & MYSQL_WAIT_EXCEPT ? POLLPRI : 0);
	timeout = 1;
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

/**
 * @brief Helper function used to try to extract a value from the JSON field 'servers_defaults'.
 *
 * @param j JSON object constructed from 'servers_defaults' field.
 * @param hid Hostgroup for which the 'servers_defaults' is defined in 'mysql_hostgroup_attributes'. Used for
 *  error logging.
 * @param key The key for the value to be extracted.
 * @param val_check A validation function, checks if the value is within a expected range.
 *
 * @return The value extracted from the supplied JSON. In case of error '-1', and error cause is logged.
 */
template <typename T, typename std::enable_if<std::is_integral<T>::value, bool>::type = true>
T j_get_srv_default_int_val(
	const json& j, uint32_t hid, const string& key, const function<bool(T)>& val_check
) {
	if (j.find(key) != j.end()) {
		const json::value_t val_type = j[key].type();
		const char* type_name = j[key].type_name();

		if (val_type == json::value_t::number_integer || val_type == json::value_t::number_unsigned) {
			T val = j[key].get<T>();

			if (val_check(val)) {
				return val;
			} else {
				proxy_error(
					"Invalid value %ld supplied for 'mysql_hostgroup_attributes.servers_defaults.%s' for hostgroup %d."
						" Value NOT UPDATED.\n",
					static_cast<int64_t>(val), key.c_str(), hid
				);
			}
		} else {
			proxy_error(
				"Invalid type '%s'(%hhu) supplied for 'mysql_hostgroup_attributes.servers_defaults.%s' for hostgroup %d."
					" Value NOT UPDATED.\n",
				type_name, static_cast<std::uint8_t>(val_type), key.c_str(), hid
			);
		}
	}

	return static_cast<T>(-1);
}


//static void * HGCU_thread_run() {
static void * HGCU_thread_run() {
	PtrArray *conn_array=new PtrArray();
	set_thread_name("MyHGCU");
	while(1) {
		MySQL_Connection *myconn= NULL;
		myconn = (MySQL_Connection *)MyHGM->queue.remove();
		if (myconn==NULL) {
			// intentionally exit immediately
			delete conn_array;
			return NULL;
		}
		conn_array->add(myconn);
		while (MyHGM->queue.size()) {
			myconn=(MySQL_Connection *)MyHGM->queue.remove();
			if (myconn==NULL) {
				delete conn_array;
				return NULL;
			}
			conn_array->add(myconn);
		}
		unsigned int l=conn_array->len;
		int *errs=(int *)malloc(sizeof(int)*l);
		int *statuses=(int *)malloc(sizeof(int)*l);
		my_bool *ret=(my_bool *)malloc(sizeof(my_bool)*l);
		int i;
		for (i=0;i<(int)l;i++) {
			myconn->reset();
			MyHGM->increase_reset_counter();
			myconn=(MySQL_Connection *)conn_array->index(i);
			if (myconn->mysql->net.pvio && myconn->mysql->net.fd && myconn->mysql->net.buff) {
				MySQL_Connection_userinfo *userinfo = myconn->userinfo;
				char *auth_password = NULL;
				if (userinfo->password) {
					if (userinfo->password[0]=='*') { // we don't have the real password, let's pass sha1
						auth_password=userinfo->sha1_pass;
					} else {
						auth_password=userinfo->password;
					}
				}
				//async_exit_status = mysql_change_user_start(&ret_bool,mysql,_ui->username, auth_password, _ui->schemaname);
				// we first reset the charset to a default one.
				// this to solve the problem described here:
				// https://github.com/sysown/proxysql/pull/3249#issuecomment-761887970
				if (myconn->mysql->charset->nr >= 255)
					mysql_options(myconn->mysql, MYSQL_SET_CHARSET_NAME, myconn->mysql->charset->csname);
				statuses[i]=mysql_change_user_start(&ret[i], myconn->mysql, myconn->userinfo->username, auth_password, myconn->userinfo->schemaname);
				if (myconn->mysql->net.pvio==NULL || myconn->mysql->net.fd==0 || myconn->mysql->net.buff==NULL) {
					statuses[i]=0; ret[i]=1;
				}
			} else {
				statuses[i]=0;
				ret[i]=1;
			}
		}
		for (i=0;i<(int)conn_array->len;i++) {
			if (statuses[i]==0) {
				myconn=(MySQL_Connection *)conn_array->remove_index_fast(i);
				if (!ret[i]) {
					MyHGM->push_MyConn_to_pool(myconn);
				} else {
					myconn->send_quit=false;
					MyHGM->destroy_MyConn_from_pool(myconn);
				}
				statuses[i]=statuses[conn_array->len];
				ret[i]=ret[conn_array->len];
				i--;
			}
		}
		unsigned long long now=monotonic_time();
		while (conn_array->len && ((monotonic_time() - now) < 1000000)) {
			usleep(50);
			for (i=0;i<(int)conn_array->len;i++) {
				myconn=(MySQL_Connection *)conn_array->index(i);
				if (myconn->mysql->net.pvio && myconn->mysql->net.fd && myconn->mysql->net.buff) {
					statuses[i]=wait_for_mysql(myconn->mysql, statuses[i]);
					if (myconn->mysql->net.pvio && myconn->mysql->net.fd && myconn->mysql->net.buff) {
						if ((statuses[i] & MYSQL_WAIT_TIMEOUT) == 0) {
							statuses[i]=mysql_change_user_cont(&ret[i], myconn->mysql, statuses[i]);
							if (myconn->mysql->net.pvio==NULL || myconn->mysql->net.fd==0 || myconn->mysql->net.buff==NULL ) {
								statuses[i]=0; ret[i]=1;
							}
						}
					} else {
						statuses[i]=0; ret[i]=1;
					}
				} else {
					statuses[i]=0; ret[i]=1;
				}
			}
			for (i=0;i<(int)conn_array->len;i++) {
				if (statuses[i]==0) {
					myconn=(MySQL_Connection *)conn_array->remove_index_fast(i);
					if (!ret[i]) {
						myconn->reset();
						MyHGM->push_MyConn_to_pool(myconn);
					} else {
						myconn->send_quit=false;
						MyHGM->destroy_MyConn_from_pool(myconn);
					}
					statuses[i]=statuses[conn_array->len];
					ret[i]=ret[conn_array->len];
					i--;
				}
			}
		}
		while (conn_array->len) {
			// we reached here, and there are still connections
			myconn=(MySQL_Connection *)conn_array->remove_index_fast(0);
			myconn->send_quit=false;
			MyHGM->destroy_MyConn_from_pool(myconn);
		}
		free(statuses);
		free(errs);
		free(ret);
	}
	delete conn_array;
}


using metric_name = std::string;
using metric_help = std::string;
using metric_tags = std::map<std::string, std::string>;

using hg_counter_tuple =
	std::tuple<
		p_hg_counter::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using hg_gauge_tuple =
	std::tuple<
		p_hg_gauge::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using hg_dyn_counter_tuple =
	std::tuple<
		p_hg_dyn_counter::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using hg_dyn_gauge_tuple =
	std::tuple<
		p_hg_dyn_gauge::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using hg_counter_vector = std::vector<hg_counter_tuple>;
using hg_gauge_vector = std::vector<hg_gauge_tuple>;
using hg_dyn_counter_vector = std::vector<hg_dyn_counter_tuple>;
using hg_dyn_gauge_vector = std::vector<hg_dyn_gauge_tuple>;

/**
 * @brief Metrics map holding the metrics for the 'MySQL_HostGroups_Manager' module.
 *
 * @note Many metrics in this map, share a common "id name", because
 *  they differ only by label, because of this, HELP is shared between
 *  them. For better visual identification of this groups they are
 *  sepparated using a line separator comment.
 */
const std::tuple<
	hg_counter_vector,
	hg_gauge_vector,
	hg_dyn_counter_vector,
	hg_dyn_gauge_vector
>
hg_metrics_map = std::make_tuple(
	hg_counter_vector {
		std::make_tuple (
			p_hg_counter::servers_table_version,
			"proxysql_servers_table_version_total",
			"Number of times the \"servers_table\" have been modified.",
			metric_tags {}
		),

		// ====================================================================
		std::make_tuple (
			p_hg_counter::server_connections_created,
			"proxysql_server_connections_total",
			"Total number of server connections (created|delayed|aborted).",
			metric_tags {
				{ "status", "created" }
			}
		),
		std::make_tuple (
			p_hg_counter::server_connections_delayed,
			"proxysql_server_connections_total",
			"Total number of server connections (created|delayed|aborted).",
			metric_tags {
				{ "status", "delayed" }
			}
		),
		std::make_tuple (
			p_hg_counter::server_connections_aborted,
			"proxysql_server_connections_total",
			"Total number of server connections (created|delayed|aborted).",
			metric_tags {
				{ "status", "aborted" }
			}
		),
		// ====================================================================

		// ====================================================================
		std::make_tuple (
			p_hg_counter::client_connections_created,
			"proxysql_client_connections_total",
			"Total number of client connections created.",
			metric_tags {
				{ "status", "created" }
			}
		),
		std::make_tuple (
			p_hg_counter::client_connections_sha2cached,
			"proxysql_client_connections_sha2cached_total",
			"Total number of attempted client connections with known cached passwords.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::client_connections_aborted,
			"proxysql_client_connections_total",
			"Total number of client failed connections (or closed improperly).",
			metric_tags {
				{ "status", "aborted" }
			}
		),
		// ====================================================================

		std::make_tuple (
			p_hg_counter::com_autocommit,
			"proxysql_com_autocommit_total",
			"Total queries autocommited.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::com_autocommit_filtered,
			"proxysql_com_autocommit_filtered_total",
			"Total queries filtered autocommit.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::com_rollback,
			"proxysql_com_rollback_total",
			"Total queries rollbacked.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::com_rollback_filtered,
			"proxysql_com_rollback_filtered_total",
			"Total queries filtered rollbacked.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::com_backend_change_user,
			"proxysql_com_backend_change_user_total",
			"Total CHANGE_USER queries backend.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::com_backend_init_db,
			"proxysql_com_backend_init_db_total",
			"Total queries backend INIT DB.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::com_backend_set_names,
			"proxysql_com_backend_set_names_total",
			"Total queries backend SET NAMES.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::com_frontend_init_db,
			"proxysql_com_frontend_init_db_total",
			"Total INIT DB queries frontend.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::com_frontend_set_names,
			"proxysql_com_frontend_set_names_total",
			"Total SET NAMES frontend queries.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::com_frontend_use_db,
			"proxysql_com_frontend_use_db_total",
			"Total USE DB queries frontend.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::com_commit_cnt,
			"proxysql_com_commit_cnt_total",
			"Total queries commit.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::com_commit_cnt_filtered,
			"proxysql_com_commit_cnt_filtered_total",
			"Total queries commit filtered.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::selects_for_update__autocommit0,
			"proxysql_selects_for_update__autocommit0_total",
			"Total queries that are SELECT for update or equivalent.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::access_denied_wrong_password,
			"proxysql_access_denied_wrong_password_total",
			"Total access denied \"wrong password\".",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::access_denied_max_connections,
			"proxysql_access_denied_max_connections_total",
			"Total access denied \"max connections\".",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::access_denied_max_user_connections,
			"proxysql_access_denied_max_user_connections_total",
			"Total access denied \"max user connections\".",
			metric_tags {}
		),

		// ====================================================================
		std::make_tuple (
			p_hg_counter::myhgm_myconnpool_get,
			"proxysql_myhgm_myconnpool_get_total",
			"The number of requests made to the connection pool.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::myhgm_myconnpool_get_ok,
			"proxysql_myhgm_myconnpool_get_ok_total",
			"The number of successful requests to the connection pool (i.e. where a connection was available).",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::myhgm_myconnpool_get_ping,
			"proxysql_myhgm_myconnpool_get_ping_total",
			"The number of connections that were taken from the pool to run a ping to keep them alive.",
			metric_tags {}
		),
		// ====================================================================

		std::make_tuple (
			p_hg_counter::myhgm_myconnpool_push,
			"proxysql_myhgm_myconnpool_push_total",
			"The number of connections returned to the connection pool.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::myhgm_myconnpool_reset,
			"proxysql_myhgm_myconnpool_reset_total",
			"The number of connections that have been reset / re-initialized using \"COM_CHANGE_USER\"",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_counter::myhgm_myconnpool_destroy,
			"proxysql_myhgm_myconnpool_destroy_total",
			"The number of connections considered unhealthy and therefore closed.",
			metric_tags {}
		),

		// ====================================================================

		std::make_tuple (
			p_hg_counter::auto_increment_delay_multiplex,
			"proxysql_myhgm_auto_increment_multiplex_total",
			"The number of times that 'auto_increment_delay_multiplex' has been triggered.",
			metric_tags {}
		),
	},
	// prometheus gauges
	hg_gauge_vector {
		std::make_tuple (
			p_hg_gauge::server_connections_connected,
			"proxysql_server_connections_connected",
			"Backend connections that are currently connected.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_gauge::client_connections_connected,
			"proxysql_client_connections_connected",
			"Client connections that are currently connected.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_gauge::client_connections_connected_prim,
			"proxysql_client_connections_connected_primary",
			"Client connections that are currently connected using primary password.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_gauge::client_connections_connected_addl,
			"proxysql_client_connections_connected_additional",
			"Client connections that are currently connected using additional password.",
			metric_tags {}
		)
	},
	// prometheus dynamic counters
	hg_dyn_counter_vector {
		// connection_pool
		// ====================================================================

		// ====================================================================
		std::make_tuple (
			p_hg_dyn_counter::conn_pool_bytes_data_recv,
			"proxysql_connpool_data_bytes_total",
			"Amount of data (sent|recv) from the backend, excluding metadata.",
			metric_tags {
				{ "traffic_flow", "recv" }
			}
		),
		std::make_tuple (
			p_hg_dyn_counter::conn_pool_bytes_data_sent,
			"proxysql_connpool_data_bytes_total",
			"Amount of data (sent|recv) from the backend, excluding metadata.",
			metric_tags {
				{ "traffic_flow", "sent" }
			}
		),
		// ====================================================================

		// ====================================================================
		std::make_tuple (
			p_hg_dyn_counter::connection_pool_conn_err,
			"proxysql_connpool_conns_total",
			"How many connections have been tried to be established.",
			metric_tags {
				{ "status", "err" }
			}
		),
		std::make_tuple (
			p_hg_dyn_counter::connection_pool_conn_ok,
			"proxysql_connpool_conns_total",
			"How many connections have been tried to be established.",
			metric_tags {
				{ "status", "ok" }
			}
		),
		// ====================================================================

		std::make_tuple (
			p_hg_dyn_counter::connection_pool_queries,
			"proxysql_connpool_conns_queries_total",
			"The number of queries routed towards this particular backend server.",
			metric_tags {}
		),
		// gtid
		std::make_tuple (
			p_hg_dyn_counter::gtid_executed,
			"proxysql_gtid_executed_total",
			"Tracks the number of executed gtid per host and port.",
			metric_tags {}
		),
		// mysql_error
		std::make_tuple (
			p_hg_dyn_counter::proxysql_mysql_error,
			"proxysql_mysql_error_total",
			"Tracks the mysql errors generated by proxysql.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_dyn_counter::mysql_error,
			"mysql_error_total",
			"Tracks the mysql errors encountered.",
			metric_tags {}
		)
	},
	// prometheus dynamic gauges
	hg_dyn_gauge_vector {
		std::make_tuple (
			p_hg_dyn_gauge::connection_pool_conn_free,
			"proxysql_connpool_conns",
			"How many backend connections are currently (free|used).",
			metric_tags {
				{ "status", "free" }
			}
		),
		std::make_tuple (
			p_hg_dyn_gauge::connection_pool_conn_used,
			"proxysql_connpool_conns",
			"How many backend connections are currently (free|used).",
			metric_tags {
				{ "status", "used" }
			}
		),
		std::make_tuple (
			p_hg_dyn_gauge::connection_pool_latency_us,
			"proxysql_connpool_conns_latency_us",
			"The currently ping time in microseconds, as reported from Monitor.",
			metric_tags {}
		),
		std::make_tuple (
			p_hg_dyn_gauge::connection_pool_status,
			"proxysql_connpool_conns_status",
			"The status of the backend server (1 - ONLINE, 2 - SHUNNED, 3 - OFFLINE_SOFT, 4 - OFFLINE_HARD, 5 - SHUNNED_REPLICATION_LAG).",
			metric_tags {}
		)
	}
);

MySQL_HostGroups_Manager::MySQL_HostGroups_Manager() {
	status.client_connections=0;
	status.client_connections_prim_pass=0;
	status.client_connections_addl_pass=0;
	status.client_connections_aborted=0;
	status.client_connections_created=0;
	status.client_connections_sha2cached=0;
	status.server_connections_connected=0;
	status.server_connections_aborted=0;
	status.server_connections_created=0;
	status.server_connections_delayed=0;
	status.servers_table_version=0;
	pthread_mutex_init(&status.servers_table_version_lock, NULL);
	pthread_cond_init(&status.servers_table_version_cond, NULL);
	status.myconnpoll_get=0;
	status.myconnpoll_get_ok=0;
	status.myconnpoll_get_ping=0;
	status.myconnpoll_push=0;
	status.myconnpoll_destroy=0;
	status.myconnpoll_reset=0;
	status.autocommit_cnt=0;
	status.commit_cnt=0;
	status.rollback_cnt=0;
	status.autocommit_cnt_filtered=0;
	status.commit_cnt_filtered=0;
	status.rollback_cnt_filtered=0;
	status.backend_change_user=0;
	status.backend_init_db=0;
	status.backend_set_names=0;
	status.frontend_init_db=0;
	status.frontend_set_names=0;
	status.frontend_use_db=0;
	status.access_denied_wrong_password=0;
	status.access_denied_max_connections=0;
	status.access_denied_max_user_connections=0;
	status.select_for_update_or_equivalent=0;
	status.auto_increment_delay_multiplex=0;
#if 0
	pthread_mutex_init(&readonly_mutex, NULL);
#endif // 0
	pthread_mutex_init(&Group_Replication_Info_mutex, NULL);
	pthread_mutex_init(&Galera_Info_mutex, NULL);
	pthread_mutex_init(&AWS_Aurora_Info_mutex, NULL);
#if 0
	pthread_mutex_init(&lock, NULL);
	admindb=NULL;	// initialized only if needed
	mydb=new SQLite3DB();
#endif // 0
#ifdef DEBUG
	mydb->open((char *)"file:mem_mydb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
#else
	mydb->open((char *)"file:mem_mydb?mode=memory", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
#endif /* DEBUG */
	mydb->execute(MYHGM_MYSQL_SERVERS);
	mydb->execute(MYHGM_MYSQL_SERVERS_INCOMING);
	mydb->execute(MYHGM_MYSQL_REPLICATION_HOSTGROUPS);
	mydb->execute(MYHGM_MYSQL_GROUP_REPLICATION_HOSTGROUPS);
	mydb->execute(MYHGM_MYSQL_GALERA_HOSTGROUPS);
	mydb->execute(MYHGM_MYSQL_AWS_AURORA_HOSTGROUPS);
	mydb->execute(MYHGM_MYSQL_HOSTGROUP_ATTRIBUTES);
	mydb->execute(MYHGM_MYSQL_SERVERS_SSL_PARAMS);
	mydb->execute("CREATE INDEX IF NOT EXISTS idx_mysql_servers_hostname_port ON mysql_servers (hostname,port)");
	MyHostGroups=new PtrArray();
	runtime_mysql_servers=NULL;
	incoming_replication_hostgroups=NULL;
	incoming_group_replication_hostgroups=NULL;
	incoming_galera_hostgroups=NULL;
	incoming_aws_aurora_hostgroups = NULL;
	incoming_hostgroup_attributes = NULL;
	incoming_mysql_servers_ssl_params = NULL;
	incoming_mysql_servers_v2 = NULL;
	pthread_rwlock_init(&gtid_rwlock, NULL);
	gtid_missing_nodes = false;
	gtid_ev_loop=NULL;
	gtid_ev_timer=NULL;
	gtid_ev_async = (struct ev_async *)malloc(sizeof(struct ev_async));
	mysql_servers_to_monitor = NULL;

	{
		static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		rand_del[0] = '-';
		for (int i = 1; i < 6; i++) {
			rand_del[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
		}
		rand_del[6] = '-';
		rand_del[7] = 0;
	}
	pthread_mutex_init(&mysql_errors_mutex, NULL);

	// Initialize prometheus metrics
	init_prometheus_counter_array<hg_metrics_map_idx, p_hg_counter>(hg_metrics_map, this->status.p_counter_array);
	init_prometheus_gauge_array<hg_metrics_map_idx, p_hg_gauge>(hg_metrics_map, this->status.p_gauge_array);
	init_prometheus_dyn_counter_array<hg_metrics_map_idx, p_hg_dyn_counter>(hg_metrics_map, this->status.p_dyn_counter_array);
	init_prometheus_dyn_gauge_array<hg_metrics_map_idx, p_hg_dyn_gauge>(hg_metrics_map, this->status.p_dyn_gauge_array);

	pthread_mutex_init(&mysql_errors_mutex, NULL);
}

void MySQL_HostGroups_Manager::init() {
	//conn_reset_queue = NULL;
	//conn_reset_queue = new wqueue<MySQL_Connection *>();
	HGCU_thread = new std::thread(&HGCU_thread_run);
	//pthread_create(&HGCU_thread_id, NULL, HGCU_thread_run , NULL);

	// gtid initialization;
	GTID_syncer_thread = new std::thread(&GTID_syncer_run);

	//pthread_create(&GTID_syncer_thread_id, NULL, GTID_syncer_run , NULL);
}

void MySQL_HostGroups_Manager::shutdown() {
	queue.add(NULL);
	HGCU_thread->join();
	delete HGCU_thread;
	ev_async_send(gtid_ev_loop, gtid_ev_async);
	GTID_syncer_thread->join();
	delete GTID_syncer_thread;
}

MySQL_HostGroups_Manager::~MySQL_HostGroups_Manager() {
	while (MyHostGroups->len) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->remove_index_fast(0);
		delete myhgc;
	}
	delete MyHostGroups;
	delete mydb;
	if (admindb) {
		delete admindb;
	}
	for (auto  info : AWS_Aurora_Info_Map)
		delete info.second;
	free(gtid_ev_async);
	if (gtid_ev_loop)
		ev_loop_destroy(gtid_ev_loop);
	if (gtid_ev_timer)
		free(gtid_ev_timer);
	pthread_mutex_destroy(&lock);
}

void MySQL_HostGroups_Manager::p_update_mysql_error_counter(p_mysql_error_type err_type, unsigned int hid, char* address, uint16_t port, unsigned int code) {
	p_hg_dyn_counter::metric metric = p_hg_dyn_counter::mysql_error;
	if (err_type == p_mysql_error_type::proxysql) {
		metric = p_hg_dyn_counter::proxysql_mysql_error;
	}

	std::string s_hostgroup = std::to_string(hid);
	std::string s_address = std::string(address);
	std::string s_port = std::to_string(port);
	// TODO: Create switch here to classify error codes
	std::string s_code = std::to_string(code);
	std::string metric_id = s_hostgroup + ":" + address + ":" + s_port + ":" + s_code;
	std::map<string, string> metric_labels {
		{ "hostgroup", s_hostgroup },
		{ "address", address },
		{ "port", s_port },
		{ "code", s_code }
	};

	pthread_mutex_lock(&mysql_errors_mutex);

	p_inc_map_counter(
		status.p_mysql_errors_map,
		status.p_dyn_counter_array[metric],
		metric_id,
		metric_labels
	);

	pthread_mutex_unlock(&mysql_errors_mutex);
}

void MySQL_HostGroups_Manager::wait_servers_table_version(unsigned v, unsigned w) {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	//ts.tv_sec += w;
	unsigned int i = 0;
	int rc = 0;
	pthread_mutex_lock(&status.servers_table_version_lock);
	while ((rc == 0 || rc == ETIMEDOUT) && (i < w) && (__sync_fetch_and_add(&glovars.shutdown,0)==0) && (__sync_fetch_and_add(&status.servers_table_version,0) < v)) {
		i++;
		ts.tv_sec += 1;
		rc = pthread_cond_timedwait( &status.servers_table_version_cond, &status.servers_table_version_lock, &ts);
	}
	pthread_mutex_unlock(&status.servers_table_version_lock);
}

unsigned int MySQL_HostGroups_Manager::get_servers_table_version() {
	return __sync_fetch_and_add(&status.servers_table_version,0);
}

// we always assume that the calling thread has acquired a rdlock()
int MySQL_HostGroups_Manager::servers_add(SQLite3_result *resultset) {
	if (resultset==NULL) {
		return 0;
	}
	int rc;
	mydb->execute("DELETE FROM mysql_servers_incoming");
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	//sqlite3 *mydb3=mydb->get_db();
	char *query1=(char *)"INSERT INTO mysql_servers_incoming VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
	std::string query32s = "INSERT INTO mysql_servers_incoming VALUES " + generate_multi_rows_query(32,12);
	char *query32 = (char *)query32s.c_str();
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	rc = mydb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, mydb);
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
	rc = mydb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, mydb);
	MySerStatus status1=MYSQL_SERVER_STATUS_ONLINE;
	int row_idx=0;
	int max_bulk_row_idx=resultset->rows_count/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		status1=MYSQL_SERVER_STATUS_ONLINE;
		if (strcasecmp(r1->fields[4],"ONLINE")) {
			if (!strcasecmp(r1->fields[4],"SHUNNED")) {
				status1=MYSQL_SERVER_STATUS_SHUNNED;
			} else {
				if (!strcasecmp(r1->fields[4],"OFFLINE_SOFT")) {
					status1=MYSQL_SERVER_STATUS_OFFLINE_SOFT;
				} else {
					if (!strcasecmp(r1->fields[4],"OFFLINE_HARD")) {
						status1=MYSQL_SERVER_STATUS_OFFLINE_HARD;
					}
				}
			}
		}
		int idx=row_idx%32;
		if (row_idx<max_bulk_row_idx) { // bulk
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*12)+2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+4, atoi(r1->fields[3])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+5, atoi(r1->fields[5])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+6, status1); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+7, atoi(r1->fields[6])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+8, atoi(r1->fields[7])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+9, atoi(r1->fields[8])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+10, atoi(r1->fields[9])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement32, (idx*12)+11, atoi(r1->fields[10])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_text)(statement32, (idx*12)+12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, mydb);
				rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, mydb);
			}
		} else { // single row
			rc=(*proxy_sqlite3_bind_int64)(statement1, 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 4, atoi(r1->fields[3])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 5, atoi(r1->fields[5])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 6, status1); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 7, atoi(r1->fields[6])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 8, atoi(r1->fields[7])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 9, atoi(r1->fields[8])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 10, atoi(r1->fields[9])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_int64)(statement1, 11, atoi(r1->fields[10])); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_bind_text)(statement1, 12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
			SAFE_SQLITE3_STEP2(statement1);
			rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, mydb);
			rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, mydb);
		}
		row_idx++;
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	return 0;
}

/**
 * @brief Calculate and update the checksum for a specified table in the database.
 *
 * This function calculates the checksum for a specified table in the database using the provided SpookyHash object.
 * The checksum is computed based on the table's contents, sorted by the specified column name. If the initialization
 * flag is false, the SpookyHash object is initialized with predefined parameters. The calculated checksum is stored
 * in the raw_checksum parameter.
 *
 * @param myhash A reference to the SpookyHash object used for calculating the checksum.
 * @param init A reference to a boolean flag indicating whether the SpookyHash object has been initialized.
 * @param TableName The name of the table for which the checksum is to be calculated.
 * @param ColumnName The name of the column to be used for sorting the table before calculating the checksum.
 * @param raw_checksum A reference to a uint64_t variable where the calculated checksum will be stored.
 */
void MySQL_HostGroups_Manager::CUCFT1(
	SpookyHash& myhash, bool& init, const string& TableName, const string& ColumnName, uint64_t& raw_checksum
) {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	string query = "SELECT * FROM " + TableName + " ORDER BY " + ColumnName;
	mydb->execute_statement(query.c_str(), &error , &cols , &affected_rows , &resultset);
	if (resultset) {
		if (resultset->rows_count) {
			if (init == false) {
				init = true;
				myhash.Init(19,3);
			}
			uint64_t hash1_ = resultset->raw_checksum();
			raw_checksum = hash1_;
			myhash.Update(&hash1_, sizeof(hash1_));
			proxy_info("Checksum for table %s is 0x%lX\n", TableName.c_str(), hash1_);
		}
		delete resultset;
	} else {
		proxy_info("Checksum for table %s is 0x%lX\n", TableName.c_str(), (long unsigned int)0);
	}
}

/**
 * @brief Compute and update checksum values for specified tables.
 *
 * This function computes checksum values for specified tables by executing checksum calculation queries for each table.
 * It updates the checksum values in the `table_resultset_checksum` array.
 *
 * @param myhash A reference to a SpookyHash object used for computing the checksums.
 * @param init A reference to a boolean flag indicating whether the checksum computation has been initialized.
 * @note This function resets the current checksum values for all tables except MYSQL_SERVERS and MYSQL_SERVERS_V2
 *       before recomputing the checksums.
 * @note The computed checksum values are stored in the `table_resultset_checksum` array.
 */
void MySQL_HostGroups_Manager::commit_update_checksums_from_tables(SpookyHash& myhash, bool& init) {
	// Always reset the current table values before recomputing
	for (size_t i = 0; i < table_resultset_checksum.size(); i++) {
		if (i != HGM_TABLES::MYSQL_SERVERS && i != HGM_TABLES::MYSQL_SERVERS_V2) {
			table_resultset_checksum[i] = 0;
		}
	}

	CUCFT1(myhash,init,"mysql_replication_hostgroups","writer_hostgroup", table_resultset_checksum[HGM_TABLES::MYSQL_REPLICATION_HOSTGROUPS]);
	CUCFT1(myhash,init,"mysql_group_replication_hostgroups","writer_hostgroup", table_resultset_checksum[HGM_TABLES::MYSQL_GROUP_REPLICATION_HOSTGROUPS]);
	CUCFT1(myhash,init,"mysql_galera_hostgroups","writer_hostgroup", table_resultset_checksum[HGM_TABLES::MYSQL_GALERA_HOSTGROUPS]);
	CUCFT1(myhash,init,"mysql_aws_aurora_hostgroups","writer_hostgroup", table_resultset_checksum[HGM_TABLES::MYSQL_AWS_AURORA_HOSTGROUPS]);
	CUCFT1(myhash,init,"mysql_hostgroup_attributes","hostgroup_id", table_resultset_checksum[HGM_TABLES::MYSQL_HOSTGROUP_ATTRIBUTES]);
	CUCFT1(myhash,init,"mysql_servers_ssl_params","hostname,port,username", table_resultset_checksum[HGM_TABLES::MYSQL_SERVERS_SSL_PARAMS]);
}

/**
 * @brief This code updates the 'hostgroup_server_mapping' table with the most recent mysql_servers and mysql_replication_hostgroups 
 *	  records while utilizing checksums to prevent unnecessary updates.
 * 
 * IMPORTANT: Make sure wrlock() is called before calling this method.
 * 
*/
void MySQL_HostGroups_Manager::update_hostgroup_manager_mappings() {

	if (hgsm_mysql_servers_checksum != table_resultset_checksum[HGM_TABLES::MYSQL_SERVERS] ||
		hgsm_mysql_replication_hostgroups_checksum != table_resultset_checksum[HGM_TABLES::MYSQL_REPLICATION_HOSTGROUPS])
	{
		proxy_info("Rebuilding 'Hostgroup_Manager_Mapping' due to checksums change - mysql_servers { old: 0x%lX, new: 0x%lX }, mysql_replication_hostgroups { old:0x%lX, new:0x%lX }\n",
			hgsm_mysql_servers_checksum, table_resultset_checksum[HGM_TABLES::MYSQL_SERVERS],
			hgsm_mysql_replication_hostgroups_checksum, table_resultset_checksum[HGM_TABLES::MYSQL_REPLICATION_HOSTGROUPS]);

		char* error = NULL;
		int cols = 0;
		int affected_rows = 0;
		SQLite3_result* resultset = NULL;

		hostgroup_server_mapping.clear();

		const char* query = "SELECT DISTINCT hostname, port, '1' is_writer, status, reader_hostgroup, writer_hostgroup, mem_pointer FROM mysql_replication_hostgroups JOIN mysql_servers ON hostgroup_id=writer_hostgroup WHERE status<>3 \
							 UNION \
							 SELECT DISTINCT hostname, port, '0' is_writer, status, reader_hostgroup, writer_hostgroup, mem_pointer FROM mysql_replication_hostgroups JOIN mysql_servers ON hostgroup_id=reader_hostgroup WHERE status<>3 \
							 ORDER BY hostname, port";

		mydb->execute_statement(query, &error, &cols, &affected_rows, &resultset);

		if (resultset && resultset->rows_count) {
			std::string fetched_server_id;
			HostGroup_Server_Mapping* fetched_server_mapping = NULL;

			for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
				SQLite3_row* r = *it;

				const std::string& server_id = std::string(r->fields[0]) + ":::" + r->fields[1];

				if (fetched_server_mapping == NULL || server_id != fetched_server_id) {

					auto itr = hostgroup_server_mapping.find(server_id);

					if (itr == hostgroup_server_mapping.end()) {
						std::unique_ptr<HostGroup_Server_Mapping> server_mapping(new HostGroup_Server_Mapping(this));
						fetched_server_mapping = server_mapping.get();
						hostgroup_server_mapping.insert( std::pair<std::string,std::unique_ptr<MySQL_HostGroups_Manager::HostGroup_Server_Mapping>> {
															server_id, std::move(server_mapping)
															} );
					} else {
						fetched_server_mapping = itr->second.get();
					}

					fetched_server_id = server_id;
				}

				HostGroup_Server_Mapping::Node node;
				//node.server_status = static_cast<MySerStatus>(atoi(r->fields[3]));
				node.reader_hostgroup_id = atoi(r->fields[4]);
				node.writer_hostgroup_id = atoi(r->fields[5]);
				node.srv = reinterpret_cast<MySrvC*>(atoll(r->fields[6]));

				HostGroup_Server_Mapping::Type type = (r->fields[2] && r->fields[2][0] == '1') ? HostGroup_Server_Mapping::Type::WRITER : HostGroup_Server_Mapping::Type::READER;
				fetched_server_mapping->add(type, node);
			}
		}
		delete resultset;

		hgsm_mysql_servers_checksum = table_resultset_checksum[HGM_TABLES::MYSQL_SERVERS];
		hgsm_mysql_replication_hostgroups_checksum = table_resultset_checksum[HGM_TABLES::MYSQL_REPLICATION_HOSTGROUPS];
	}
}

/**
 * @brief Generates a resultset holding the current Admin 'runtime_mysql_servers' as reported by Admin.
 * @details Requires caller to hold the mutex 'MySQL_HostGroups_Manager::wrlock'.
 * @param mydb The db in which to perform the query, typically 'MySQL_HostGroups_Manager::mydb'.
 * @return An SQLite3 resultset for the query 'MYHGM_GEN_ADMIN_RUNTIME_SERVERS'.
 */
unique_ptr<SQLite3_result> get_admin_runtime_mysql_servers(SQLite3DB* mydb) {
	char* error = nullptr;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* resultset = nullptr;

	mydb->execute_statement(MYHGM_GEN_CLUSTER_ADMIN_RUNTIME_SERVERS, &error, &cols, &affected_rows, &resultset);

	if (error) {
		proxy_error("SQLite3 query generating 'runtime_mysql_servers' resultset failed with error '%s'\n", error);
		assert(0);
	}

	return unique_ptr<SQLite3_result>(resultset);
}

/**
 * @brief Generates a resultset with holding the current 'mysql_servers_v2' table.
 * @details Requires caller to hold the mutex 'ProxySQL_Admin::mysql_servers_wrlock'.
 * @return A resulset holding 'mysql_servers_v2'.
 */
unique_ptr<SQLite3_result> get_mysql_servers_v2() {
	char* error = nullptr;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* resultset = nullptr;

	if (GloAdmin && GloAdmin->admindb) {
		GloAdmin->admindb->execute_statement(
			MYHGM_GEN_CLUSTER_ADMIN_MYSQL_SERVERS, &error, &cols, &affected_rows, &resultset
		);
	}

	return unique_ptr<SQLite3_result>(resultset);
}

static void update_glovars_checksum_with_peers(
	ProxySQL_Checksum_Value& module_checksum,
	const string& new_checksum,
	const string& peer_checksum_value,
	time_t new_epoch,
	time_t peer_checksum_epoch,
	bool update_version
) {
	module_checksum.set_checksum(const_cast<char*>(new_checksum.c_str()));

	if (update_version)
		module_checksum.version++;

	bool computed_checksum_matches =
		peer_checksum_value != "" && module_checksum.checksum == peer_checksum_value;

	if (peer_checksum_epoch != 0 && computed_checksum_matches) {
		module_checksum.epoch = peer_checksum_epoch;
	} else {
		module_checksum.epoch = new_epoch;
	}
}

/**
 * @brief Updates the global 'mysql_servers' module checksum.
 * @details If the new computed checksum matches the supplied 'cluster_checksum', the epoch used for the
 *  checksum is the supplied epoch instead of current time. This way we ensure the preservation of the
 *  checksum and epoch fetched from the ProxySQL cluster peer node.
 *
 *  IMPORTANT: This function also generates a new 'global_checksum'. This is because everytime
 *  'runtime_mysql_servers' change, updating the global checksum is unconditional.
 * @param new_checksum The new computed checksum for 'runtime_mysql_servers'.
 * @param peer_checksum A checksum fetched from another ProxySQL cluster node, holds the checksum value
 *  and its epoch. Should be empty if no remote checksum is being considered.
 * @param epoch The epoch to be preserved in case the supplied 'peer_checksum' matches the new computed
 *  checksum.
 */
static void update_glovars_mysql_servers_checksum(
	const string& new_checksum,
	const runtime_mysql_servers_checksum_t& peer_checksum = {},
	bool update_version = false
) {
	time_t new_epoch = time(NULL);

	update_glovars_checksum_with_peers(
		GloVars.checksums_values.mysql_servers,
		new_checksum,
		peer_checksum.value,
		new_epoch,
		peer_checksum.epoch,
		update_version
	);

	GloVars.checksums_values.updates_cnt++;
	GloVars.generate_global_checksum();
	GloVars.epoch_version = new_epoch;
}

/**
 * @brief Updates the global 'mysql_servers_v2' module checksum.
 * @details Unlike 'update_glovars_mysql_servers_checksum' this function doesn't generate a new
 *  'global_checksum'. It's caller responsibility to ensure that 'global_checksum' is updated. 
 * @param new_checksum The new computed checksum for 'mysql_servers_v2'.
 * @param peer_checksum A checksum fetched from another ProxySQL cluster node, holds the checksum value
 *  and its epoch. Should be empty if no remote checksum is being considered.
 * @param epoch The epoch to be preserved in case the supplied 'peer_checksum' matches the new computed
 *  checksum.
 */
static void update_glovars_mysql_servers_v2_checksum(
	const string& new_checksum,
	const mysql_servers_v2_checksum_t& peer_checksum = {},
	bool update_version = false
) {
	time_t new_epoch = time(NULL);

	update_glovars_checksum_with_peers(
		GloVars.checksums_values.mysql_servers_v2,
		new_checksum,
		peer_checksum.value,
		new_epoch,
		peer_checksum.epoch,
		update_version
	);
}

/**
 * @brief Commit and update checksum from the MySQL servers.
 *
 * This function commits updates and calculates the checksum from the MySQL servers. It performs the following steps:
 * 1. Deletes existing data from the 'mysql_servers' table.
 * 2. Generates a new 'mysql_servers' table.
 * 3. Saves the runtime MySQL servers data obtained from the provided result set or from the database if the result set is null.
 * 4. Calculates the checksum of the runtime MySQL servers data and updates the checksum value in the 'table_resultset_checksum' array.
 *
 * @param runtime_mysql_servers A pointer to the result set containing runtime MySQL servers data.
 * @return The raw checksum value calculated from the runtime MySQL servers data.
 */
uint64_t MySQL_HostGroups_Manager::commit_update_checksum_from_mysql_servers(SQLite3_result* runtime_mysql_servers) {
	mydb->execute("DELETE FROM mysql_servers");
	generate_mysql_servers_table();

	if (runtime_mysql_servers == nullptr) {
		unique_ptr<SQLite3_result> resultset { get_admin_runtime_mysql_servers(mydb) };
		save_runtime_mysql_servers(resultset.release());
	} else {
		save_runtime_mysql_servers(runtime_mysql_servers);
	}

	uint64_t raw_checksum = this->runtime_mysql_servers ? this->runtime_mysql_servers->raw_checksum() : 0;
	table_resultset_checksum[HGM_TABLES::MYSQL_SERVERS] = raw_checksum;

	return raw_checksum;
}

/**
 * @brief Commit and update checksum from the MySQL servers V2.
 *
 * This function commits updates and calculates the checksum from the MySQL servers V2 data. It performs the following steps:
 * 1. Saves the provided MySQL servers V2 data if not null, or retrieves and saves the data from the database.
 * 2. Calculates the checksum of the MySQL servers V2 data and updates the checksum value in the 'table_resultset_checksum' array.
 *
 * @param mysql_servers_v2 A pointer to the result set containing MySQL servers V2 data.
 * @return The raw checksum value calculated from the MySQL servers V2 data.
 */
uint64_t MySQL_HostGroups_Manager::commit_update_checksum_from_mysql_servers_v2(SQLite3_result* mysql_servers_v2) {
	if (mysql_servers_v2 == nullptr) {
		unique_ptr<SQLite3_result> resultset { get_mysql_servers_v2() };
		save_mysql_servers_v2(resultset.release());
	} else {
		save_mysql_servers_v2(mysql_servers_v2);
	}

	uint64_t raw_checksum = this->incoming_mysql_servers_v2 ? this->incoming_mysql_servers_v2->raw_checksum() : 0;
	table_resultset_checksum[HGM_TABLES::MYSQL_SERVERS_V2] = raw_checksum;

	return raw_checksum;
}

std::string MySQL_HostGroups_Manager::gen_global_mysql_servers_v2_checksum(uint64_t servers_v2_hash) {
	bool init = false;
	SpookyHash global_hash {};

	if (servers_v2_hash != 0) {
		if (init == false) {
			init = true;
			global_hash.Init(19, 3);
		}

		global_hash.Update(&servers_v2_hash, sizeof(servers_v2_hash));
	}

	commit_update_checksums_from_tables(global_hash, init);

	uint64_t hash_1 = 0, hash_2 = 0;
	if (init) {
		global_hash.Final(&hash_1,&hash_2);
	}

	string mysrvs_checksum { get_checksum_from_hash(hash_1) };
	return mysrvs_checksum;
}

bool MySQL_HostGroups_Manager::commit() {
	return commit({},{});
}

bool MySQL_HostGroups_Manager::commit(
	const peer_runtime_mysql_servers_t& peer_runtime_mysql_servers,
	const peer_mysql_servers_v2_t& peer_mysql_servers_v2,
	bool only_commit_runtime_mysql_servers,
	bool update_version
) {
	// if only_commit_runtime_mysql_servers is true, mysql_servers_v2 resultset will not be entertained and will cause memory leak.
	if (only_commit_runtime_mysql_servers) {
		proxy_info("Generating runtime mysql servers records only.\n");
	} else {
		proxy_info("Generating runtime mysql servers and mysql servers v2 records.\n");
	}

	unsigned long long curtime1=monotonic_time();
	wrlock();
	// purge table
	purge_mysql_servers_table();
	// if any server has gtid_port enabled, use_gtid is set to true
	// and then has_gtid_port is set too
	bool use_gtid = false;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_servers\n");
	mydb->execute("DELETE FROM mysql_servers");
	generate_mysql_servers_table();

	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	if (GloMTH->variables.hostgroup_manager_verbose) {
		mydb->execute_statement((char *)"SELECT * FROM mysql_servers_incoming", &error , &cols , &affected_rows , &resultset);
		if (error) {
			proxy_error("Error on read from mysql_servers_incoming : %s\n", error);
		} else {
			if (resultset) {
				proxy_info("Dumping mysql_servers_incoming\n");
				resultset->dump_to_stderr();
			}
		}
		if (resultset) { delete resultset; resultset=NULL; }
	}
	char *query=NULL;
	query=(char *)"SELECT mem_pointer, t1.hostgroup_id, t1.hostname, t1.port FROM mysql_servers t1 LEFT OUTER JOIN mysql_servers_incoming t2 ON (t1.hostgroup_id=t2.hostgroup_id AND t1.hostname=t2.hostname AND t1.port=t2.port) WHERE t2.hostgroup_id IS NULL";
	mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		if (GloMTH->variables.hostgroup_manager_verbose) {
			proxy_info("Dumping mysql_servers LEFT JOIN mysql_servers_incoming\n");
			resultset->dump_to_stderr();
		}
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			long long ptr=atoll(r->fields[0]);
			proxy_warning("Removed server at address %lld, hostgroup %s, address %s port %s. Setting status OFFLINE HARD and immediately dropping all free connections. Used connections will be dropped when trying to use them\n", ptr, r->fields[1], r->fields[2], r->fields[3]);
			MySrvC *mysrvc=(MySrvC *)ptr;
			mysrvc->set_status(MYSQL_SERVER_STATUS_OFFLINE_HARD);
			mysrvc->ConnectionsFree->drop_all_connections();
			char *q1=(char *)"DELETE FROM mysql_servers WHERE mem_pointer=%lld";
			char *q2=(char *)malloc(strlen(q1)+32);
			sprintf(q2,q1,ptr);
			mydb->execute(q2);
			free(q2);
		}
	}
	if (resultset) { delete resultset; resultset=NULL; }

	// This seems unnecessary. Removed as part of issue #829
	//mydb->execute("DELETE FROM mysql_servers");
	//generate_mysql_servers_table();

	mydb->execute("INSERT OR IGNORE INTO mysql_servers(hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers_incoming");

	// SELECT FROM mysql_servers whatever is not identical in mysql_servers_incoming, or where mem_pointer=0 (where there is no pointer yet)
	query=(char *)"SELECT t1.*, t2.gtid_port, t2.weight, t2.status, t2.compression, t2.max_connections, t2.max_replication_lag, t2.use_ssl, t2.max_latency_ms, t2.comment FROM mysql_servers t1 JOIN mysql_servers_incoming t2 ON (t1.hostgroup_id=t2.hostgroup_id AND t1.hostname=t2.hostname AND t1.port=t2.port) WHERE mem_pointer=0 OR t1.gtid_port<>t2.gtid_port OR t1.weight<>t2.weight OR t1.status<>t2.status OR t1.compression<>t2.compression OR t1.max_connections<>t2.max_connections OR t1.max_replication_lag<>t2.max_replication_lag OR t1.use_ssl<>t2.use_ssl OR t1.max_latency_ms<>t2.max_latency_ms or t1.comment<>t2.comment";
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
	mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {

		if (GloMTH->variables.hostgroup_manager_verbose) {
			proxy_info("Dumping mysql_servers JOIN mysql_servers_incoming\n");
			resultset->dump_to_stderr();
		}
		// optimization #829
		int rc;
		sqlite3_stmt *statement1=NULL;
		sqlite3_stmt *statement2=NULL;
		//sqlite3 *mydb3=mydb->get_db();
		char *query1=(char *)"UPDATE mysql_servers SET mem_pointer = ?1 WHERE hostgroup_id = ?2 AND hostname = ?3 AND port = ?4";
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		rc = mydb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, mydb);
		char *query2=(char *)"UPDATE mysql_servers SET weight = ?1 , status = ?2 , compression = ?3 , max_connections = ?4 , max_replication_lag = ?5 , use_ssl = ?6 , max_latency_ms = ?7 , comment = ?8 , gtid_port = ?9 WHERE hostgroup_id = ?10 AND hostname = ?11 AND port = ?12";
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query2, -1, &statement2, 0);
		rc = mydb->prepare_v2(query2, &statement2);
		ASSERT_SQLITE_OK(rc, mydb);

		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			long long ptr=atoll(r->fields[12]); // increase this index every time a new column is added
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d , weight=%d, status=%d, mem_pointer=%llu, hostgroup=%d, compression=%d\n", r->fields[1], atoi(r->fields[2]), atoi(r->fields[4]), atoi(r->fields[5]), ptr, atoi(r->fields[0]), atoi(r->fields[6]));
			//fprintf(stderr,"%lld\n", ptr);
			if (ptr==0) {
				if (GloMTH->variables.hostgroup_manager_verbose) {
					proxy_info("Creating new server in HG %d : %s:%d , gtid_port=%d, weight=%d, status=%d\n", atoi(r->fields[0]), r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), atoi(r->fields[4]), atoi(r->fields[5]));
				}
				MySrvC *mysrvc=new MySrvC(r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), atoi(r->fields[4]), (MySerStatus)atoi(r->fields[5]), atoi(r->fields[6]), atoi(r->fields[7]), atoi(r->fields[8]), atoi(r->fields[9]), atoi(r->fields[10]), r->fields[11]); // add new fields here if adding more columns in mysql_servers
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Adding new server %s:%d , weight=%d, status=%d, mem_ptr=%p into hostgroup=%d\n", r->fields[1], atoi(r->fields[2]), atoi(r->fields[4]), atoi(r->fields[5]), mysrvc, atoi(r->fields[0]));
				add(mysrvc,atoi(r->fields[0]));
				ptr=(uintptr_t)mysrvc;
				rc=(*proxy_sqlite3_bind_int64)(statement1, 1, ptr); ASSERT_SQLITE_OK(rc, mydb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 2, atoi(r->fields[0])); ASSERT_SQLITE_OK(rc, mydb);
				rc=(*proxy_sqlite3_bind_text)(statement1, 3,  r->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
				rc=(*proxy_sqlite3_bind_int64)(statement1, 4, atoi(r->fields[2])); ASSERT_SQLITE_OK(rc, mydb);
				SAFE_SQLITE3_STEP2(statement1);
				rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, mydb);
				rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, mydb);
				if (mysrvc->gtid_port) {
					// this server has gtid_port configured, we set use_gtid
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 6, "Server %u:%s:%d has gtid_port enabled, setting use_gitd=true if not already set\n", mysrvc->myhgc->hid , mysrvc->address, mysrvc->port);
					use_gtid = true;
				}
			} else {
				bool run_update=false;
				MySrvC *mysrvc=(MySrvC *)ptr;
				// carefully increase the 2nd index by 1 for every new column added
				if (atoi(r->fields[3])!=atoi(r->fields[13])) {
					if (GloMTH->variables.hostgroup_manager_verbose)
						proxy_info("Changing gtid_port for server %u:%s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->myhgc->hid , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]) , mysrvc->gtid_port , atoi(r->fields[13]));
					mysrvc->gtid_port=atoi(r->fields[13]);
				}

				if (atoi(r->fields[4])!=atoi(r->fields[14])) {
					if (GloMTH->variables.hostgroup_manager_verbose)
						proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing weight for server %d:%s:%d (%s:%d) from %d (%ld) to %d\n" , mysrvc->myhgc->hid , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), atoi(r->fields[4]) , mysrvc->weight , atoi(r->fields[14]));
					mysrvc->weight=atoi(r->fields[14]);
				}
				if (atoi(r->fields[5])!=atoi(r->fields[15])) {
					bool change_server_status = true;
					if (GloMTH->variables.evaluate_replication_lag_on_servers_load == 1) {
						if (mysrvc->get_status() == MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG && // currently server is shunned due to replication lag
							(MySerStatus)atoi(r->fields[15]) == MYSQL_SERVER_STATUS_ONLINE) { // new server status is online
							if (mysrvc->cur_replication_lag != -2) { // Master server? Seconds_Behind_Master column is not present
								const unsigned int new_max_repl_lag = atoi(r->fields[18]);
								if (mysrvc->cur_replication_lag < 0 ||
									(new_max_repl_lag > 0 &&
									((unsigned int)mysrvc->cur_replication_lag > new_max_repl_lag))) { // we check if current replication lag is greater than new max_replication_lag
									change_server_status = false;
								}
							}
						}
					}
					if (change_server_status == true) {
						if (GloMTH->variables.hostgroup_manager_verbose)
							proxy_info("Changing status for server %d:%s:%d (%s:%d) from %d (%d) to %d\n", mysrvc->myhgc->hid, mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), atoi(r->fields[5]), (int)mysrvc->get_status(), atoi(r->fields[15]));
						mysrvc->set_status((MySerStatus)atoi(r->fields[15]));
					}
					if (mysrvc->get_status() == MYSQL_SERVER_STATUS_SHUNNED) {
						mysrvc->shunned_automatic=false;
					}
				}
				if (atoi(r->fields[6])!=atoi(r->fields[16])) {
					if (GloMTH->variables.hostgroup_manager_verbose)
						proxy_info("Changing compression for server %d:%s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->myhgc->hid , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), atoi(r->fields[6]) , mysrvc->compression , atoi(r->fields[16]));
					mysrvc->compression=atoi(r->fields[16]);
				}
				if (atoi(r->fields[7])!=atoi(r->fields[17])) {
					if (GloMTH->variables.hostgroup_manager_verbose)
					proxy_info("Changing max_connections for server %d:%s:%d (%s:%d) from %d (%ld) to %d\n" , mysrvc->myhgc->hid , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), atoi(r->fields[7]) , mysrvc->max_connections , atoi(r->fields[17]));
					mysrvc->max_connections=atoi(r->fields[17]);
				}
				if (atoi(r->fields[8])!=atoi(r->fields[18])) {
					if (GloMTH->variables.hostgroup_manager_verbose)
						proxy_info("Changing max_replication_lag for server %u:%s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->myhgc->hid , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), atoi(r->fields[8]) , mysrvc->max_replication_lag , atoi(r->fields[18]));
					mysrvc->max_replication_lag=atoi(r->fields[18]);
					if (mysrvc->max_replication_lag == 0) { // we just changed it to 0
						if (mysrvc->get_status() == MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) {
							// the server is currently shunned due to replication lag
							// but we reset max_replication_lag to 0
							// therefore we immediately reset the status too
							mysrvc->set_status(MYSQL_SERVER_STATUS_ONLINE);
						}
					}
				}
				if (atoi(r->fields[9])!=atoi(r->fields[19])) {
					if (GloMTH->variables.hostgroup_manager_verbose)
						proxy_info("Changing use_ssl for server %d:%s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->myhgc->hid , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), atoi(r->fields[9]) , mysrvc->use_ssl , atoi(r->fields[19]));
					mysrvc->use_ssl=atoi(r->fields[19]);
				}
				if (atoi(r->fields[10])!=atoi(r->fields[20])) {
					if (GloMTH->variables.hostgroup_manager_verbose)
						proxy_info("Changing max_latency_ms for server %d:%s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->myhgc->hid , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), atoi(r->fields[10]) , mysrvc->max_latency_us/1000 , atoi(r->fields[20]));
					mysrvc->max_latency_us=1000*atoi(r->fields[20]);
				}
				if (strcmp(r->fields[11],r->fields[21])) {
					if (GloMTH->variables.hostgroup_manager_verbose)
						proxy_info("Changing comment for server %d:%s:%d (%s:%d) from '%s' to '%s'\n" , mysrvc->myhgc->hid , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[11], r->fields[21]);
					free(mysrvc->comment);
					mysrvc->comment=strdup(r->fields[21]);
				}
				if (run_update) {
					rc=(*proxy_sqlite3_bind_int64)(statement2, 1, mysrvc->weight); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 2, (int)mysrvc->get_status()); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 3, mysrvc->compression); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 4, mysrvc->max_connections); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 5, mysrvc->max_replication_lag); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 6, mysrvc->use_ssl); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 7, mysrvc->max_latency_us/1000); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_text)(statement2, 8,  mysrvc->comment, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 9, mysrvc->gtid_port); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 10, mysrvc->myhgc->hid); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_text)(statement2, 11,  mysrvc->address, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 12, mysrvc->port); ASSERT_SQLITE_OK(rc, mydb);
					SAFE_SQLITE3_STEP2(statement2);
					rc=(*proxy_sqlite3_clear_bindings)(statement2); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_reset)(statement2); ASSERT_SQLITE_OK(rc, mydb);
				}
				if (mysrvc->gtid_port) {
					// this server has gtid_port configured, we set use_gtid
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 6, "Server %u:%s:%d has gtid_port enabled, setting use_gitd=true if not already set\n", mysrvc->myhgc->hid , mysrvc->address, mysrvc->port);
					use_gtid = true;
				}
			}
		}
		(*proxy_sqlite3_finalize)(statement1);
		(*proxy_sqlite3_finalize)(statement2);
	}
	if (use_gtid) {
		has_gtid_port = true;
	} else {
		has_gtid_port = false;
	}
	if (resultset) { delete resultset; resultset=NULL; }
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_servers_incoming\n");
	mydb->execute("DELETE FROM mysql_servers_incoming");

	string global_checksum_v2 {};
	if (only_commit_runtime_mysql_servers == false) {
		// replication
		if (incoming_replication_hostgroups) { // this IF is extremely important, otherwise replication hostgroups may disappear
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_replication_hostgroups\n");
			mydb->execute("DELETE FROM mysql_replication_hostgroups");
			generate_mysql_replication_hostgroups_table();
		}

		// group replication
		if (incoming_group_replication_hostgroups) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_group_replication_hostgroups\n");
			mydb->execute("DELETE FROM mysql_group_replication_hostgroups");
			generate_mysql_group_replication_hostgroups_table();
		}

		// galera
		if (incoming_galera_hostgroups) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_galera_hostgroups\n");
			mydb->execute("DELETE FROM mysql_galera_hostgroups");
			generate_mysql_galera_hostgroups_table();
		}

		// AWS Aurora
		if (incoming_aws_aurora_hostgroups) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_aws_aurora_hostgroups\n");
			mydb->execute("DELETE FROM mysql_aws_aurora_hostgroups");
			generate_mysql_aws_aurora_hostgroups_table();
		}

		// hostgroup attributes
		if (incoming_hostgroup_attributes) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_hostgroup_attributes\n");
			mydb->execute("DELETE FROM mysql_hostgroup_attributes");
			generate_mysql_hostgroup_attributes_table();
		}

		// SSL params
		if (incoming_mysql_servers_ssl_params) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_servers_ssl_params\n");
			mydb->execute("DELETE FROM mysql_servers_ssl_params");
			generate_mysql_servers_ssl_params_table();
		}

		uint64_t new_hash = commit_update_checksum_from_mysql_servers_v2(peer_mysql_servers_v2.resultset);

		{
			const string new_checksum { get_checksum_from_hash(new_hash) };
			proxy_info("Checksum for table %s is %s\n", "mysql_servers_v2", new_checksum.c_str());
		}

		global_checksum_v2 = gen_global_mysql_servers_v2_checksum(new_hash);
		proxy_info("New computed global checksum for 'mysql_servers_v2' is '%s'\n", global_checksum_v2.c_str());
	}

	// Update 'mysql_servers' and global checksums
	{
		uint64_t new_hash = commit_update_checksum_from_mysql_servers(peer_runtime_mysql_servers.resultset);
		const string new_checksum { get_checksum_from_hash(new_hash) };
		proxy_info("Checksum for table %s is %s\n", "mysql_servers", new_checksum.c_str());

		pthread_mutex_lock(&GloVars.checksum_mutex);
		if (only_commit_runtime_mysql_servers == false) {
			update_glovars_mysql_servers_v2_checksum(global_checksum_v2, peer_mysql_servers_v2.checksum, true);
		}
		update_glovars_mysql_servers_checksum(new_checksum, peer_runtime_mysql_servers.checksum, update_version);
		pthread_mutex_unlock(&GloVars.checksum_mutex);
	}

	// fill Hostgroup_Manager_Mapping with latest records
	update_hostgroup_manager_mappings();


	ev_async_send(gtid_ev_loop, gtid_ev_async);

	__sync_fetch_and_add(&status.servers_table_version,1);

	// We completely reset read_only_set1. It will generated (completely) again in read_only_action()
	// Note: read_only_set1 will be regenerated all at once
	read_only_set1.erase(read_only_set1.begin(), read_only_set1.end());
	// We completely reset read_only_set2. It will be again written in read_only_action()
	// Note: read_only_set2 will be regenerated one server at the time
	read_only_set2.erase(read_only_set2.begin(), read_only_set2.end());

	this->status.p_counter_array[p_hg_counter::servers_table_version]->Increment();
	pthread_cond_broadcast(&status.servers_table_version_cond);
	pthread_mutex_unlock(&status.servers_table_version_lock);

	// NOTE: In order to guarantee the latest generated version, this should be kept after all the
	// calls to 'generate_mysql_servers'.
	update_table_mysql_servers_for_monitor(false);

	wrunlock();
	unsigned long long curtime2=monotonic_time();
	curtime1 = curtime1/1000;
	curtime2 = curtime2/1000;
	proxy_info("MySQL_HostGroups_Manager::commit() locked for %llums\n", curtime2-curtime1);

	if (GloMTH) {
		GloMTH->signal_all_threads(1);
	}

	return true;
}

/** 
 * @brief Calculate the checksum for the runtime mysql_servers record, after excluding all the rows
 *    with the status OFFLINE_HARD from the result set
 * 
 * @details The runtime mysql_servers is now considered as a distinct module and have a separate checksum calculation.
 *    This is because the records in the runtime module may differ from those in the admin mysql_servers module, which
 *	  can cause synchronization issues within the cluster.
 * 
 * @param runtime_mysql_servers resultset of runtime mysql_servers or can be a nullptr.
*/
uint64_t MySQL_HostGroups_Manager::get_mysql_servers_checksum(SQLite3_result* runtime_mysql_servers) {

	//Note: GloVars.checksum_mutex needs to be locked
	SQLite3_result* resultset = nullptr;

	if (runtime_mysql_servers == nullptr) {
		char* error = NULL;
		int cols = 0;
		int affected_rows = 0;

		mydb->execute_statement(MYHGM_GEN_CLUSTER_ADMIN_RUNTIME_SERVERS, &error, &cols, &affected_rows, &resultset);

		if (resultset) {
			save_runtime_mysql_servers(resultset);
		} else {
			proxy_info("Checksum for table %s is 0x%lX\n", "mysql_servers", (long unsigned int)0);
		}
	} else {
		resultset = runtime_mysql_servers;
		save_runtime_mysql_servers(runtime_mysql_servers);
	}

	table_resultset_checksum[HGM_TABLES::MYSQL_SERVERS] = resultset != nullptr ? resultset->raw_checksum() : 0;
	proxy_info("Checksum for table %s is 0x%lX\n", "mysql_servers", table_resultset_checksum[HGM_TABLES::MYSQL_SERVERS]);

	return table_resultset_checksum[HGM_TABLES::MYSQL_SERVERS];
}

/**
 * @brief Check if a GTID exists for a given MySQL server connection.
 *
 * This function checks whether a GTID (Global Transaction Identifier) exists for the specified MySQL server connection.
 * It performs the following steps:
 * 1. Acquires a read lock on the GTID read-write lock.
 * 2. Constructs a string representation of the MySQL server address and port.
 * 3. Searches for the GTID information associated with the MySQL server in the GTID map using the constructed string as the key.
 * 4. If the GTID information is found and is active, it checks whether the specified GTID exists.
 * 5. Releases the read lock on the GTID read-write lock.
 *
 * @param mysrvc A pointer to the MySQL server connection.
 * @param gtid_uuid A pointer to the character array representing the GTID UUID.
 * @param gtid_trxid The GTID transaction ID.
 * @return True if the specified GTID exists for the MySQL server connection, false otherwise.
 */
bool MySQL_HostGroups_Manager::gtid_exists(MySrvC *mysrvc, char * gtid_uuid, uint64_t gtid_trxid) {
	bool ret = false;
	pthread_rwlock_rdlock(&gtid_rwlock);
	std::string s1 = mysrvc->address;
	s1.append(":");
	s1.append(std::to_string(mysrvc->port));
	std::unordered_map <string, GTID_Server_Data *>::iterator it2;
	it2 = gtid_map.find(s1);
	GTID_Server_Data *gtid_is=NULL;
	if (it2!=gtid_map.end()) {
		gtid_is=it2->second;
		if (gtid_is) {
			if (gtid_is->active == true) {
				ret = gtid_is->gtid_exists(gtid_uuid,gtid_trxid);
			}
		}
	}
	//proxy_info("Checking if server %s has GTID %s:%lu . %s\n", s1.c_str(), gtid_uuid, gtid_trxid, (ret ? "YES" : "NO"));
	pthread_rwlock_unlock(&gtid_rwlock);
	return ret;
}

void MySQL_HostGroups_Manager::generate_mysql_gtid_executed_tables() {
	pthread_rwlock_wrlock(&gtid_rwlock);
	// first, set them all as active = false
	std::unordered_map<string, GTID_Server_Data *>::iterator it = gtid_map.begin();
	while(it != gtid_map.end()) {
		GTID_Server_Data * gtid_si = it->second;
		if (gtid_si) {
			gtid_si->active = false;
		}
		it++;
	}

	// NOTE: We are required to lock while iterating over 'MyHostGroups'. Otherwise race conditions could take place,
	// e.g. servers could be purged by 'purge_mysql_servers_table' and invalid memory be accessed.
	wrlock();
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		MySrvC *mysrvc=NULL;
		for (unsigned int j=0; j<myhgc->mysrvs->servers->len; j++) {
			mysrvc=myhgc->mysrvs->idx(j);
			if (mysrvc->gtid_port) {
				std::string s1 = mysrvc->address;
				s1.append(":");
				s1.append(std::to_string(mysrvc->port));
				std::unordered_map <string, GTID_Server_Data *>::iterator it2;
				it2 = gtid_map.find(s1);
				GTID_Server_Data *gtid_is=NULL;
				if (it2!=gtid_map.end()) {
					gtid_is=it2->second;
					if (gtid_is == NULL) {
						gtid_map.erase(it2);
					}
				}
				if (gtid_is) {
					gtid_is->active = true;
				} else if (mysrvc->get_status() != MYSQL_SERVER_STATUS_OFFLINE_HARD) {
					// we didn't find it. Create it
					/*
					struct ev_io *watcher = (struct ev_io *)malloc(sizeof(struct ev_io));
					gtid_is = new GTID_Server_Data(watcher, mysrvc->address, mysrvc->port, mysrvc->gtid_port);
					gtid_map.emplace(s1,gtid_is);
					*/
					struct ev_io * c = NULL;
					c = new_connector(mysrvc->address, mysrvc->gtid_port, mysrvc->port);
					if (c) {
						gtid_is = (GTID_Server_Data *)c->data;
						gtid_map.emplace(s1,gtid_is);
						//pthread_mutex_lock(&ev_loop_mutex);
						ev_io_start(MyHGM->gtid_ev_loop,c);
						//pthread_mutex_unlock(&ev_loop_mutex);
					}
				}
			}
		}
	}
	wrunlock();
	std::vector<string> to_remove;
	it = gtid_map.begin();
	while(it != gtid_map.end()) {
		GTID_Server_Data * gtid_si = it->second;
		if (gtid_si && gtid_si->active == false) {
			to_remove.push_back(it->first);
		}
		it++;
	}
	for (std::vector<string>::iterator it3=to_remove.begin(); it3!=to_remove.end(); ++it3) {
		it = gtid_map.find(*it3);
		GTID_Server_Data * gtid_si = it->second;
		ev_io_stop(MyHGM->gtid_ev_loop, gtid_si->w);
		close(gtid_si->w->fd);
		free(gtid_si->w);
		gtid_map.erase(*it3);
	}
	pthread_rwlock_unlock(&gtid_rwlock);
}

/**
 * @brief Purge the MySQL servers table by removing offline hard servers with no active connections.
 *
 * This function iterates through each host group in the host groups manager and examines each server within the host group.
 * For each server that is marked as offline hard and has no active connections (both used and free), it removes the server from the host group.
 * After removing the server, it deletes the server object to free up memory.
 * This process ensures that offline hard servers with no connections are properly removed from the MySQL servers table.
 */
void MySQL_HostGroups_Manager::purge_mysql_servers_table() {
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		MySrvC *mysrvc=NULL;
		for (unsigned int j=0; j<myhgc->mysrvs->servers->len; j++) {
			mysrvc=myhgc->mysrvs->idx(j);
			if (mysrvc->get_status() == MYSQL_SERVER_STATUS_OFFLINE_HARD) {
				if (mysrvc->ConnectionsUsed->conns_length()==0 && mysrvc->ConnectionsFree->conns_length()==0) {
					// no more connections for OFFLINE_HARD server, removing it
					mysrvc=(MySrvC *)myhgc->mysrvs->servers->remove_index_fast(j);
					// already being refreshed in MySrvC destructor
					//myhgc->refresh_online_server_count(); 
					j--;
					delete mysrvc;
				}
			}
		}
	}
}



void MySQL_HostGroups_Manager::generate_mysql_servers_table(int *_onlyhg) {
	int rc;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;

	PtrArray *lst=new PtrArray();
	//sqlite3 *mydb3=mydb->get_db();
	char *query1=(char *)"INSERT INTO mysql_servers VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	rc = mydb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, mydb);
	std::string query32s = "INSERT INTO mysql_servers VALUES " + generate_multi_rows_query(32,13);
	char *query32 = (char *)query32s.c_str();
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
	rc = mydb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, mydb);

	if (mysql_thread___hostgroup_manager_verbose) {
		if (_onlyhg==NULL) {
			proxy_info("Dumping current MySQL Servers structures for hostgroup ALL\n");
		} else {
			int hidonly=*_onlyhg;
			proxy_info("Dumping current MySQL Servers structures for hostgroup %d\n", hidonly);
		}
	}
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		if (_onlyhg) {
			int hidonly=*_onlyhg;
			if (myhgc->hid!=(unsigned int)hidonly) {
				// skipping this HG
				continue;
			}
		}
		MySrvC *mysrvc=NULL;
		for (unsigned int j=0; j<myhgc->mysrvs->servers->len; j++) {
			mysrvc=myhgc->mysrvs->idx(j);
			if (mysql_thread___hostgroup_manager_verbose) {
				char *st;
				switch ((int)mysrvc->get_status()) {
					case 0:
						st=(char *)"ONLINE";
						break;
					case 2:
						st=(char *)"OFFLINE_SOFT";
						break;
					case 3:
						st=(char *)"OFFLINE_HARD";
						break;
					default:
					case 1:
					case 4:
						st=(char *)"SHUNNED";
						break;
				}
				fprintf(stderr,"HID: %d , address: %s , port: %d , gtid_port: %d , weight: %ld , status: %s , max_connections: %ld , max_replication_lag: %u , use_ssl: %u , max_latency_ms: %u , comment: %s\n", mysrvc->myhgc->hid, mysrvc->address, mysrvc->port, mysrvc->gtid_port, mysrvc->weight, st, mysrvc->max_connections, mysrvc->max_replication_lag, mysrvc->use_ssl, mysrvc->max_latency_us*1000, mysrvc->comment);
			}
			lst->add(mysrvc);
			if (lst->len==32) {
				while (lst->len) {
					int i=lst->len;
					i--;
					MySrvC *mysrvc=(MySrvC *)lst->remove_index_fast(0);
					uintptr_t ptr=(uintptr_t)mysrvc;
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+1, mysrvc->myhgc->hid); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_text)(statement32, (i*13)+2, mysrvc->address, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+3, mysrvc->port); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+4, mysrvc->gtid_port); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+5, mysrvc->weight); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+6, (int)mysrvc->get_status()); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+7, mysrvc->compression); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+8, mysrvc->max_connections); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+9, mysrvc->max_replication_lag); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+10, mysrvc->use_ssl); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+11, mysrvc->max_latency_us/1000); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_text)(statement32, (i*13)+12, mysrvc->comment, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+13, ptr); ASSERT_SQLITE_OK(rc, mydb);
				}
				SAFE_SQLITE3_STEP2(statement32);
				rc=(*proxy_sqlite3_clear_bindings)(statement32); ASSERT_SQLITE_OK(rc, mydb);
				rc=(*proxy_sqlite3_reset)(statement32); ASSERT_SQLITE_OK(rc, mydb);
			}
		}
	}
	while (lst->len) {
		MySrvC *mysrvc=(MySrvC *)lst->remove_index_fast(0);
		uintptr_t ptr=(uintptr_t)mysrvc;
		rc=(*proxy_sqlite3_bind_int64)(statement1, 1, mysrvc->myhgc->hid); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_text)(statement1, 2, mysrvc->address, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 3, mysrvc->port); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 4, mysrvc->gtid_port); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 5, mysrvc->weight); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 6, (int)mysrvc->get_status()); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 7, mysrvc->compression); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 8, mysrvc->max_connections); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 9, mysrvc->max_replication_lag); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 10, mysrvc->use_ssl); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 11, mysrvc->max_latency_us/1000); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_text)(statement1, 12, mysrvc->comment, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 13, ptr); ASSERT_SQLITE_OK(rc, mydb);

		SAFE_SQLITE3_STEP2(statement1);
		rc=(*proxy_sqlite3_clear_bindings)(statement1); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_reset)(statement1); ASSERT_SQLITE_OK(rc, mydb);
	}
	(*proxy_sqlite3_finalize)(statement1);
	(*proxy_sqlite3_finalize)(statement32);
	if (mysql_thread___hostgroup_manager_verbose) {
		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		if (_onlyhg==NULL) {
			mydb->execute_statement((char *)"SELECT hostgroup_id hid, hostname, port, gtid_port gtid, weight, status, compression cmp, max_connections max_conns, max_replication_lag max_lag, use_ssl ssl, max_latency_ms max_lat, comment, mem_pointer FROM mysql_servers", &error , &cols , &affected_rows , &resultset);
		} else {
			int hidonly=*_onlyhg;
			char *q1 = (char *)malloc(256);
			sprintf(q1,"SELECT hostgroup_id hid, hostname, port, gtid_port gtid, weight, status, compression cmp, max_connections max_conns, max_replication_lag max_lag, use_ssl ssl, max_latency_ms max_lat, comment, mem_pointer FROM mysql_servers WHERE hostgroup_id=%d" , hidonly);
			mydb->execute_statement(q1, &error , &cols , &affected_rows , &resultset);
			free(q1);
		}
		if (error) {
			proxy_error("Error on read from mysql_servers : %s\n", error);
		} else {
			if (resultset) {
				if (_onlyhg==NULL) {
					proxy_info("Dumping mysql_servers: ALL\n");
				} else {
					int hidonly=*_onlyhg;
					proxy_info("Dumping mysql_servers: HG %d\n", hidonly);
				}
				resultset->dump_to_stderr();
			}
		}
		if (resultset) { delete resultset; resultset=NULL; }
	}
	delete lst;
}

/**
 * @brief Generate the mysql_replication_hostgroups table based on incoming data.
 *
 * This function populates the mysql_replication_hostgroups table in the host groups manager database
 * using the incoming replication hostgroups data. It iterates through each row of the incoming data,
 * constructs an SQL INSERT query to insert the data into the table, and executes the query.
 * If verbose mode is enabled, it logs information about each row being processed.
 *
 * @note This function assumes that the incoming_replication_hostgroups member variable is not NULL.
 *       If it is NULL, the function returns without performing any action.
 */
void MySQL_HostGroups_Manager::generate_mysql_replication_hostgroups_table() {
	if (incoming_replication_hostgroups==NULL)
		return;
	if (mysql_thread___hostgroup_manager_verbose) {
		proxy_info("New mysql_replication_hostgroups table\n");
	}
	for (std::vector<SQLite3_row *>::iterator it = incoming_replication_hostgroups->rows.begin() ; it != incoming_replication_hostgroups->rows.end(); ++it) {
		SQLite3_row *r=*it;
		char *o=NULL;
		int comment_length=0;	// #issue #643
		//if (r->fields[3]) { // comment is not null
			o=escape_string_single_quotes(r->fields[3],false);
			comment_length=strlen(o);
		//}
		char *query=(char *)malloc(256+comment_length);
		//if (r->fields[3]) { // comment is not null
			sprintf(query,"INSERT INTO mysql_replication_hostgroups VALUES(%s,%s,'%s','%s')",r->fields[0], r->fields[1], r->fields[2], o);
			if (o!=r->fields[3]) { // there was a copy
				free(o);
			}
		//} else {
			//sprintf(query,"INSERT INTO mysql_replication_hostgroups VALUES(%s,%s,NULL)",r->fields[0],r->fields[1]);
		//}
		mydb->execute(query);
		if (mysql_thread___hostgroup_manager_verbose) {
			fprintf(stderr,"writer_hostgroup: %s , reader_hostgroup: %s, check_type %s, comment: %s\n", r->fields[0],r->fields[1], r->fields[2], r->fields[3]);
		}
		free(query);
	}
	incoming_replication_hostgroups=NULL;
}


void MySQL_HostGroups_Manager::generate_mysql_group_replication_hostgroups_table() {
	if (incoming_group_replication_hostgroups==NULL) {
		return;
	}
	int rc;
	sqlite3_stmt *statement=NULL;
	//sqlite3 *mydb3=mydb->get_db();
	char *query=(char *)"INSERT INTO mysql_group_replication_hostgroups(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query, -1, &statement, 0);
	rc = mydb->prepare_v2(query, &statement);
	ASSERT_SQLITE_OK(rc, mydb);
	proxy_info("New mysql_group_replication_hostgroups table\n");
	pthread_mutex_lock(&Group_Replication_Info_mutex);
	for (std::map<int , Group_Replication_Info *>::iterator it1 = Group_Replication_Info_Map.begin() ; it1 != Group_Replication_Info_Map.end(); ++it1) {
		Group_Replication_Info *info=NULL;
		info=it1->second;
		info->__active=false;
	}
	for (std::vector<SQLite3_row *>::iterator it = incoming_group_replication_hostgroups->rows.begin() ; it != incoming_group_replication_hostgroups->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int writer_hostgroup=atoi(r->fields[0]);
		int backup_writer_hostgroup=atoi(r->fields[1]);
		int reader_hostgroup=atoi(r->fields[2]);
		int offline_hostgroup=atoi(r->fields[3]);
		int active=atoi(r->fields[4]);
		int max_writers=atoi(r->fields[5]);
		int writer_is_also_reader=atoi(r->fields[6]);
		int max_transactions_behind=atoi(r->fields[7]);
		proxy_info("Loading MySQL Group Replication info for (%d,%d,%d,%d,%s,%d,%d,%d,\"%s\")\n", writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,(active ? "on" : "off"),max_writers,writer_is_also_reader,max_transactions_behind,r->fields[8]);
		rc=(*proxy_sqlite3_bind_int64)(statement, 1, writer_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 2, backup_writer_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 3, reader_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 4, offline_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 5, active); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 6, max_writers); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 7, writer_is_also_reader); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 8, max_transactions_behind); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_text)(statement, 9, r->fields[8], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);

		SAFE_SQLITE3_STEP2(statement);
		rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, mydb);
		std::map<int , Group_Replication_Info *>::iterator it2;
		it2 = Group_Replication_Info_Map.find(writer_hostgroup);
		Group_Replication_Info *info=NULL;
		if (it2!=Group_Replication_Info_Map.end()) {
			info=it2->second;
			bool changed=false;
			changed=info->update(backup_writer_hostgroup,reader_hostgroup,offline_hostgroup, max_writers, max_transactions_behind,  (bool)active, writer_is_also_reader, r->fields[8]);
			if (changed) {
				//info->need_converge=true;
			}
		} else {
			info=new Group_Replication_Info(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup, max_writers, max_transactions_behind,  (bool)active, writer_is_also_reader, r->fields[8]);
			//info->need_converge=true;
			Group_Replication_Info_Map.insert(Group_Replication_Info_Map.begin(), std::pair<int, Group_Replication_Info *>(writer_hostgroup,info));
		}
	}
	(*proxy_sqlite3_finalize)(statement);
	delete incoming_group_replication_hostgroups;
	incoming_group_replication_hostgroups=NULL;

	// remove missing ones
	for (auto it3 = Group_Replication_Info_Map.begin(); it3 != Group_Replication_Info_Map.end(); ) {
		Group_Replication_Info *info=it3->second;
		if (info->__active==false) {
			delete info;
			it3 = Group_Replication_Info_Map.erase(it3);
		} else {
			it3++;
		}
	}
	// TODO: it is now time to compute all the changes


	// it is now time to build a new structure in Monitor
	generate_mysql_group_replication_hostgroups_monitor_resultset();
	pthread_mutex_unlock(&Group_Replication_Info_mutex);
}

void MySQL_HostGroups_Manager::generate_mysql_group_replication_hostgroups_monitor_resultset() {
	pthread_mutex_lock(&GloMyMon->group_replication_mutex);
	{
		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		char *query=(char *)"SELECT writer_hostgroup, hostname, port, MAX(use_ssl) use_ssl , writer_is_also_reader , max_transactions_behind FROM "
			" mysql_servers JOIN mysql_group_replication_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=backup_writer_hostgroup OR "
			" hostgroup_id=reader_hostgroup OR hostgroup_id=offline_hostgroup WHERE active=1 GROUP BY hostname, port";
		mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		if (resultset) {
			if (GloMyMon->Group_Replication_Hosts_resultset) {
				delete GloMyMon->Group_Replication_Hosts_resultset;
			}
			GloMyMon->Group_Replication_Hosts_resultset=resultset;
		}
	}
	pthread_mutex_unlock(&GloMyMon->group_replication_mutex);
}

void MySQL_HostGroups_Manager::generate_mysql_galera_hostgroups_table() {
	if (incoming_galera_hostgroups==NULL) {
		return;
	}
	int rc;
	sqlite3_stmt *statement=NULL;
	//sqlite3 *mydb3=mydb->get_db();
	char *query=(char *)"INSERT INTO mysql_galera_hostgroups(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query, -1, &statement, 0);
	rc = mydb->prepare_v2(query, &statement);
	ASSERT_SQLITE_OK(rc, mydb);
	proxy_info("New mysql_galera_hostgroups table\n");
	pthread_mutex_lock(&Galera_Info_mutex);
	for (std::map<int , Galera_Info *>::iterator it1 = Galera_Info_Map.begin() ; it1 != Galera_Info_Map.end(); ++it1) {
		Galera_Info *info=NULL;
		info=it1->second;
		info->__active=false;
	}
	for (std::vector<SQLite3_row *>::iterator it = incoming_galera_hostgroups->rows.begin() ; it != incoming_galera_hostgroups->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int writer_hostgroup=atoi(r->fields[0]);
		int backup_writer_hostgroup=atoi(r->fields[1]);
		int reader_hostgroup=atoi(r->fields[2]);
		int offline_hostgroup=atoi(r->fields[3]);
		int active=atoi(r->fields[4]);
		int max_writers=atoi(r->fields[5]);
		int writer_is_also_reader=atoi(r->fields[6]);
		int max_transactions_behind=atoi(r->fields[7]);
		proxy_info("Loading Galera info for (%d,%d,%d,%d,%s,%d,%d,%d,\"%s\")\n", writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,(active ? "on" : "off"),max_writers,writer_is_also_reader,max_transactions_behind,r->fields[8]);
		rc=(*proxy_sqlite3_bind_int64)(statement, 1, writer_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 2, backup_writer_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 3, reader_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 4, offline_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 5, active); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 6, max_writers); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 7, writer_is_also_reader); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 8, max_transactions_behind); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_text)(statement, 9, r->fields[8], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);

		SAFE_SQLITE3_STEP2(statement);
		rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, mydb);
		std::map<int , Galera_Info *>::iterator it2;
		it2 = Galera_Info_Map.find(writer_hostgroup);
		Galera_Info *info=NULL;
		if (it2!=Galera_Info_Map.end()) {
			info=it2->second;
			bool changed=false;
			changed=info->update(backup_writer_hostgroup,reader_hostgroup,offline_hostgroup, max_writers, max_transactions_behind,  (bool)active, writer_is_also_reader, r->fields[8]);
			if (changed) {
				//info->need_converge=true;
			}
		} else {
			info=new Galera_Info(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup, max_writers, max_transactions_behind,  (bool)active, writer_is_also_reader, r->fields[8]);
			//info->need_converge=true;
			Galera_Info_Map.insert(Galera_Info_Map.begin(), std::pair<int, Galera_Info *>(writer_hostgroup,info));
		}
	}
	(*proxy_sqlite3_finalize)(statement);
	delete incoming_galera_hostgroups;
	incoming_galera_hostgroups=NULL;

	// remove missing ones
	for (auto it3 = Galera_Info_Map.begin(); it3 != Galera_Info_Map.end(); ) {
		Galera_Info *info=it3->second;
		if (info->__active==false) {
			delete info;
			it3 = Galera_Info_Map.erase(it3);
		} else {
			it3++;
		}
	}
	// TODO: it is now time to compute all the changes


	// it is now time to build a new structure in Monitor
	pthread_mutex_lock(&GloMyMon->galera_mutex);
	{
		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		char *query=(char *)"SELECT writer_hostgroup, hostname, port, MAX(use_ssl) use_ssl , writer_is_also_reader , max_transactions_behind "
			" FROM mysql_servers JOIN mysql_galera_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=backup_writer_hostgroup OR "
			" hostgroup_id=reader_hostgroup OR hostgroup_id=offline_hostgroup WHERE active=1 GROUP BY writer_hostgroup, hostname, port";
		mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		if (resultset) {
			if (GloMyMon->Galera_Hosts_resultset) {
				delete GloMyMon->Galera_Hosts_resultset;
			}
			GloMyMon->Galera_Hosts_resultset=resultset;
		}
	}
	pthread_mutex_unlock(&GloMyMon->galera_mutex);

	pthread_mutex_unlock(&Galera_Info_mutex);
}

void MySQL_HostGroups_Manager::update_table_mysql_servers_for_monitor(bool lock) {
	if (lock) {
		wrlock();
	}

	std::lock_guard<std::mutex> mysql_servers_lock(this->mysql_servers_to_monitor_mutex);

	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* resultset = NULL;
	const char* query = "SELECT hostname, port, status, use_ssl FROM mysql_servers WHERE status != 3 GROUP BY hostname, port";

	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
	mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);

	if (error != nullptr) {
		proxy_error("Error on read from mysql_servers : %s\n", error);
	} else {
		if (resultset != nullptr) {
			delete this->mysql_servers_to_monitor;
			this->mysql_servers_to_monitor = resultset;
		}
	}

	if (lock) {
		wrunlock();
	}

	MySQL_Monitor::trigger_dns_cache_update();
}

/**
 * @brief Dump data from a specified MySQL table.
 *
 * This function retrieves data from the specified MySQL table and returns it as a result set.
 * The table name determines the SQL query to be executed to fetch the data. If the table is
 * one of the predefined tables with special handling (e.g., mysql_servers), additional actions
 * such as purging and generating the table may be performed before fetching the data.
 *
 * @param name The name of the MySQL table from which to dump data.
 * @return A SQLite3_result pointer representing the result set containing the dumped data.
 *         The caller is responsible for managing the memory of the result set.
 * @note If the provided table name is not recognized, the function assertion fails.
 */
SQLite3_result * MySQL_HostGroups_Manager::dump_table_mysql(const string& name) {
	char * query = (char *)"";
	if (name == "mysql_aws_aurora_hostgroups") {
		query=(char *)"SELECT writer_hostgroup,reader_hostgroup,active,aurora_port,domain_name,max_lag_ms,"
					    "check_interval_ms,check_timeout_ms,writer_is_also_reader,new_reader_weight,add_lag_ms,min_lag_ms,lag_num_checks,comment FROM mysql_aws_aurora_hostgroups";
	} else if (name == "mysql_galera_hostgroups") {
		query=(char *)"SELECT writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment FROM mysql_galera_hostgroups";
	} else if (name == "mysql_group_replication_hostgroups") {
		query=(char *)"SELECT writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment FROM mysql_group_replication_hostgroups";
	} else if (name == "mysql_replication_hostgroups") {
		query=(char *)"SELECT writer_hostgroup, reader_hostgroup, check_type, comment FROM mysql_replication_hostgroups";
	} else if (name == "mysql_hostgroup_attributes") {
		query=(char *)"SELECT hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, init_connect, multiplex, connection_warming, throttle_connections_per_sec, ignore_session_variables, hostgroup_settings, servers_defaults, comment FROM mysql_hostgroup_attributes ORDER BY hostgroup_id";
	} else if (name == "mysql_servers_ssl_params") {
		query=(char *)"SELECT hostname, port, username, ssl_ca, ssl_cert, ssl_key, ssl_capath, ssl_crl, ssl_crlpath, ssl_cipher, tls_version, comment FROM mysql_servers_ssl_params ORDER BY hostname, port, username";
	} else if (name == "mysql_servers") {
		query = (char *)MYHGM_GEN_ADMIN_RUNTIME_SERVERS;
	} else if (name == "cluster_mysql_servers") {
		query = (char *)MYHGM_GEN_CLUSTER_ADMIN_RUNTIME_SERVERS;
	} else {
		assert(0);
	}
	wrlock();
	if (name == "mysql_servers") {
		purge_mysql_servers_table();
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_servers\n");
		mydb->execute("DELETE FROM mysql_servers");
		generate_mysql_servers_table();
	}
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
	mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	wrunlock();
	return resultset;
}

void MySQL_HostGroups_Manager::increase_reset_counter() {
	wrlock();
	status.myconnpoll_reset++;
	wrunlock();
}

/**
 * @brief Pushes a MySQL_Connection back to the connection pool.
 *
 * This method is responsible for returning a MySQL_Connection object back to its associated connection pool
 * after it has been used. It performs various checks and optimizations before deciding whether to return
 * the connection to the pool or destroy it.
 *
 * @param c The MySQL_Connection object to be pushed back to the pool.
 * @param _lock Boolean flag indicating whether to acquire a lock before performing the operation. Default is true.
 *
 * @note The method assumes that the provided MySQL_Connection object has a valid parent server (MySrvC).
 * If the parent server is not valid, unexpected behavior may occur.
 *
 * @note The method also assumes that the global thread handler (GloMTH) is available and initialized properly.
 * If the global thread handler is not initialized, certain checks may fail, leading to unexpected behavior.
 */
void MySQL_HostGroups_Manager::push_MyConn_to_pool(MySQL_Connection *c, bool _lock) {
	// Ensure that the provided connection has a valid parent server
	assert(c->parent);

	MySrvC *mysrvc = nullptr; // Pointer to the parent server object

	// Acquire a lock if specified
	if (_lock)
		wrlock();

	// Reset the auto-increment delay token associated with the connection
	c->auto_increment_delay_token = 0;

	// Increment the counter tracking the number of connections pushed back to the pool
	status.myconnpoll_push++;

	// Obtain a pointer to the parent server (MySrvC)
	mysrvc = static_cast<MySrvC *>(c->parent);

	// Log debug information about the connection being returned to the pool
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL_Connection %p, server %s:%d with status %d\n", c, mysrvc->address, mysrvc->port, (int)mysrvc->get_status());

	// Remove the connection from the list of used connections for the parent server
	mysrvc->ConnectionsUsed->remove(c);

	// If the global thread handler (GloMTH) is not available, skip further processing
	if (GloMTH == nullptr) {
		goto __exit_push_MyConn_to_pool;
	}

	// If the largest query length exceeds the threshold, destroy the connection
	if (c->largest_query_length > (unsigned int)GloMTH->variables.threshold_query_length) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d with status %d . largest_query_length = %lu\n", c, mysrvc->address, mysrvc->port, (int)mysrvc->get_status(), c->largest_query_length);
		delete c;
		goto __exit_push_MyConn_to_pool;
	}	

	// If the server is online and the connection is in the idle state
	if (mysrvc->get_status() == MYSQL_SERVER_STATUS_ONLINE) {
		if (c->async_state_machine==ASYNC_IDLE) {
			if (GloMTH == NULL) { goto __exit_push_MyConn_to_pool; }
			if (c->local_stmts->get_num_backend_stmts() > (unsigned int)GloMTH->variables.max_stmts_per_connection) {  // Check if the connection has too many prepared statements
				// Log debug information about destroying the connection due to too many prepared statements
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d with status %d because has too many prepared statements\n", c, mysrvc->address, mysrvc->port, (int)mysrvc->get_status());
//				delete c;
				mysrvc->ConnectionsUsed->add(c); // Add the connection back to the list of used connections
				destroy_MyConn_from_pool(c, false); // Destroy the connection from the pool
			} else {
				c->optimize(); // Optimize the connection
				mysrvc->ConnectionsFree->add(c); // Add the connection to the list of free connections
			}
		} else {
			// Log debug information about destroying the connection
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d with status %d\n", c, mysrvc->address, mysrvc->port, (int)mysrvc->get_status());
			delete c; // Destroy the connection
		}
	} else {
		// Log debug information about destroying the connection
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d with status %d\n", c, mysrvc->address, mysrvc->port, (int)mysrvc->get_status());
		delete c; // Destroy the connection
	}

// Exit point for releasing the lock
__exit_push_MyConn_to_pool:
	if (_lock)
		wrunlock(); // Release the lock if acquired
}

/**
 * @brief Pushes an array of MySQL_Connection objects back to the connection pool.
 *
 * This method is responsible for returning an array of MySQL_Connection objects back to their associated
 * connection pool after they have been used. It iterates through the array and calls the push_MyConn_to_pool
 * method for each connection without acquiring a lock for each individual push operation.
 *
 * @param ca An array of MySQL_Connection pointers representing the connections to be pushed back to the pool.
 * @param cnt The number of connections in the array.
 *
 * @note This method assumes that the array of connections is valid and does not contain any nullptr entries.
 * Unexpected behavior may occur if the array contains invalid pointers.
 */
void MySQL_HostGroups_Manager::push_MyConn_to_pool_array(MySQL_Connection **ca, unsigned int cnt) {
	unsigned int i=0; // Index variable for iterating through the array
	MySQL_Connection *c = nullptr; // Pointer to hold the current connection from the array
	c=ca[i];

	// Acquire a write lock to perform the operations atomically
	wrlock();

	// Iterate through the array of connections
	while (i<cnt) {
		// Push the current connection back to the pool without acquiring a lock for each individual push
		push_MyConn_to_pool(c,false);
		i++;
		if (i<cnt)
			c=ca[i];
	}

	// Release the write lock after processing all connections in the array
	wrunlock();
}

void MySQL_HostGroups_Manager::unshun_server_all_hostgroups(const char * address, uint16_t port, time_t t, int max_wait_sec, unsigned int *skip_hid) {
	// we scan all hostgroups looking for a specific server to unshun
	// if skip_hid is not NULL , the specific hostgroup is skipped
	if (GloMTH->variables.hostgroup_manager_verbose >= 3) {
		char buf[64];
		if (skip_hid == NULL) {
			sprintf(buf,"NULL");
		} else {
			sprintf(buf,"%u", *skip_hid);
		}
		proxy_info("Calling unshun_server_all_hostgroups() for server %s:%d . Arguments: %lu , %d , %s\n" , address, port, t, max_wait_sec, buf);
	}
	int i, j;
	for (i=0; i<(int)MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		if (skip_hid != NULL && myhgc->hid == *skip_hid) {
			// if skip_hid is not NULL, we skip that specific hostgroup
			continue;
		}
		bool found = false; // was this server already found in this hostgroup?
		for (j=0; found==false && j<(int)myhgc->mysrvs->cnt(); j++) {
			MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
			if (mysrvc->get_status() == MYSQL_SERVER_STATUS_SHUNNED) {
				// we only care for SHUNNED nodes
				// Note that we check for address and port only for status==MYSQL_SERVER_STATUS_SHUNNED ,
				// that means that potentially we will pass by the matching node and still looping .
				// This is potentially an optimization because we only check status and do not perform any strcmp()
				if (strcmp(mysrvc->address,address)==0 && mysrvc->port==port) {
					// we found the server in this hostgroup
					// no need to process more servers in the same hostgroup
					found = true;
					if (t > mysrvc->time_last_detected_error && (t - mysrvc->time_last_detected_error) > max_wait_sec) {
						if (
							(mysrvc->shunned_and_kill_all_connections==false) // it is safe to bring it back online
							||
							(mysrvc->shunned_and_kill_all_connections==true && mysrvc->ConnectionsUsed->conns_length()==0 && mysrvc->ConnectionsFree->conns_length()==0) // if shunned_and_kill_all_connections is set, ensure all connections are already dropped
						) {
							if (GloMTH->variables.hostgroup_manager_verbose >= 3) {
								proxy_info("Unshunning server %d:%s:%d . time_last_detected_error=%lu\n", mysrvc->myhgc->hid, address, port, mysrvc->time_last_detected_error);
							}
							mysrvc->set_status(MYSQL_SERVER_STATUS_ONLINE);
							mysrvc->shunned_automatic=false;
							mysrvc->shunned_and_kill_all_connections=false;
							mysrvc->connect_ERR_at_time_last_detected_error=0;
							mysrvc->time_last_detected_error=0;
						}
					}
				}
			}
		}
	}
}

/**
 * @brief Retrieves a MySQL_Connection from the connection pool for a given hostgroup.
 *
 * This method is responsible for retrieving a MySQL_Connection from the connection pool associated
 * with the specified hostgroup. It selects a random MySQL server within the hostgroup based on various
 * criteria such as GTID information, maximum lag, and session attributes. If a suitable connection is found,
 * it is marked as used and returned to the caller.
 *
 * @param _hid The ID of the hostgroup from which to retrieve the connection.
 * @param sess A pointer to the MySQL_Session object associated with the connection.
 * @param ff A boolean flag indicating whether to prioritize failover connections.
 * @param gtid_uuid The GTID UUID used for GTID-based routing.
 * @param gtid_trxid The GTID transaction ID used for GTID-based routing.
 * @param max_lag_ms The maximum allowed lag in milliseconds.
 *
 * @return A pointer to the retrieved MySQL_Connection object if successful, or nullptr if no suitable connection
 *         is available in the pool.
 *
 * @note This method locks the connection pool to ensure thread safety during access. It releases the lock once
 *       the operation is completed.
 */
MySQL_Connection * MySQL_HostGroups_Manager::get_MyConn_from_pool(unsigned int _hid, MySQL_Session *sess, bool ff, char * gtid_uuid, uint64_t gtid_trxid, int max_lag_ms) {
	MySQL_Connection * conn = nullptr; // Pointer to hold the retrieved MySQL_Connection

	// Acquire a write lock to access the connection pool
	wrlock();

	// Increment the counter for connection pool retrieval attempts
	status.myconnpoll_get++;

	// Look up the hostgroup by ID and retrieve a random MySQL server from it based on specified criteria
	MyHGC *myhgc=MyHGC_lookup(_hid);
	MySrvC *mysrvc = NULL;
#ifdef TEST_AURORA
	for (int i=0; i<10; i++)
#endif // TEST_AURORA
	mysrvc = myhgc->get_random_MySrvC(gtid_uuid, gtid_trxid, max_lag_ms, sess);
	if (mysrvc) { // a MySrvC exists. If not, we return NULL = no targets
		// Attempt to get a random MySQL_Connection from the server's free connection pool
		conn=mysrvc->ConnectionsFree->get_random_MyConn(sess, ff);

		// If a connection is obtained, mark it as used and update connection pool statistics
		if (conn) {
			mysrvc->ConnectionsUsed->add(conn);
			status.myconnpoll_get_ok++;
			mysrvc->update_max_connections_used();
		}
	}

	// Release the write lock after accessing the connection pool
	wrunlock();

	// Debug message indicating the retrieved MySQL_Connection and its server details
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, (conn ? conn->parent->address : "") , (conn ? conn->parent->port : 0 ));

	// Return the retrieved MySQL_Connection (or nullptr if none available)
	return conn;
}

void MySQL_HostGroups_Manager::destroy_MyConn_from_pool(MySQL_Connection *c, bool _lock) {
	// 'libmariadbclient' only performs a cleanup of SSL error queue during connect when making use of
	// 'auth_caching_sha2_client|auth_sha256_client' during connect. If any SSL errors took place during the
	// previous operation, we must cleanup the queue to avoid polluting other backend conns.
	int myerr=mysql_errno(c->mysql);
	if (myerr >= 2000 && myerr < 3000 && c->mysql->options.use_ssl) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Client error %d detected on SSL connection, cleaning SSL error queue\n", myerr);
		ERR_clear_error();
	}

	bool to_del=true; // the default, legacy behavior
	MySrvC *mysrvc=(MySrvC *)c->parent;
	if (mysrvc->get_status() == MYSQL_SERVER_STATUS_ONLINE && c->send_quit && queue.size() < __sync_fetch_and_add(&GloMTH->variables.connpoll_reset_queue_length, 0)) {
		if (c->async_state_machine==ASYNC_IDLE) {
			// overall, the backend seems healthy and so it is the connection. Try to reset it
			int myerr=mysql_errno(c->mysql);
			if (myerr >= 2000 && myerr < 3000) {
				// client library error . We must not try to save the connection
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Not trying to reset MySQL_Connection %p, server %s:%d . Error code %d\n", c, mysrvc->address, mysrvc->port, myerr);
			} else {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Trying to reset MySQL_Connection %p, server %s:%d\n", c, mysrvc->address, mysrvc->port);
				to_del=false;
				queue.add(c);
			}
		} else {
		// the connection seems health, but we are trying to destroy it
		// probably because there is a long running query
		// therefore we will try to kill the connection
			if (mysql_thread___kill_backend_connection_when_disconnect) {
				int myerr=mysql_errno(c->mysql);
				switch (myerr) {
					case 1231:
						break;
					default:
					if (c->mysql->thread_id) {
						MySQL_Connection_userinfo *ui=c->userinfo;
						char *auth_password=NULL;
						if (ui->password) {
							if (ui->password[0]=='*') { // we don't have the real password, let's pass sha1
								auth_password=ui->sha1_pass;
							} else {
								auth_password=ui->password;
							}
						}
						KillArgs *ka = new KillArgs(ui->username, auth_password, c->parent->address, c->parent->port, c->parent->myhgc->hid, c->mysql->thread_id, KILL_CONNECTION, c->parent->use_ssl, NULL, c->connected_host_details.ip);
						pthread_attr_t attr;
						pthread_attr_init(&attr);
						pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
						pthread_attr_setstacksize (&attr, 256*1024);
						pthread_t pt;
						if (pthread_create(&pt, &attr, &kill_query_thread, ka) != 0) {
							// LCOV_EXCL_START
							proxy_error("Thread creation\n");
							assert(0);
							// LCOV_EXCL_STOP
						}
					}
						break;
				}
			}
		}
	}
	if (to_del) {
		// we lock only this part of the code because we need to remove the connection from ConnectionsUsed
		if (_lock) {
			wrlock();
		}
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d\n", c, mysrvc->address, mysrvc->port);
		mysrvc->ConnectionsUsed->remove(c);
		status.myconnpoll_destroy++;
                if (_lock) {
			wrunlock();
		}
		delete c;
	}
}

inline double get_prometheus_counter_val(
	std::map<std::string, prometheus::Counter*>& counter_map, const std::string& endpoint_id
) {
	const auto& counter_entry = counter_map.find(endpoint_id);
	double current_val = 0;

	if (counter_entry != counter_map.end()) {
		current_val = counter_entry->second->Value();
	}

	return current_val;
}

void reset_hg_attrs_server_defaults(MySrvC* mysrvc) {
	mysrvc->weight = -1;
	mysrvc->max_connections = -1;
	mysrvc->use_ssl = -1;
}

void update_hg_attrs_server_defaults(MySrvC* mysrvc, MyHGC* myhgc) {
	if (mysrvc->weight == -1) {
		if (myhgc->servers_defaults.weight != -1) {
			mysrvc->weight = myhgc->servers_defaults.weight;
		} else {
			// Same harcoded default as in 'CREATE TABLE mysql_servers ...'
			mysrvc->weight = 1;
		}
	}
	if (mysrvc->max_connections == -1) {
		if (myhgc->servers_defaults.max_connections != -1) {
			mysrvc->max_connections = myhgc->servers_defaults.max_connections;
		} else {
			// Same harcoded default as in 'CREATE TABLE mysql_servers ...'
			mysrvc->max_connections = 1000;
		}
	}
	if (mysrvc->use_ssl == -1) {
		if (myhgc->servers_defaults.use_ssl != -1) {
			mysrvc->use_ssl = myhgc->servers_defaults.use_ssl;
		} else {
			// Same harcoded default as in 'CREATE TABLE mysql_servers ...'
			mysrvc->use_ssl = 0;
		}
	}
}

/**
 * @brief Adds a MySQL server connection (MySrvC) to the specified hostgroup.
 *
 * This method adds a MySQL server connection (MySrvC) to the hostgroup identified by the given hostgroup ID (_hid).
 * It performs necessary updates to the server metrics and attributes associated with the hostgroup. Additionally, it
 * updates the endpoint metrics for the server based on its address and port.
 *
 * @param mysrvc A pointer to the MySQL server connection (MySrvC) to be added to the hostgroup.
 * @param _hid The ID of the hostgroup to which the server connection is being added.
 *
 * @note The method updates various metrics and attributes associated with the server and hostgroup. It also ensures
 *       that endpoint metrics are updated to reflect the addition of the server to the hostgroup.
 */
void MySQL_HostGroups_Manager::add(MySrvC *mysrvc, unsigned int _hid) {

	// Debug message indicating the addition of the MySQL server connection to the hostgroup
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Adding MySrvC %p (%s:%d) for hostgroup %d\n", mysrvc, mysrvc->address, mysrvc->port, _hid);

	// Construct the endpoint ID using the hostgroup ID, server address, and port
	std::string endpoint_id { std::to_string(_hid) + ":" + string { mysrvc->address } + ":" + std::to_string(mysrvc->port) };

	// Since metrics for servers are stored per-endpoint; the metrics for a particular endpoint can live longer than the
	// 'MySrvC' itself. For example, a failover or a server config change could remove the server from a particular
	// hostgroup, and a subsequent one bring it back to the original hostgroup. For this reason, everytime a 'mysrvc' is
	// created and added to a particular hostgroup, we update the endpoint metrics for it.

	// Update server metrics based on endpoint ID
	mysrvc->bytes_recv = get_prometheus_counter_val(this->status.p_conn_pool_bytes_data_recv_map, endpoint_id);
	mysrvc->bytes_sent = get_prometheus_counter_val(this->status.p_conn_pool_bytes_data_sent_map, endpoint_id);
	mysrvc->connect_ERR = get_prometheus_counter_val(this->status.p_connection_pool_conn_err_map, endpoint_id);
	mysrvc->connect_OK = get_prometheus_counter_val(this->status.p_connection_pool_conn_ok_map, endpoint_id);
	mysrvc->queries_sent = get_prometheus_counter_val(this->status.p_connection_pool_queries_map, endpoint_id);

	// Lookup the hostgroup by ID and add the server connection to it
	MyHGC *myhgc=MyHGC_lookup(_hid);

	// Update server defaults with hostgroup attributes
	update_hg_attrs_server_defaults(mysrvc, myhgc);

	// Add the server to the hostgroup's servers list
	myhgc->mysrvs->add(mysrvc);
}

void MySQL_HostGroups_Manager::replication_lag_action_inner(MyHGC *myhgc, const char *address, unsigned int port, 
	int current_replication_lag, bool override_repl_lag) {
	
	if (current_replication_lag == -1 && override_repl_lag == true) {
		current_replication_lag = myhgc->get_monitor_slave_lag_when_null();
		override_repl_lag = false;
		proxy_error("Replication lag on server %s:%d is NULL, using value %d\n", address, port, current_replication_lag);
	}

	for (int j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
		MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
		if (strcmp(mysrvc->address,address)==0 && mysrvc->port==port) {
			mysrvc->cur_replication_lag = current_replication_lag;
			if (mysrvc->get_status() == MYSQL_SERVER_STATUS_ONLINE) {
				if (
//					(current_replication_lag==-1 )
//					||
					(
						current_replication_lag >= 0 &&
						mysrvc->max_replication_lag > 0 && // see issue #4018
						(current_replication_lag > (int)mysrvc->max_replication_lag)
					)
				) {
					// always increase the counter
					mysrvc->cur_replication_lag_count += 1;
					if (mysrvc->cur_replication_lag_count >= (unsigned int)mysql_thread___monitor_replication_lag_count) {
						proxy_warning("Shunning server %s:%d from HG %u with replication lag of %d second, count number: '%d'\n", address, port, myhgc->hid, current_replication_lag, mysrvc->cur_replication_lag_count);
						mysrvc->set_status(MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG);
					} else {
						proxy_info(
							"Not shunning server %s:%d from HG %u with replication lag of %d second, count number: '%d' < replication_lag_count: '%d'\n",
							address,
							port,
							myhgc->hid,
							current_replication_lag,
							mysrvc->cur_replication_lag_count,
							mysql_thread___monitor_replication_lag_count
						);
					}
				} else {
					mysrvc->cur_replication_lag_count = 0;
				}
			} else {
				if (mysrvc->get_status() == MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) {
					if (
						(/*current_replication_lag >= 0 &&*/override_repl_lag == false &&
						(current_replication_lag <= (int)mysrvc->max_replication_lag))
						||
						(current_replication_lag==-2 && override_repl_lag == true) // see issue 959
					) {
						mysrvc->set_status(MYSQL_SERVER_STATUS_ONLINE);
						proxy_warning("Re-enabling server %s:%d from HG %u with replication lag of %d second\n", address, port, myhgc->hid, current_replication_lag);
						mysrvc->cur_replication_lag_count = 0;
					}
				}
			}
			return;
		}
	}
}

void MySQL_HostGroups_Manager::replication_lag_action(const std::list<replication_lag_server_t>& mysql_servers) {

	//this method does not use admin table, so this lock is not needed. 
	//GloAdmin->mysql_servers_wrlock();
	unsigned long long curtime1 = monotonic_time();
	wrlock();

	for (const auto& server : mysql_servers) {

		const int hid = std::get<REPLICATION_LAG_SERVER_T::RLS_HOSTGROUP_ID>(server);
		const std::string& address = std::get<REPLICATION_LAG_SERVER_T::RLS_ADDRESS>(server);
		const unsigned int port = std::get<REPLICATION_LAG_SERVER_T::RLS_PORT>(server);
		const int current_replication_lag = std::get<REPLICATION_LAG_SERVER_T::RLS_CURRENT_REPLICATION_LAG>(server);
		const bool override_repl_lag = std::get<REPLICATION_LAG_SERVER_T::RLS_OVERRIDE_REPLICATION_LAG>(server);

		if (mysql_thread___monitor_replication_lag_group_by_host == false) {
			// legacy check. 1 check per server per hostgroup
			MyHGC *myhgc = MyHGC_find(hid);
			replication_lag_action_inner(myhgc,address.c_str(),port,current_replication_lag,override_repl_lag);
		}
		else {
			// only 1 check per server, no matter the hostgroup
			// all hostgroups must be searched
			for (unsigned int i=0; i<MyHostGroups->len; i++) {
				MyHGC*myhgc=(MyHGC*)MyHostGroups->index(i);
				replication_lag_action_inner(myhgc,address.c_str(),port,current_replication_lag,override_repl_lag);
			}
		}
	}

	wrunlock();
	//GloAdmin->mysql_servers_wrunlock();

	unsigned long long curtime2 = monotonic_time();
	curtime1 = curtime1 / 1000;
	curtime2 = curtime2 / 1000;
	proxy_debug(PROXY_DEBUG_MONITOR, 7, "MySQL_HostGroups_Manager::replication_lag_action() locked for %llums (server count:%ld)\n", curtime2 - curtime1, mysql_servers.size());
}

/**
 * @brief Finds the supplied server in the provided 'MyHGC' and sets the status
 *   either to 'MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG' if 'enable' is
 *   'false' or 'MYSQL_SERVER_STATUS_ONLINE' if 'true'. If either of the
 *   'myhgc' or 'address' params are 'NULL' the function performs no action,
 *   and returns immediately.
 *
 * @param myhgc The MySQL Hostgroup Container in which to perform the server
 *   search.
 * @param address The server address.
 * @param port The server port.
 * @param lag_count The lag count, computed by 'get_lag_behind_count'.
 * @param enable Boolean specifying if the server should be enabled or not.
 */
void MySQL_HostGroups_Manager::group_replication_lag_action_set_server_status(MyHGC* myhgc, char* address, int port, int lag_count, bool enable) {
	if (myhgc == NULL || address == NULL) return;
	proxy_debug(
		PROXY_DEBUG_MONITOR, 5, "Params - address: %s, port: %d, lag_count: %d, enable: %d\n", address, port,
		lag_count, enable
	);

	for (int j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
		MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
		proxy_debug(
			PROXY_DEBUG_MONITOR, 6, "Server 'MySrvC' - address: %s, port: %d, status: %d\n", mysrvc->address,
			mysrvc->port, (int)mysrvc->get_status()
		);

		if (strcmp(mysrvc->address,address)==0 && mysrvc->port==port) {

			if (enable == true) {
				if (mysrvc->get_status() == MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG || mysrvc->get_status() == MYSQL_SERVER_STATUS_SHUNNED) {
					mysrvc->set_status(MYSQL_SERVER_STATUS_ONLINE);
					proxy_info("Re-enabling server %u:%s:%d from replication lag\n", myhgc->hid, address, port);
				}
			} else {
				if (mysrvc->get_status()==MYSQL_SERVER_STATUS_ONLINE) {
					proxy_warning("Shunning 'soft' server %u:%s:%d with replication lag, count number: %d\n", myhgc->hid, address, port, lag_count);
					mysrvc->set_status(MYSQL_SERVER_STATUS_SHUNNED);
				} else {
					if (mysrvc->get_status()==MYSQL_SERVER_STATUS_SHUNNED) {
						if (lag_count >= ( mysql_thread___monitor_groupreplication_max_transactions_behind_count * 2 )) {
							proxy_warning("Shunning 'hard' server %u:%s:%d with replication lag, count number: %d\n", myhgc->hid, address, port, lag_count);
							mysrvc->set_status(MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG);
						}
					}
				}
			}
		}
	}
}

void MySQL_HostGroups_Manager::group_replication_lag_action(
	int _hid, char *address, unsigned int port, int lag_counts, bool read_only, bool enable
) {
	GloAdmin->mysql_servers_wrlock();
	wrlock();

	int reader_hostgroup = 0;
	// bool writer_is_also_reader = false;

	// Get the reader_hostgroup for the supplied writter hostgroup
	const std::string t_reader_hostgroup_query {
		"SELECT reader_hostgroup,writer_is_also_reader FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d"
	};
	std::string reader_hostgroup_query {};
	string_format(t_reader_hostgroup_query, reader_hostgroup_query, _hid);

	int cols=0;
	char *error=NULL;
	int affected_rows=0;
	SQLite3_result* rhid_res=NULL;
	SQLite3_row* rhid_row=nullptr;

	mydb->execute_statement(
		reader_hostgroup_query.c_str(), &error , &cols , &affected_rows , &rhid_res
	);

	// If the server isn't present in the supplied hostgroup, there is nothing to do.
	if (rhid_res->rows.empty() || rhid_res->rows[0]->get_size() == 0) {
		goto __exit_replication_lag_action;
	}

	rhid_row = rhid_res->rows[0];
	reader_hostgroup = atoi(rhid_row->fields[0]);

	{
		MyHGC* myhgc = nullptr;

		if (
			mysql_thread___monitor_groupreplication_max_transactions_behind_for_read_only == 0 ||
			mysql_thread___monitor_groupreplication_max_transactions_behind_for_read_only == 2 ||
			enable
		) {
			if (read_only == false) {
				myhgc = MyHGM->MyHGC_find(_hid);
				group_replication_lag_action_set_server_status(myhgc, address, port, lag_counts, enable);
			}
		}

		if (
			mysql_thread___monitor_groupreplication_max_transactions_behind_for_read_only == 1 ||
			mysql_thread___monitor_groupreplication_max_transactions_behind_for_read_only == 2 ||
			enable
		) {
			myhgc = MyHGM->MyHGC_find(reader_hostgroup);
			group_replication_lag_action_set_server_status(myhgc, address, port, lag_counts, enable);
		}
	}

	if (rhid_res != nullptr) {
		delete rhid_res;
		rhid_res = nullptr;
	}

__exit_replication_lag_action:

	wrunlock();
	GloAdmin->mysql_servers_wrunlock();
}

void MySQL_HostGroups_Manager::drop_all_idle_connections() {
	// NOTE: the caller should hold wrlock
	int i, j;
	for (i=0; i<(int)MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
			MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
			if (mysrvc->get_status()!=MYSQL_SERVER_STATUS_ONLINE) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d is not online\n", mysrvc->address, mysrvc->port);
				//__sync_fetch_and_sub(&status.server_connections_connected, mysrvc->ConnectionsFree->conns->len);
				mysrvc->ConnectionsFree->drop_all_connections();
			}

			// Drop idle connections if beyond max_connection
			while (mysrvc->ConnectionsFree->conns_length() && mysrvc->ConnectionsUsed->conns_length()+mysrvc->ConnectionsFree->conns_length() > mysrvc->max_connections) {
				MySQL_Connection *conn=mysrvc->ConnectionsFree->remove(0);
				delete conn;
			}

			//PtrArray *pa=mysrvc->ConnectionsFree->conns;
			MySrvConnList *mscl=mysrvc->ConnectionsFree;
			int free_connections_pct = mysql_thread___free_connections_pct;
			if (mysrvc->myhgc->attributes.configured == true) {
				// mysql_hostgroup_attributes takes priority
				free_connections_pct = mysrvc->myhgc->attributes.free_connections_pct;
			}
			while (mscl->conns_length() > free_connections_pct*mysrvc->max_connections/100) {
				MySQL_Connection *mc=mscl->remove(0);
				delete mc;
			}

			// drop all connections with life exceeding mysql-connection_max_age
			if (mysql_thread___connection_max_age_ms) {
				unsigned long long curtime=monotonic_time();
				int i=0;
				for (i=0; i<(int)mscl->conns_length() ; i++) {
					MySQL_Connection *mc=mscl->index(i);
					unsigned long long intv = mysql_thread___connection_max_age_ms;
					intv *= 1000;
					if (curtime > mc->creation_time + intv) {
						mc=mscl->remove(0);
						delete mc;
						i--;
					}
				}
			}

		}
	}
}

/*
 * Prepares at most num_conn idle connections in the given hostgroup for
 * pinging. When -1 is passed as a hostgroup, all hostgroups are examined.
 *
 * The resulting idle connections are returned in conn_list. Note that not all
 * currently idle connections will be returned (some might be purged).
 *
 * Connections are purged according to 2 criteria:
 * - whenever the maximal number of connections for a server is hit, free
 *   connections will be purged
 * - also, idle connections that cause the number of free connections to rise
 *   above a certain percentage of the maximal number of connections will be
 *   dropped as well
 */
int MySQL_HostGroups_Manager::get_multiple_idle_connections(int _hid, unsigned long long _max_last_time_used, MySQL_Connection **conn_list, int num_conn) {
	wrlock();
	drop_all_idle_connections();
	int num_conn_current=0;
	int j,k;
	MyHGC* myhgc = NULL;
	// Multimap holding the required info for accesing the oldest idle connections found.
	std::multimap<uint64_t,std::pair<MySrvC*,int32_t>> oldest_idle_connections {};

	for (int i=0; i<(int)MyHostGroups->len; i++) {
		if (_hid == -1) {
			// all hostgroups must be examined
			// as of version 2.3.2 , this is always the case
			myhgc=(MyHGC *)MyHostGroups->index(i);
		} else {
			// only one hostgroup is examined
			// as of version 2.3.2 , this never happen
			// but the code support this functionality
			myhgc = MyHGC_find(_hid);
			i = (int)MyHostGroups->len; // to exit from this "for" loop
			if (myhgc == NULL)
				continue; // immediately exit
		}
		if (_hid >= 0 && _hid!=(int)myhgc->hid) continue;
		for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
			MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
			//PtrArray *pa=mysrvc->ConnectionsFree->conns;
			MySrvConnList *mscl=mysrvc->ConnectionsFree;
			for (k=0; k<(int)mscl->conns_length(); k++) {
				MySQL_Connection *mc=mscl->index(k);
				// If the connection is idle ...
				if (mc->last_time_used && mc->last_time_used < _max_last_time_used) {
					if ((int)oldest_idle_connections.size() < num_conn) {
						oldest_idle_connections.insert({mc->last_time_used, { mysrvc, k }});
					} else if (num_conn != 0) {
						auto last_elem_it = std::prev(oldest_idle_connections.end());

						if (mc->last_time_used < last_elem_it->first) {
							oldest_idle_connections.erase(last_elem_it);
							oldest_idle_connections.insert({mc->last_time_used, { mysrvc, k }});
						}
					}
				}
			}
		}
	}

	// In order to extract the found connections, the following actions must be performed:
	//
	// 1. Filter the found connections by 'MySrvC'.
	// 2. Order by indexes on 'ConnectionsFree' in desc order.
	// 3. Move the conns from 'ConnectionsFree' into 'ConnectionsUsed'.
	std::unordered_map<MySrvC*,vector<int>> mysrvcs_conns_idxs {};

	// 1. Filter the connections by 'MySrvC'.
	//
	// We extract this for being able to later iterate through the obtained 'MySrvC' using the conn indexes.
	for (const auto& conn_info : oldest_idle_connections) {
		MySrvC* mysrvc = conn_info.second.first;
		int32_t mc_idx = conn_info.second.second;
		auto mysrcv_it = mysrvcs_conns_idxs.find(mysrvc);

		if (mysrcv_it == mysrvcs_conns_idxs.end()) {
			mysrvcs_conns_idxs.insert({ mysrvc, { mc_idx }});
		} else {
			mysrcv_it->second.push_back(mc_idx);
		}
	}

	// 2. Order by indexes on FreeConns in desc order.
	//
	// Since the conns are stored in 'ConnectionsFree', which holds the conns in a 'PtrArray', and we plan
	// to remove multiple connections using the pre-stored indexes. We need to reorder the indexes in 'desc'
	// order, otherwise we could be trashing the array while consuming it. See 'PtrArray::remove_index_fast'.
	for (auto& mysrvc_conns_idxs : mysrvcs_conns_idxs) {
		std::sort(std::begin(mysrvc_conns_idxs.second), std::end(mysrvc_conns_idxs.second),  std::greater<int>());
	}

	// 3. Move the conns from 'ConnectionsFree' into 'ConnectionsUsed'.
	for (auto& conn_info : mysrvcs_conns_idxs) {
		MySrvC* mysrvc = conn_info.first;

		for (const int conn_idx : conn_info.second) {
			MySrvConnList* mscl = mysrvc->ConnectionsFree;
			MySQL_Connection* mc = mscl->remove(conn_idx);
			mysrvc->ConnectionsUsed->add(mc);

			conn_list[num_conn_current] = mc;
			num_conn_current++;

			// Left here as a safeguard
			if (num_conn_current >= num_conn) {
				goto __exit_get_multiple_idle_connections;
			}
		}
	}

__exit_get_multiple_idle_connections:
	status.myconnpoll_get_ping+=num_conn_current;
	wrunlock();
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning %d idle connections\n", num_conn_current);
	return num_conn_current;
}

void MySQL_HostGroups_Manager::save_incoming_mysql_table(SQLite3_result *s, const string& name) {
	SQLite3_result ** inc = NULL;
	if (name == "mysql_aws_aurora_hostgroups") {
		inc = &incoming_aws_aurora_hostgroups;
	} else if (name == "mysql_galera_hostgroups") {
		inc = &incoming_galera_hostgroups;
	} else if (name == "mysql_group_replication_hostgroups") {
		inc = &incoming_group_replication_hostgroups;
	} else if (name == "mysql_replication_hostgroups") {
		inc = &incoming_replication_hostgroups;
	} else if (name == "mysql_hostgroup_attributes") {
		inc = &incoming_hostgroup_attributes;
	} else if (name == "mysql_servers_ssl_params") {
		inc = &incoming_mysql_servers_ssl_params;
	} else {
		assert(0);
	}
	if (*inc != nullptr) {
		delete *inc;
		*inc = nullptr;
	}
	*inc = s;
}

void MySQL_HostGroups_Manager::save_runtime_mysql_servers(SQLite3_result *s) {
	if (runtime_mysql_servers) {
		delete runtime_mysql_servers;
		runtime_mysql_servers = nullptr;
	}
	runtime_mysql_servers=s;
}

void MySQL_HostGroups_Manager::save_mysql_servers_v2(SQLite3_result* s) {
	if (incoming_mysql_servers_v2) {
		delete incoming_mysql_servers_v2;
		incoming_mysql_servers_v2 = nullptr;
	}
	incoming_mysql_servers_v2 = s;
}

/**
 * @brief Retrieves the current SQLite3 result set associated with the specified MySQL table name.
 *
 * This method retrieves the current SQLite3 result set corresponding to the specified MySQL table name.
 * The method is used to obtain the result set for various MySQL tables, such as hostgroups, replication configurations,
 * SSL parameters, and runtime server information.
 *
 * @param name The name of the MySQL table for which the current SQLite3 result set is to be retrieved.
 *             Supported table names include:
 *                - "mysql_aws_aurora_hostgroups"
 *                - "mysql_galera_hostgroups"
 *                - "mysql_group_replication_hostgroups"
 *                - "mysql_replication_hostgroups"
 *                - "mysql_hostgroup_attributes"
 *                - "mysql_servers_ssl_params"
 *                - "cluster_mysql_servers"
 *                - "mysql_servers_v2"
 *
 * @return A pointer to the current SQLite3 result set associated with the specified MySQL table name.
 *         If the table name is not recognized or no result set is available for the specified table, NULL is returned.
 *
 * @note The method assumes that the result sets are stored in class member variables, and it returns the pointer to
 *       the appropriate result set based on the provided table name. If the table name is not recognized, an assertion
 *       failure occurs, indicating an invalid table name.
 */
SQLite3_result* MySQL_HostGroups_Manager::get_current_mysql_table(const string& name) {
	if (name == "mysql_aws_aurora_hostgroups") {
		return this->incoming_aws_aurora_hostgroups;
	} else if (name == "mysql_galera_hostgroups") {
		return this->incoming_galera_hostgroups;
	} else if (name == "mysql_group_replication_hostgroups") {
		return this->incoming_group_replication_hostgroups;
	} else if (name == "mysql_replication_hostgroups") {
		return this->incoming_replication_hostgroups;
	} else if (name == "mysql_hostgroup_attributes") {
		return this->incoming_hostgroup_attributes;
	} else if (name == "mysql_servers_ssl_params") {
		return this->incoming_mysql_servers_ssl_params;
	} else if (name == "cluster_mysql_servers") {
		return this->runtime_mysql_servers;
	} else if (name == "mysql_servers_v2") {
		return this->incoming_mysql_servers_v2;
	} else {
		assert(0); // Assertion failure for unrecognized table name
	}
	return NULL;
}



SQLite3_result * MySQL_HostGroups_Manager::SQL3_Free_Connections() {
	const int colnum=13;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Dumping Free Connections in Pool\n");
	SQLite3_result *result=new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT,"fd");
	result->add_column_definition(SQLITE_TEXT,"hostgroup");
	result->add_column_definition(SQLITE_TEXT,"srv_host");
	result->add_column_definition(SQLITE_TEXT,"srv_port");
	result->add_column_definition(SQLITE_TEXT,"user");
	result->add_column_definition(SQLITE_TEXT,"schema");
	result->add_column_definition(SQLITE_TEXT,"init_connect");
	result->add_column_definition(SQLITE_TEXT,"time_zone");
	result->add_column_definition(SQLITE_TEXT,"sql_mode");
	result->add_column_definition(SQLITE_TEXT,"autocommit");
	result->add_column_definition(SQLITE_TEXT,"idle_ms");
	result->add_column_definition(SQLITE_TEXT,"statistics");
	result->add_column_definition(SQLITE_TEXT,"mysql_info");
	unsigned long long curtime = monotonic_time();
	wrlock();
	int i,j, k, l;
	for (i=0; i<(int)MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
			MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
			if (mysrvc->get_status()!=MYSQL_SERVER_STATUS_ONLINE) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d is not online\n", mysrvc->address, mysrvc->port);
				mysrvc->ConnectionsFree->drop_all_connections();
			}
			// drop idle connections if beyond max_connection
			while (mysrvc->ConnectionsFree->conns_length() && mysrvc->ConnectionsUsed->conns_length()+mysrvc->ConnectionsFree->conns_length() > mysrvc->max_connections) {
				//MySQL_Connection *conn=(MySQL_Connection *)mysrvc->ConnectionsFree->conns->remove_index_fast(0);
				MySQL_Connection *conn=mysrvc->ConnectionsFree->remove(0);
				delete conn;
			}
			char buf[1024];
			for (l=0; l < (int) mysrvc->ConnectionsFree->conns_length(); l++) {
				char **pta=(char **)malloc(sizeof(char *)*colnum);
				MySQL_Connection *conn = mysrvc->ConnectionsFree->index(l);
				sprintf(buf,"%d", conn->fd);
				pta[0]=strdup(buf);
				sprintf(buf,"%d", (int)myhgc->hid);
				pta[1]=strdup(buf);
				pta[2]=strdup(mysrvc->address);
				sprintf(buf,"%d", mysrvc->port);
				pta[3]=strdup(buf);
				pta[4] = strdup(conn->userinfo->username);
				pta[5] = strdup(conn->userinfo->schemaname);
				pta[6] = NULL;
				if (conn->options.init_connect) {
					pta[6] = strdup(conn->options.init_connect);
				}
				pta[7] = NULL;
				if (conn->variables[SQL_TIME_ZONE].value) {
					pta[7] = strdup(conn->variables[SQL_TIME_ZONE].value);
				}
				pta[8] = NULL;
				if (conn->variables[SQL_SQL_MODE].value) {
					pta[8] = strdup(conn->variables[SQL_SQL_MODE].value);
				}
				sprintf(buf,"%d", conn->options.autocommit);
				pta[9]=strdup(buf);
				sprintf(buf,"%llu", (curtime-conn->last_time_used)/1000);
				pta[10]=strdup(buf);
				{
					json j;
					char buff[32];
					sprintf(buff,"%p",conn);
					j["address"] = buff;
					uint64_t age_ms = (curtime - conn->creation_time)/1000;
					j["age_ms"] = age_ms;
					j["bytes_recv"] = conn->bytes_info.bytes_recv;
					j["bytes_sent"] = conn->bytes_info.bytes_sent;
					j["myconnpoll_get"] = conn->statuses.myconnpoll_get;
					j["myconnpoll_put"] = conn->statuses.myconnpoll_put;
					j["questions"] = conn->statuses.questions;
					string s = j.dump();
					pta[11] = strdup(s.c_str());
				}
				{
					MYSQL *_my = conn->mysql;
					json j;
					char buff[32];
					sprintf(buff,"%p",_my);
					j["address"] = buff;
					j["host"] = _my->host;
					j["host_info"] = _my->host_info;
					j["port"] = _my->port;
					j["server_version"] = _my->server_version;
					j["user"] = _my->user;
					j["unix_socket"] = (_my->unix_socket ? _my->unix_socket : "");
					j["db"] = (_my->db ? _my->db : "");
					j["affected_rows"] = _my->affected_rows;
					j["insert_id"] = _my->insert_id;
					j["thread_id"] = _my->thread_id;
					j["server_status"] = _my->server_status;
					j["charset"] = _my->charset->nr;
					j["charset_name"] = _my->charset->csname;

					j["options"]["charset_name"] = ( _my->options.charset_name ? _my->options.charset_name : "" );
					j["options"]["use_ssl"] = _my->options.use_ssl;
					j["client_flag"]["client_found_rows"] = (_my->client_flag & CLIENT_FOUND_ROWS ? 1 : 0);
					j["client_flag"]["client_multi_statements"] = (_my->client_flag & CLIENT_MULTI_STATEMENTS ? 1 : 0);
					j["client_flag"]["client_multi_results"] = (_my->client_flag & CLIENT_MULTI_RESULTS ? 1 : 0);
					j["net"]["last_errno"] = _my->net.last_errno;
					j["net"]["fd"] = _my->net.fd;
					j["net"]["max_packet_size"] = _my->net.max_packet_size;
					j["net"]["sqlstate"] = _my->net.sqlstate;
					string s = j.dump();
					pta[12] = strdup(s.c_str());
				}
				result->add_row(pta);
				for (k=0; k<colnum; k++) {
					if (pta[k])
						free(pta[k]);
				}
				free(pta);
			}
		}
	}
	wrunlock();
	return result;
}

void MySQL_HostGroups_Manager::p_update_connection_pool_update_counter(
	const std::string& endpoint_id, const std::map<std::string, std::string>& labels, std::map<std::string,
	prometheus::Counter*>& m_map, unsigned long long value, p_hg_dyn_counter::metric idx
) {
	const auto& counter_id = m_map.find(endpoint_id);
	if (counter_id != m_map.end()) {
		const auto& cur_val = counter_id->second->Value();
		counter_id->second->Increment(value - cur_val);
	} else {
		auto& new_counter = status.p_dyn_counter_array[idx];
		const auto& new_counter_it = m_map.insert(
			{
				endpoint_id,
				std::addressof(new_counter->Add(labels))
			}
		);
		new_counter_it.first->second->Increment(value);
	}
}

void MySQL_HostGroups_Manager::p_update_connection_pool_update_gauge(
	const std::string& endpoint_id, const std::map<std::string, std::string>& labels,
	std::map<std::string, prometheus::Gauge*>& m_map, unsigned long long value, p_hg_dyn_gauge::metric idx
) {
	const auto& counter_id = m_map.find(endpoint_id);
	if (counter_id != m_map.end()) {
		counter_id->second->Set(value);
	} else {
		auto& new_counter = status.p_dyn_gauge_array[idx];
		const auto& new_gauge_it = m_map.insert(
			{
				endpoint_id,
				std::addressof(new_counter->Add(labels))
			}
		);
		new_gauge_it.first->second->Set(value);
	}
}

void MySQL_HostGroups_Manager::p_update_connection_pool() {
	std::vector<string> cur_servers_ids {};
	wrlock();
	for (int i = 0; i < static_cast<int>(MyHostGroups->len); i++) {
		MyHGC *myhgc = static_cast<MyHGC*>(MyHostGroups->index(i));
		for (int j = 0; j < static_cast<int>(myhgc->mysrvs->cnt()); j++) {
			MySrvC *mysrvc = static_cast<MySrvC*>(myhgc->mysrvs->servers->index(j));
			std::string endpoint_addr = mysrvc->address;
			std::string endpoint_port = std::to_string(mysrvc->port);
			std::string hostgroup_id = std::to_string(myhgc->hid);
			std::string endpoint_id = hostgroup_id + ":" + endpoint_addr + ":" + endpoint_port;
			const std::map<std::string, std::string> common_labels {
				{"endpoint", endpoint_addr + ":" + endpoint_port},
				{"hostgroup", hostgroup_id }
			};
			cur_servers_ids.push_back(endpoint_id);

			// proxysql_connection_pool_bytes_data_recv metric
			std::map<std::string, std::string> recv_pool_bytes_labels = common_labels;
			recv_pool_bytes_labels.insert({"traffic_flow", "recv"});
			p_update_connection_pool_update_counter(endpoint_id, recv_pool_bytes_labels,
				status.p_conn_pool_bytes_data_recv_map, mysrvc->bytes_recv, p_hg_dyn_counter::conn_pool_bytes_data_recv);

			// proxysql_connection_pool_bytes_data_sent metric
			std::map<std::string, std::string> sent_pool_bytes_labels = common_labels;
			sent_pool_bytes_labels.insert({"traffic_flow", "sent"});
			p_update_connection_pool_update_counter(endpoint_id, sent_pool_bytes_labels,
				status.p_conn_pool_bytes_data_sent_map, mysrvc->bytes_sent, p_hg_dyn_counter::conn_pool_bytes_data_sent);

			// proxysql_connection_pool_conn_err metric
			std::map<std::string, std::string> pool_conn_err_labels = common_labels;
			pool_conn_err_labels.insert({"status", "err"});
			p_update_connection_pool_update_counter(endpoint_id, pool_conn_err_labels,
				status.p_connection_pool_conn_err_map, mysrvc->connect_ERR, p_hg_dyn_counter::connection_pool_conn_err);

			// proxysql_connection_pool_conn_ok metric
			std::map<std::string, std::string> pool_conn_ok_labels = common_labels;
			pool_conn_ok_labels.insert({"status", "ok"});
			p_update_connection_pool_update_counter(endpoint_id, pool_conn_ok_labels,
				status.p_connection_pool_conn_ok_map, mysrvc->connect_OK, p_hg_dyn_counter::connection_pool_conn_ok);

			// proxysql_connection_pool_conn_free metric
			std::map<std::string, std::string> pool_conn_free_labels = common_labels;
			pool_conn_free_labels.insert({"status", "free"});
			p_update_connection_pool_update_gauge(endpoint_id, pool_conn_free_labels,
				status.p_connection_pool_conn_free_map, mysrvc->ConnectionsFree->conns_length(), p_hg_dyn_gauge::connection_pool_conn_free);

			// proxysql_connection_pool_conn_used metric
			std::map<std::string, std::string> pool_conn_used_labels = common_labels;
			pool_conn_used_labels.insert({"status", "used"});
			p_update_connection_pool_update_gauge(endpoint_id, pool_conn_used_labels,
				status.p_connection_pool_conn_used_map, mysrvc->ConnectionsUsed->conns_length(), p_hg_dyn_gauge::connection_pool_conn_used);

			// proxysql_connection_pool_latency_us metric
			p_update_connection_pool_update_gauge(endpoint_id, common_labels,
				status.p_connection_pool_latency_us_map, mysrvc->current_latency_us, p_hg_dyn_gauge::connection_pool_latency_us);

			// proxysql_connection_pool_queries metric
			p_update_connection_pool_update_counter(endpoint_id, common_labels,
				status.p_connection_pool_queries_map, mysrvc->queries_sent, p_hg_dyn_counter::connection_pool_queries);

			// proxysql_connection_pool_status metric
			p_update_connection_pool_update_gauge(endpoint_id, common_labels,
				status.p_connection_pool_status_map, ((int)mysrvc->get_status()) + 1, p_hg_dyn_gauge::connection_pool_status);
		}
	}

	// Remove the non-present servers for the gauge metrics
	vector<string> missing_server_keys {};

	for (const auto& key : status.p_connection_pool_status_map) {
		if (std::find(cur_servers_ids.begin(), cur_servers_ids.end(), key.first) == cur_servers_ids.end()) {
			missing_server_keys.push_back(key.first);
		}
	}

	for (const auto& key : missing_server_keys) {
		auto gauge = status.p_connection_pool_status_map[key];
		status.p_dyn_gauge_array[p_hg_dyn_gauge::connection_pool_status]->Remove(gauge);
		status.p_connection_pool_status_map.erase(key);

		gauge = status.p_connection_pool_conn_free_map[key];
		status.p_dyn_gauge_array[p_hg_dyn_gauge::connection_pool_conn_free]->Remove(gauge);
		status.p_connection_pool_conn_free_map.erase(key);

		gauge = status.p_connection_pool_conn_used_map[key];
		status.p_dyn_gauge_array[p_hg_dyn_gauge::connection_pool_conn_used]->Remove(gauge);
		status.p_connection_pool_conn_used_map.erase(key);

		gauge = status.p_connection_pool_latency_us_map[key];
		status.p_dyn_gauge_array[p_hg_dyn_gauge::connection_pool_latency_us]->Remove(gauge);
		status.p_connection_pool_latency_us_map.erase(key);
	}

	wrunlock();
}

SQLite3_result * MySQL_HostGroups_Manager::SQL3_Connection_Pool(bool _reset, int *hid) {
  const int colnum=14;
  proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Dumping Connection Pool\n");
  SQLite3_result *result=new SQLite3_result(colnum);
  result->add_column_definition(SQLITE_TEXT,"hostgroup");
  result->add_column_definition(SQLITE_TEXT,"srv_host");
  result->add_column_definition(SQLITE_TEXT,"srv_port");
  result->add_column_definition(SQLITE_TEXT,"status");
  result->add_column_definition(SQLITE_TEXT,"ConnUsed");
  result->add_column_definition(SQLITE_TEXT,"ConnFree");
  result->add_column_definition(SQLITE_TEXT,"ConnOK");
  result->add_column_definition(SQLITE_TEXT,"ConnERR");
  result->add_column_definition(SQLITE_TEXT,"MaxConnUsed");
  result->add_column_definition(SQLITE_TEXT,"Queries");
  result->add_column_definition(SQLITE_TEXT,"Queries_GTID_sync");
  result->add_column_definition(SQLITE_TEXT,"Bytes_sent");
  result->add_column_definition(SQLITE_TEXT,"Bytes_recv");
  result->add_column_definition(SQLITE_TEXT,"Latency_us");
	wrlock();
	int i,j, k;
	for (i=0; i<(int)MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
			MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
			if (hid == NULL) {
				if (mysrvc->get_status()!=MYSQL_SERVER_STATUS_ONLINE) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d is not online\n", mysrvc->address, mysrvc->port);
					//__sync_fetch_and_sub(&status.server_connections_connected, mysrvc->ConnectionsFree->conns->len);
					mysrvc->ConnectionsFree->drop_all_connections();
				}
				// drop idle connections if beyond max_connection
				while (mysrvc->ConnectionsFree->conns_length() && mysrvc->ConnectionsUsed->conns_length()+mysrvc->ConnectionsFree->conns_length() > mysrvc->max_connections) {
					//MySQL_Connection *conn=(MySQL_Connection *)mysrvc->ConnectionsFree->conns->remove_index_fast(0);
					MySQL_Connection *conn=mysrvc->ConnectionsFree->remove(0);
					delete conn;
					//__sync_fetch_and_sub(&status.server_connections_connected, 1);
				}
			} else {
				if (*hid != (int)myhgc->hid) {
					continue;
				}
			}
			char buf[1024];
			char **pta=(char **)malloc(sizeof(char *)*colnum);
			sprintf(buf,"%d", (int)myhgc->hid);
			pta[0]=strdup(buf);
			pta[1]=strdup(mysrvc->address);
			sprintf(buf,"%d", mysrvc->port);
			pta[2]=strdup(buf);
			switch ((int)mysrvc->get_status()) {
				case 0:
					pta[3]=strdup("ONLINE");
					break;
				case 1:
					pta[3]=strdup("SHUNNED");
					break;
				case 2:
					pta[3]=strdup("OFFLINE_SOFT");
					break;
				case 3:
					pta[3]=strdup("OFFLINE_HARD");
					break;
				case 4:
					pta[3]=strdup("SHUNNED_REPLICATION_LAG");
					break;
				default:
					// LCOV_EXCL_START
					assert(0);
					break;
					// LCOV_EXCL_STOP
			}
			sprintf(buf,"%u", mysrvc->ConnectionsUsed->conns_length());
			pta[4]=strdup(buf);
			sprintf(buf,"%u", mysrvc->ConnectionsFree->conns_length());
			pta[5]=strdup(buf);
			sprintf(buf,"%u", mysrvc->connect_OK);
			pta[6]=strdup(buf);
			if (_reset) {
				mysrvc->connect_OK=0;
			}
			sprintf(buf,"%u", mysrvc->connect_ERR);
			pta[7]=strdup(buf);
			if (_reset) {
				mysrvc->connect_ERR=0;
			}
			sprintf(buf,"%u", mysrvc->max_connections_used);
			pta[8]=strdup(buf);
			if (_reset) {
				mysrvc->max_connections_used=0;
			}
			sprintf(buf,"%llu", mysrvc->queries_sent);
			pta[9]=strdup(buf);
			if (_reset) {
				mysrvc->queries_sent=0;
			}
			sprintf(buf,"%llu", mysrvc->queries_gtid_sync);
			pta[10]=strdup(buf);
			if (_reset) {
				mysrvc->queries_gtid_sync=0;
			}
			sprintf(buf,"%llu", mysrvc->bytes_sent);
			pta[11]=strdup(buf);
			if (_reset) {
				mysrvc->bytes_sent=0;
			}
			sprintf(buf,"%llu", mysrvc->bytes_recv);
			pta[12]=strdup(buf);
			if (_reset) {
				mysrvc->bytes_recv=0;
			}
			sprintf(buf,"%u", mysrvc->current_latency_us);
			pta[13]=strdup(buf);
			result->add_row(pta);
			for (k=0; k<colnum; k++) {
				if (pta[k])
					free(pta[k]);
			}
			free(pta);
		}
	}
	wrunlock();
	return result;
}

void MySQL_HostGroups_Manager::read_only_action(char *hostname, int port, int read_only) {
	// define queries
	const char *Q1B=(char *)"SELECT hostgroup_id,status FROM ( SELECT DISTINCT writer_hostgroup FROM mysql_replication_hostgroups JOIN mysql_servers WHERE (hostgroup_id=writer_hostgroup) AND hostname='%s' AND port=%d UNION SELECT DISTINCT writer_hostgroup FROM mysql_replication_hostgroups JOIN mysql_servers WHERE (hostgroup_id=reader_hostgroup) AND hostname='%s' AND port=%d) LEFT JOIN mysql_servers ON hostgroup_id=writer_hostgroup AND hostname='%s' AND port=%d";
	const char *Q2A=(char *)"DELETE FROM mysql_servers WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT writer_hostgroup FROM mysql_replication_hostgroups WHERE writer_hostgroup=mysql_servers.hostgroup_id) AND status='OFFLINE_HARD'";
	const char *Q2B=(char *)"UPDATE OR IGNORE mysql_servers SET hostgroup_id=(SELECT writer_hostgroup FROM mysql_replication_hostgroups WHERE reader_hostgroup=mysql_servers.hostgroup_id) WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT reader_hostgroup FROM mysql_replication_hostgroups WHERE reader_hostgroup=mysql_servers.hostgroup_id)";
	const char *Q3A=(char *)"INSERT OR IGNORE INTO mysql_servers(hostgroup_id, hostname, port, gtid_port, status, weight, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) SELECT reader_hostgroup, hostname, port, gtid_port, status, weight, max_connections, max_replication_lag, use_ssl, max_latency_ms, mysql_servers.comment FROM mysql_servers JOIN mysql_replication_hostgroups ON mysql_servers.hostgroup_id=mysql_replication_hostgroups.writer_hostgroup WHERE hostname='%s' AND port=%d";
	const char *Q3B=(char *)"DELETE FROM mysql_servers WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT reader_hostgroup FROM mysql_replication_hostgroups WHERE reader_hostgroup=mysql_servers.hostgroup_id)";
	const char *Q4=(char *)"UPDATE OR IGNORE mysql_servers SET hostgroup_id=(SELECT reader_hostgroup FROM mysql_replication_hostgroups WHERE writer_hostgroup=mysql_servers.hostgroup_id) WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT writer_hostgroup FROM mysql_replication_hostgroups WHERE writer_hostgroup=mysql_servers.hostgroup_id)";
	const char *Q5=(char *)"DELETE FROM mysql_servers WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT writer_hostgroup FROM mysql_replication_hostgroups WHERE writer_hostgroup=mysql_servers.hostgroup_id)";
	if (GloAdmin==NULL) {
		return;
	}

	// this prevents that multiple read_only_action() are executed at the same time
	pthread_mutex_lock(&readonly_mutex);

	// define a buffer that will be used for all queries
	char *query=(char *)malloc(strlen(hostname)*2+strlen(Q3A)+256);

	int cols=0;
	char *error=NULL;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	int num_rows=0; // note: with the new implementation (2.1.1) , this becomes a sort of boolean, not an actual count
	wrlock();
	// we minimum the time we hold the mutex, as connection pool is being locked
	if (read_only_set1.empty()) {
		SQLite3_result *res_set1=NULL;
		const char *q1 = (const char *)"SELECT DISTINCT hostname,port FROM mysql_replication_hostgroups JOIN mysql_servers ON hostgroup_id=writer_hostgroup AND status<>3";
		mydb->execute_statement((char *)q1, &error , &cols , &affected_rows , &res_set1);
		for (std::vector<SQLite3_row *>::iterator it = res_set1->rows.begin() ; it != res_set1->rows.end(); ++it) {
			SQLite3_row *r=*it;
			std::string s = r->fields[0];
			s += ":::";
			s += r->fields[1];
			read_only_set1.insert(s);
		}
		proxy_info("Regenerating read_only_set1 with %lu servers\n", read_only_set1.size());
		if (read_only_set1.empty()) {
			// to avoid regenerating this set always with 0 entries, we generate a fake entry
			read_only_set1.insert("----:::----");
		}
		delete res_set1;
	}
	wrunlock();
	std::string ser = hostname;
	ser += ":::";
	ser += std::to_string(port);
	std::set<std::string>::iterator it;
	it = read_only_set1.find(ser);
	if (it != read_only_set1.end()) {
		num_rows=1;
	}

	if (admindb==NULL) { // we initialize admindb only if needed
		admindb=new SQLite3DB();
		admindb->open((char *)"file:mem_admindb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);	
	}

	switch (read_only) {
		case 0:
			if (num_rows==0) {
				// the server has read_only=0 , but we can't find any writer, so we perform a swap
				GloAdmin->mysql_servers_wrlock();
				if (GloMTH->variables.hostgroup_manager_verbose) {
					char *error2=NULL;
					int cols2=0;
					int affected_rows2=0;
					SQLite3_result *resultset2=NULL;
					char * query2 = NULL;
					char *q = (char *)"SELECT * FROM mysql_servers WHERE hostname=\"%s\" AND port=%d";
					query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
					sprintf(query2,q,hostname,port);
					admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
					if (error2) {
						proxy_error("Error on read from mysql_servers : %s\n", error2);
					} else {
						if (resultset2) {
							proxy_info("read_only_action RO=0 phase 1 : Dumping mysql_servers for %s:%d\n", hostname, port);
							resultset2->dump_to_stderr();
						}
					}
					if (resultset2) { delete resultset2; resultset2=NULL; }
					free(query2);
				}
				GloAdmin->save_mysql_servers_runtime_to_database(false); // SAVE MYSQL SERVERS FROM RUNTIME
				if (GloMTH->variables.hostgroup_manager_verbose) {
					char *error2=NULL;
					int cols2=0;
					int affected_rows2=0;
					SQLite3_result *resultset2=NULL;
					char * query2 = NULL;
					char *q = (char *)"SELECT * FROM mysql_servers WHERE hostname=\"%s\" AND port=%d";
					query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
					sprintf(query2,q,hostname,port);
					admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
					if (error2) {
						proxy_error("Error on read from mysql_servers : %s\n", error2);
					} else {
						if (resultset2) {
							proxy_info("read_only_action RO=0 phase 2 : Dumping mysql_servers for %s:%d\n", hostname, port);
							resultset2->dump_to_stderr();
						}
					}
					if (resultset2) { delete resultset2; resultset2=NULL; }
					free(query2);
				}
				sprintf(query,Q2A,hostname,port);
				admindb->execute(query);
				sprintf(query,Q2B,hostname,port);
				admindb->execute(query);
				if (mysql_thread___monitor_writer_is_also_reader) {
					sprintf(query,Q3A,hostname,port);
				} else {
					sprintf(query,Q3B,hostname,port);
				}
				admindb->execute(query);
				if (GloMTH->variables.hostgroup_manager_verbose) {
					char *error2=NULL;
					int cols2=0;
					int affected_rows2=0;
					SQLite3_result *resultset2=NULL;
					char * query2 = NULL;
					char *q = (char *)"SELECT * FROM mysql_servers WHERE hostname=\"%s\" AND port=%d";
					query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
					sprintf(query2,q,hostname,port);
					admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
					if (error2) {
						proxy_error("Error on read from mysql_servers : %s\n", error2);
					} else {
						if (resultset2) {
							proxy_info("read_only_action RO=0 phase 3 : Dumping mysql_servers for %s:%d\n", hostname, port);
							resultset2->dump_to_stderr();
						}
					}
					if (resultset2) { delete resultset2; resultset2=NULL; }
					free(query2);
				}
				GloAdmin->load_mysql_servers_to_runtime(); // LOAD MYSQL SERVERS TO RUNTIME
				GloAdmin->mysql_servers_wrunlock();
			} else {
				// there is a server in writer hostgroup, let check the status of present and not present hosts
				bool act=false;
				wrlock();
				std::set<std::string>::iterator it;
				// read_only_set2 acts as a cache
				// if the server was RO=0 on the previous check and no action was needed,
				// it will be here
				it = read_only_set2.find(ser);
				if (it != read_only_set2.end()) {
					// the server was already detected as RO=0
					// no action required
				} else {
					// it is the first time that we detect RO on this server
					sprintf(query,Q1B,hostname,port,hostname,port,hostname,port);
					mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
					for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
						SQLite3_row *r=*it;
						int status=MYSQL_SERVER_STATUS_OFFLINE_HARD; // default status, even for missing
						if (r->fields[1]) { // has status
							status=atoi(r->fields[1]);
						}
						if (status==MYSQL_SERVER_STATUS_OFFLINE_HARD) {
							act=true;
						}
					}
					if (act == false) {
						// no action required, therefore we write in read_only_set2
						proxy_info("read_only_action() detected RO=0 on server %s:%d for the first time after commit(), but no need to reconfigure\n", hostname, port);
						read_only_set2.insert(ser);
					}
				}
				wrunlock();
				if (act==true) {	// there are servers either missing, or with stats=OFFLINE_HARD
					GloAdmin->mysql_servers_wrlock();
					if (GloMTH->variables.hostgroup_manager_verbose) {
						char *error2=NULL;
						int cols2=0;
						int affected_rows2=0;
						SQLite3_result *resultset2=NULL;
						char * query2 = NULL;
						char *q = (char *)"SELECT * FROM mysql_servers WHERE hostname=\"%s\" AND port=%d";
						query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
						sprintf(query2,q,hostname,port);
						admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
						if (error2) {
							proxy_error("Error on read from mysql_servers : %s\n", error2);
						} else {
							if (resultset2) {
								proxy_info("read_only_action RO=0 , rows=%d , phase 1 : Dumping mysql_servers for %s:%d\n", num_rows, hostname, port);
								resultset2->dump_to_stderr();
							}
						}
						if (resultset2) { delete resultset2; resultset2=NULL; }
						free(query2);
					}
					GloAdmin->save_mysql_servers_runtime_to_database(false); // SAVE MYSQL SERVERS FROM RUNTIME
					sprintf(query,Q2A,hostname,port);
					admindb->execute(query);
					sprintf(query,Q2B,hostname,port);
					admindb->execute(query);
					if (GloMTH->variables.hostgroup_manager_verbose) {
						char *error2=NULL;
						int cols2=0;
						int affected_rows2=0;
						SQLite3_result *resultset2=NULL;
						char * query2 = NULL;
						char *q = (char *)"SELECT * FROM mysql_servers WHERE hostname=\"%s\" AND port=%d";
						query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
						sprintf(query2,q,hostname,port);
						admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
						if (error2) {
							proxy_error("Error on read from mysql_servers : %s\n", error2);
						} else {
							if (resultset2) {
								proxy_info("read_only_action RO=0 , rows=%d , phase 2 : Dumping mysql_servers for %s:%d\n", num_rows, hostname, port);
								resultset2->dump_to_stderr();
							}
						}
						if (resultset2) { delete resultset2; resultset2=NULL; }
						free(query2);
					}
					if (mysql_thread___monitor_writer_is_also_reader) {
						sprintf(query,Q3A,hostname,port);
					} else {
						sprintf(query,Q3B,hostname,port);
					}
					admindb->execute(query);
					if (GloMTH->variables.hostgroup_manager_verbose) {
						char *error2=NULL;
						int cols2=0;
						int affected_rows2=0;
						SQLite3_result *resultset2=NULL;
						char * query2 = NULL;
						char *q = (char *)"SELECT * FROM mysql_servers WHERE hostname=\"%s\" AND port=%d";
						query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
						sprintf(query2,q,hostname,port);
						admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
						if (error2) {
							proxy_error("Error on read from mysql_servers : %s\n", error2);
						} else {
							if (resultset2) {
								proxy_info("read_only_action RO=0 , rows=%d , phase 3 : Dumping mysql_servers for %s:%d\n", num_rows, hostname, port);
								resultset2->dump_to_stderr();
							}
						}
						if (resultset2) { delete resultset2; resultset2=NULL; }
						free(query2);
					}
					GloAdmin->load_mysql_servers_to_runtime(); // LOAD MYSQL SERVERS TO RUNTIME
					GloAdmin->mysql_servers_wrunlock();
				}
			}
			break;
		case 1:
			if (num_rows) {
				// the server has read_only=1 , but we find it as writer, so we perform a swap
				GloAdmin->mysql_servers_wrlock();
				if (GloMTH->variables.hostgroup_manager_verbose) {
					char *error2=NULL;
					int cols2=0;
					int affected_rows2=0;
					SQLite3_result *resultset2=NULL;
					char * query2 = NULL;
					char *q = (char *)"SELECT * FROM mysql_servers WHERE hostname=\"%s\" AND port=%d";
					query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
					sprintf(query2,q,hostname,port);
					admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
					if (error2) {
						proxy_error("Error on read from mysql_servers : %s\n", error2);
					} else {
						if (resultset2) {
							proxy_info("read_only_action RO=1 phase 1 : Dumping mysql_servers for %s:%d\n", hostname, port);
							resultset2->dump_to_stderr();
						}
					}
					if (resultset2) { delete resultset2; resultset2=NULL; }
					free(query2);
				}
				GloAdmin->save_mysql_servers_runtime_to_database(false); // SAVE MYSQL SERVERS FROM RUNTIME
				sprintf(query,Q4,hostname,port);
				admindb->execute(query);
				if (GloMTH->variables.hostgroup_manager_verbose) {
					char *error2=NULL;
					int cols2=0;
					int affected_rows2=0;
					SQLite3_result *resultset2=NULL;
					char * query2 = NULL;
					char *q = (char *)"SELECT * FROM mysql_servers WHERE hostname=\"%s\" AND port=%d";
					query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
					sprintf(query2,q,hostname,port);
					admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
					if (error2) {
						proxy_error("Error on read from mysql_servers : %s\n", error2);
					} else {
						if (resultset2) {
							proxy_info("read_only_action RO=1 phase 2 : Dumping mysql_servers for %s:%d\n", hostname, port);
							resultset2->dump_to_stderr();
						}
					}
					if (resultset2) { delete resultset2; resultset2=NULL; }
					free(query2);
				}
				sprintf(query,Q5,hostname,port);
				admindb->execute(query);
				if (GloMTH->variables.hostgroup_manager_verbose) {
					char *error2=NULL;
					int cols2=0;
					int affected_rows2=0;
					SQLite3_result *resultset2=NULL;
					char * query2 = NULL;
					char *q = (char *)"SELECT * FROM mysql_servers WHERE hostname=\"%s\" AND port=%d";
					query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
					sprintf(query2,q,hostname,port);
					admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
					if (error2) {
						proxy_error("Error on read from mysql_servers : %s\n", error2);
					} else {
						if (resultset2) {
							proxy_info("read_only_action RO=1 phase 3 : Dumping mysql_servers for %s:%d\n", hostname, port);
							resultset2->dump_to_stderr();
						}
					}
					if (resultset2) { delete resultset2; resultset2=NULL; }
					free(query2);
				}
				GloAdmin->load_mysql_servers_to_runtime(); // LOAD MYSQL SERVERS TO RUNTIME
				GloAdmin->mysql_servers_wrunlock();
			}
			break;
		default:
			// LCOV_EXCL_START
			assert(0);
			break;
			// LCOV_EXCL_STOP
	}

	pthread_mutex_unlock(&readonly_mutex);
	if (resultset) {
		delete resultset;
	}
	free(query);
}

/**
 * @brief New implementation of the read_only_action method that does not depend on the admin table.
 *   The method checks each server in the provided list and adjusts the servers according to their corresponding read_only value.
 *   If any change has occured, checksum is calculated.
 *
 * @param mysql_servers List of servers having hostname, port and read only value.
 * 
 */
void MySQL_HostGroups_Manager::read_only_action_v2(const std::list<read_only_server_t>& mysql_servers) {

	bool update_mysql_servers_table = false;

	unsigned long long curtime1 = monotonic_time();
	wrlock();
	for (const auto& server : mysql_servers) {
		bool is_writer = false;
		const std::string& hostname = std::get<READ_ONLY_SERVER_T::ROS_HOSTNAME>(server);
		const int port = std::get<READ_ONLY_SERVER_T::ROS_PORT>(server);
		const int read_only = std::get<READ_ONLY_SERVER_T::ROS_READONLY>(server);
		const std::string& srv_id = hostname + ":::" + std::to_string(port);
		
		auto itr = hostgroup_server_mapping.find(srv_id);

		if (itr == hostgroup_server_mapping.end()) {
			proxy_warning("Server %s:%d not found\n", hostname.c_str(), port);
			continue;
		}

		HostGroup_Server_Mapping* host_server_mapping = itr->second.get();

		if (!host_server_mapping)
			assert(0);

		const std::vector<HostGroup_Server_Mapping::Node>& writer_map = host_server_mapping->get(HostGroup_Server_Mapping::Type::WRITER);

		is_writer = !writer_map.empty();

		if (read_only == 0) {
			if (is_writer == false) {
				// the server has read_only=0 (writer), but we can't find any writer, 
				// so we copy all reader nodes to writer
				proxy_info("Server '%s:%d' found with 'read_only=0', but not found as writer\n", hostname.c_str(), port);
				proxy_debug(PROXY_DEBUG_MONITOR, 5, "Server '%s:%d' found with 'read_only=0', but not found as writer\n", hostname.c_str(), port);
				host_server_mapping->copy_if_not_exists(HostGroup_Server_Mapping::Type::WRITER, HostGroup_Server_Mapping::Type::READER);

				if (mysql_thread___monitor_writer_is_also_reader == false) {
					// remove node from reader
					host_server_mapping->clear(HostGroup_Server_Mapping::Type::READER);
				}

				update_mysql_servers_table = true;
				proxy_info("Regenerating table 'mysql_servers' due to actions on server '%s:%d'\n", hostname.c_str(), port);
			} else {
				bool act = false;

				// if the server was RO=0 on the previous check then no action is needed
				if (host_server_mapping->get_readonly_flag() != 0) {
					// it is the first time that we detect RO on this server
					const std::vector<HostGroup_Server_Mapping::Node>& reader_map = host_server_mapping->get(HostGroup_Server_Mapping::Type::READER);

					for (const auto& reader_node : reader_map) {
						for (const auto& writer_node : writer_map) {

							if (reader_node.writer_hostgroup_id == writer_node.writer_hostgroup_id) {
								goto __writer_found;
							}
						}
						act = true;
						break;
					__writer_found:
						continue;
					}

					if (act == false) {
						// no action required, therefore we set readonly_flag to 0
						proxy_info("read_only_action_v2() detected RO=0 on server %s:%d for the first time after commit(), but no need to reconfigure\n", hostname.c_str(), port);
						host_server_mapping->set_readonly_flag(0);
					}
				} else {
					// the server was already detected as RO=0
					// no action required
				}

				if (act == true) {	// there are servers either missing, or with stats=OFFLINE_HARD

					proxy_info("Server '%s:%d' with 'read_only=0' found missing at some 'writer_hostgroup'\n", hostname.c_str(), port);
					proxy_debug(PROXY_DEBUG_MONITOR, 5, "Server '%s:%d' with 'read_only=0' found missing at some 'writer_hostgroup'\n", hostname.c_str(), port);

					// copy all reader nodes to writer
					host_server_mapping->copy_if_not_exists(HostGroup_Server_Mapping::Type::WRITER, HostGroup_Server_Mapping::Type::READER);

					if (mysql_thread___monitor_writer_is_also_reader == false) {
						// remove node from reader
						host_server_mapping->clear(HostGroup_Server_Mapping::Type::READER);
					}

					update_mysql_servers_table = true;
					proxy_info("Regenerating table 'mysql_servers' due to actions on server '%s:%d'\n", hostname.c_str(), port);
				}
			}
		} else if (read_only == 1) {
			if (is_writer) {
				// the server has read_only=1 (reader), but we find it as writer, so we copy all writer nodes to reader (previous reader nodes will be reused)
				proxy_info("Server '%s:%d' found with 'read_only=1', but not found as reader\n", hostname.c_str(), port);
				proxy_debug(PROXY_DEBUG_MONITOR, 5, "Server '%s:%d' found with 'read_only=1', but not found as reader\n", hostname.c_str(), port);
				host_server_mapping->copy_if_not_exists(HostGroup_Server_Mapping::Type::READER, HostGroup_Server_Mapping::Type::WRITER);

				// clearing all writer nodes
				host_server_mapping->clear(HostGroup_Server_Mapping::Type::WRITER);

				update_mysql_servers_table = true;
				proxy_info("Regenerating table 'mysql_servers' due to actions on server '%s:%d'\n", hostname.c_str(), port);
			}
		} else {
			// LCOV_EXCL_START
			assert(0);
			break;
			// LCOV_EXCL_STOP
		}
	}

	if (update_mysql_servers_table) {
		purge_mysql_servers_table();
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_servers\n");
		mydb->execute("DELETE FROM mysql_servers");
		generate_mysql_servers_table();

		// Update the global checksums after 'mysql_servers' regeneration
		{
			unique_ptr<SQLite3_result> resultset { get_admin_runtime_mysql_servers(mydb) };
			uint64_t raw_checksum = resultset ? resultset->raw_checksum() : 0;

			// This is required to be updated to avoid extra rebuilding member 'hostgroup_server_mapping'
			// during 'commit'. For extra details see 'hgsm_mysql_servers_checksum' @details.
			hgsm_mysql_servers_checksum = raw_checksum;

			string mysrvs_checksum { get_checksum_from_hash(raw_checksum) };
			save_runtime_mysql_servers(resultset.release());
			proxy_info("Checksum for table %s is %s\n", "mysql_servers", mysrvs_checksum.c_str());

			pthread_mutex_lock(&GloVars.checksum_mutex);
			update_glovars_mysql_servers_checksum(mysrvs_checksum);
			pthread_mutex_unlock(&GloVars.checksum_mutex);
		}
	}
	wrunlock();
	unsigned long long curtime2 = monotonic_time();
	curtime1 = curtime1 / 1000;
	curtime2 = curtime2 / 1000;
	proxy_debug(PROXY_DEBUG_MONITOR, 7, "MySQL_HostGroups_Manager::read_only_action_v2() locked for %llums (server count:%ld)\n", curtime2 - curtime1, mysql_servers.size());
}

// shun_and_killall
// this function is called only from MySQL_Monitor::monitor_ping()
// it temporary disables a host that is not responding to pings, and mark the host in a way that when used the connection will be dropped
// return true if the status was changed
bool MySQL_HostGroups_Manager::shun_and_killall(char *hostname, int port) {
	time_t t = time(NULL);
	bool ret = false;
	wrlock();
	MySrvC *mysrvc=NULL;
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
	MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		unsigned int j;
		unsigned int l=myhgc->mysrvs->cnt();
		if (l) {
			for (j=0; j<l; j++) {
				mysrvc=myhgc->mysrvs->idx(j);
				if (mysrvc->port==port && strcmp(mysrvc->address,hostname)==0) {
					switch ((MySerStatus)mysrvc->get_status()) {
						case MYSQL_SERVER_STATUS_SHUNNED:
							if (mysrvc->shunned_automatic==false) {
								break;
							}
						case MYSQL_SERVER_STATUS_ONLINE:
							if (mysrvc->get_status() == MYSQL_SERVER_STATUS_ONLINE) {
								ret = true;
							}
							mysrvc->set_status(MYSQL_SERVER_STATUS_SHUNNED);
						case MYSQL_SERVER_STATUS_OFFLINE_SOFT:
							mysrvc->shunned_automatic=true;
							mysrvc->shunned_and_kill_all_connections=true;
							mysrvc->ConnectionsFree->drop_all_connections();
							break;
						default:
							break;
					}
					// if Monitor is enabled and mysql-monitor_ping_interval is
					// set too high, ProxySQL will unshun hosts that are not
					// available. For this reason time_last_detected_error will
					// be tuned in the future
					if (mysql_thread___monitor_enabled) {
						int a = mysql_thread___shun_recovery_time_sec;
						int b = mysql_thread___monitor_ping_interval;
						b = b/1000;
						if (b > a) {
							t = t + (b - a);
						}
					}
					mysrvc->time_last_detected_error = t;
				}
			}
		}
	}
	wrunlock();
	return ret;
}

// set_server_current_latency_us
// this function is called only from MySQL_Monitor::monitor_ping()
// it set the average latency for a host in the last 3 pings
// the connection pool will use this information to evaluate or exclude a specific hosts
// note that this variable is in microsecond, while user defines it in millisecond
void MySQL_HostGroups_Manager::set_server_current_latency_us(char *hostname, int port, unsigned int _current_latency_us) {
	wrlock();
	MySrvC *mysrvc=NULL;
  for (unsigned int i=0; i<MyHostGroups->len; i++) {
    MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		unsigned int j;
		unsigned int l=myhgc->mysrvs->cnt();
		if (l) {
			for (j=0; j<l; j++) {
				mysrvc=myhgc->mysrvs->idx(j);
				if (mysrvc->port==port && strcmp(mysrvc->address,hostname)==0) {
					mysrvc->current_latency_us=_current_latency_us;
				}
			}
		}
	}
	wrunlock();
}

void MySQL_HostGroups_Manager::p_update_metrics() {
	p_update_counter(status.p_counter_array[p_hg_counter::servers_table_version], status.servers_table_version);
	// Update *server_connections* related metrics
	status.p_gauge_array[p_hg_gauge::server_connections_connected]->Set(status.server_connections_connected);
	p_update_counter(status.p_counter_array[p_hg_counter::server_connections_aborted], status.server_connections_aborted);
	p_update_counter(status.p_counter_array[p_hg_counter::server_connections_created], status.server_connections_created);
	p_update_counter(status.p_counter_array[p_hg_counter::server_connections_delayed], status.server_connections_delayed);

	// Update *client_connections* related metrics
	p_update_counter(status.p_counter_array[p_hg_counter::client_connections_created], status.client_connections_created);
	p_update_counter(status.p_counter_array[p_hg_counter::client_connections_aborted], status.client_connections_aborted);
	p_update_counter(status.p_counter_array[p_hg_counter::client_connections_sha2cached], status.client_connections_sha2cached);
	status.p_gauge_array[p_hg_gauge::client_connections_connected]->Set(status.client_connections);
	status.p_gauge_array[p_hg_gauge::client_connections_connected_prim]->Set(status.client_connections_prim_pass);
	status.p_gauge_array[p_hg_gauge::client_connections_connected_addl]->Set(status.client_connections_addl_pass);

	// Update *acess_denied* related metrics
	p_update_counter(status.p_counter_array[p_hg_counter::access_denied_wrong_password], status.access_denied_wrong_password);
	p_update_counter(status.p_counter_array[p_hg_counter::access_denied_max_connections], status.access_denied_max_connections);
	p_update_counter(status.p_counter_array[p_hg_counter::access_denied_max_user_connections], status.access_denied_max_user_connections);

	p_update_counter(status.p_counter_array[p_hg_counter::selects_for_update__autocommit0], status.select_for_update_or_equivalent);

	// Update *com_* related metrics
	p_update_counter(status.p_counter_array[p_hg_counter::com_autocommit], status.autocommit_cnt);
	p_update_counter(status.p_counter_array[p_hg_counter::com_autocommit_filtered], status.autocommit_cnt_filtered);
	p_update_counter(status.p_counter_array[p_hg_counter::com_commit_cnt], status.commit_cnt);
	p_update_counter(status.p_counter_array[p_hg_counter::com_commit_cnt_filtered], status.commit_cnt_filtered);
	p_update_counter(status.p_counter_array[p_hg_counter::com_rollback], status.rollback_cnt);
	p_update_counter(status.p_counter_array[p_hg_counter::com_rollback_filtered], status.rollback_cnt_filtered);
	p_update_counter(status.p_counter_array[p_hg_counter::com_backend_init_db], status.backend_init_db);
	p_update_counter(status.p_counter_array[p_hg_counter::com_backend_change_user], status.backend_change_user);
	p_update_counter(status.p_counter_array[p_hg_counter::com_backend_set_names], status.backend_set_names);
	p_update_counter(status.p_counter_array[p_hg_counter::com_frontend_init_db], status.frontend_init_db);
	p_update_counter(status.p_counter_array[p_hg_counter::com_frontend_set_names], status.frontend_set_names);
	p_update_counter(status.p_counter_array[p_hg_counter::com_frontend_use_db], status.frontend_use_db);

	// Update *myconnpoll* related metrics
	p_update_counter(status.p_counter_array[p_hg_counter::myhgm_myconnpool_get], status.myconnpoll_get);
	p_update_counter(status.p_counter_array[p_hg_counter::myhgm_myconnpool_get_ok], status.myconnpoll_get_ok);
	p_update_counter(status.p_counter_array[p_hg_counter::myhgm_myconnpool_get_ping], status.myconnpoll_get_ping);
	p_update_counter(status.p_counter_array[p_hg_counter::myhgm_myconnpool_push], status.myconnpoll_push);
	p_update_counter(status.p_counter_array[p_hg_counter::myhgm_myconnpool_reset], status.myconnpoll_reset);
	p_update_counter(status.p_counter_array[p_hg_counter::myhgm_myconnpool_destroy], status.myconnpoll_destroy);

	p_update_counter(status.p_counter_array[p_hg_counter::auto_increment_delay_multiplex], status.auto_increment_delay_multiplex);

	// Update the *connection_pool* metrics
	this->p_update_connection_pool();
	// Update the *gtid_executed* metrics
	this->p_update_mysql_gtid_executed();
}

SQLite3_result * MySQL_HostGroups_Manager::SQL3_Get_ConnPool_Stats() {
	const int colnum=2;
	char buf[256];
	char **pta=(char **)malloc(sizeof(char *)*colnum);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Dumping MySQL Global Status\n");
	SQLite3_result *result=new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT,"Variable_Name");
	result->add_column_definition(SQLITE_TEXT,"Variable_Value");
	wrlock();
	// NOTE: as there is no string copy, we do NOT free pta[0] and pta[1]
    {
		pta[0]=(char *)"MyHGM_myconnpoll_get";
		sprintf(buf,"%lu",status.myconnpoll_get);
		pta[1]=buf;
		result->add_row(pta);
	}
    {
		pta[0]=(char *)"MyHGM_myconnpoll_get_ok";
		sprintf(buf,"%lu",status.myconnpoll_get_ok);
		pta[1]=buf;
		result->add_row(pta);
	}
    {
		pta[0]=(char *)"MyHGM_myconnpoll_push";
		sprintf(buf,"%lu",status.myconnpoll_push);
		pta[1]=buf;
		result->add_row(pta);
	}
    {
		pta[0]=(char *)"MyHGM_myconnpoll_destroy";
		sprintf(buf,"%lu",status.myconnpoll_destroy);
		pta[1]=buf;
		result->add_row(pta);
	}
    {
		pta[0]=(char *)"MyHGM_myconnpoll_reset";
		sprintf(buf,"%lu",status.myconnpoll_reset);
		pta[1]=buf;
		result->add_row(pta);
	}
	wrunlock();
	free(pta);
	return result;
}

/**
 * @brief Retrieves memory usage statistics for the MySQL host groups manager.
 *
 * This method calculates the total memory usage of the MySQL host groups manager, including memory allocated for
 * host groups, server connections, and MySQL connections. It iterates over all host groups and their associated
 * server connections to compute the memory usage.
 *
 * @return The total memory usage of the MySQL host groups manager in bytes.
 */
unsigned long long MySQL_HostGroups_Manager::Get_Memory_Stats() {
	// Initialize the memory size counter
	unsigned long long intsize=0;
	// Acquire write lock to ensure thread safety during memory calculation
	wrlock();
	MySrvC *mysrvc=NULL; // Pointer to a MySQL server connection

	// Iterate over all hostgroups
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
		// Add memory size for the hostgroup object
		intsize+=sizeof(MyHGC);
		// Get the hostgroup object
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		unsigned int j,k;
		// Get the number of server connections in the hostgroup
		unsigned int l=myhgc->mysrvs->cnt();
		// Iterate over all server connections in the hostgroup
		if (l) {
			for (j=0; j<l; j++) {
				// Add memory size for the server connection object
				intsize+=sizeof(MySrvC);
				// Get the server connection object
				mysrvc=myhgc->mysrvs->idx(j);
				// Calculate memory usage for each connection in the "ConnectionsFree" list
				intsize+=((mysrvc->ConnectionsUsed->conns_length())*sizeof(MySQL_Connection *));
				for (k=0; k<mysrvc->ConnectionsFree->conns_length(); k++) {
					// Get a MySQL connection
					MySQL_Connection *myconn=mysrvc->ConnectionsFree->index(k);
					// Add memory size for MySQL connection object and MYSQL struct
					intsize+=sizeof(MySQL_Connection)+sizeof(MYSQL);
					// Add memory size for the MySQL packet buffer
					intsize+=myconn->mysql->net.max_packet;
					// Add memory size for the default stack size of the asynchronous context
					intsize+=(4096*15); // ASYNC_CONTEXT_DEFAULT_STACK_SIZE
					// Add memory size for result set object if present
					if (myconn->MyRS) {
						intsize+=myconn->MyRS->current_size();
					}
				}
				intsize+=((mysrvc->ConnectionsUsed->conns_length())*sizeof(MySQL_Connection *));
			}
		}
	}
	// Release the write lock
	wrunlock();
	// Return the total memory usage
	return intsize;
}

Group_Replication_Info::Group_Replication_Info(int w, int b, int r, int o, int mw, int mtb, bool _a, int _w, char *c) {
	comment=NULL;
	if (c) {
		comment=strdup(c);
	}
	writer_hostgroup=w;
	backup_writer_hostgroup=b;
	reader_hostgroup=r;
	offline_hostgroup=o;
	max_writers=mw;
	max_transactions_behind=mtb;
	active=_a;
	writer_is_also_reader=_w;
	current_num_writers=0;
	current_num_backup_writers=0;
	current_num_readers=0;
	current_num_offline=0;
	__active=true;
	need_converge=true;
}

Group_Replication_Info::~Group_Replication_Info() {
	if (comment) {
		free(comment);
		comment=NULL;
	}
}

bool Group_Replication_Info::update(int b, int r, int o, int mw, int mtb, bool _a, int _w, char *c) {
	bool ret=false;
	__active=true;
	if (backup_writer_hostgroup!=b) {
		backup_writer_hostgroup=b;
		ret=true;
	}
	if (reader_hostgroup!=r) {
		reader_hostgroup=r;
		ret=true;
	}
	if (offline_hostgroup!=o) {
		offline_hostgroup=o;
		ret=true;
	}
	if (max_writers!=mw) {
		max_writers=mw;
		ret=true;
	}
	if (max_transactions_behind!=mtb) {
		max_transactions_behind=mtb;
		ret=true;
	}
	if (active!=_a) {
		active=_a;
		ret=true;
	}
	if (writer_is_also_reader!=_w) {
		writer_is_also_reader=_w;
		ret=true;
	}
	// for comment we don't change return value
	if (comment) {
		if (c) {
			if (strcmp(comment,c)) {
				free(comment);
				comment=strdup(c);
			}
		} else {
			free(comment);
			comment=NULL;
		}
	} else {
		if (c) {
			comment=strdup(c);
		}
	}
	return ret;
}

void MySQL_HostGroups_Manager::update_group_replication_set_offline(char *_hostname, int _port, int _writer_hostgroup, char *_error) {
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=NULL;
	char *q=NULL;
	char *error=NULL;
	q=(char *)"SELECT hostgroup_id FROM mysql_servers JOIN mysql_group_replication_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=backup_writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE hostname='%s' AND port=%d AND status<>3";
	query=(char *)malloc(strlen(q)+strlen(_hostname)+32);
	sprintf(query,q,_hostname,_port);
  mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		free(error);
		error=NULL;
	}
	free(query);
	if (resultset) { // we lock only if needed
		if (resultset->rows_count) {
			proxy_warning("Group Replication: setting host %s:%d offline because: %s\n", _hostname, _port, _error);
			GloAdmin->mysql_servers_wrlock();
			mydb->execute("DELETE FROM mysql_servers_incoming");
			mydb->execute("INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers");
			// NOTE: Only updated the servers that have belong to the same cluster.
			q=(char *)"UPDATE OR IGNORE mysql_servers_incoming SET hostgroup_id=(SELECT offline_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d) WHERE hostname='%s' AND port=%d AND hostgroup_id IN ("
				" SELECT %d UNION ALL"
				" SELECT backup_writer_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d UNION ALL"
				" SELECT reader_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d"
			")";
			query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_writer_hostgroup,_hostname,_port,_writer_hostgroup,_writer_hostgroup,_writer_hostgroup);
			mydb->execute(query);
			// NOTE: Only delete the servers that have belong to the same cluster.
			q=(char*)"DELETE FROM mysql_servers_incoming WHERE hostname='%s' AND port=%d AND hostgroup_id IN ("
				" SELECT %d UNION ALL"
				" SELECT backup_writer_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d UNION ALL"
				" SELECT reader_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d"
			")";
			sprintf(query,q,_hostname,_port,_writer_hostgroup,_writer_hostgroup,_writer_hostgroup);
			mydb->execute(query);
			//free(query);
			// q=(char *)"UPDATE mysql_servers_incoming SET status=0 WHERE hostname='%s' AND port=%d AND hostgroup_id=(SELECT offline_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d)";
			// sprintf(query,q,_hostname,_port,_writer_hostgroup);
			q=(char *)"UPDATE mysql_servers_incoming SET status=(CASE "
				" (SELECT status FROM mysql_servers_incoming WHERE hostname='%s' AND port=%d AND"
					" hostgroup_id=(SELECT offline_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d)) WHEN 2 THEN 2 ELSE 0 END)"
				" WHERE hostname='%s' AND port=%d AND hostgroup_id=(SELECT offline_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d)";
			sprintf(query,q,_hostname,_port,_writer_hostgroup,_hostname,_port,_writer_hostgroup);
			mydb->execute(query);
			//free(query);
			converge_group_replication_config(_writer_hostgroup);
			commit();
			wrlock();
			SQLite3_result *resultset2=NULL;
			q=(char *)"SELECT writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_writer_hostgroup);
			mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset2);
			if (resultset2) {
				if (resultset2->rows_count) {
					for (std::vector<SQLite3_row *>::iterator it = resultset2->rows.begin() ; it != resultset2->rows.end(); ++it) {
						SQLite3_row *r=*it;
						int writer_hostgroup=atoi(r->fields[0]);
						int backup_writer_hostgroup=atoi(r->fields[1]);
						int reader_hostgroup=atoi(r->fields[2]);
						int offline_hostgroup=atoi(r->fields[3]);
						q=(char *)"DELETE FROM mysql_servers WHERE hostgroup_id IN (%d , %d , %d , %d)";
						sprintf(query,q,_writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup);
						mydb->execute(query);
						generate_mysql_servers_table(&writer_hostgroup);
						generate_mysql_servers_table(&backup_writer_hostgroup);
						generate_mysql_servers_table(&reader_hostgroup);
						generate_mysql_servers_table(&offline_hostgroup);
					}
				}
				delete resultset2;
				resultset2=NULL;
			}
			wrunlock();
			GloAdmin->mysql_servers_wrunlock();
			free(query);
		}
	}
	if (resultset) {
		delete resultset;
		resultset=NULL;
	}
}

/**
 * @brief Set the server specified by the supplied 'hostname:port' and hostgroup as 'reader'.
 * @details Tries to find the server in any hostgroup other than in the desired on, in case of not
 *  finding it:
 *    1. Move the server to the reader hostgroup, preserving status if required.
 *    2. Deletes the server from other hostgroups in the cluster (determined by 'writer_hostgroup').
 *    3. Converge the current configuration and rebuild the hostgroups.
 *
 *  PRESERVE-OFFLINE_SOFT: When moving the target server, always preserve the OFFLINE_SOFT state.
 *
 * @param _hostname Hostname of the target server to be set as writer.
 * @param _port Port of the target server to be set as writer.
 * @param _writer_hostgroup 'writer_hostgroup' of the cluster in which server is going to be placed as writer.
 * @param _error Reason why the server has beens et as 'read_only'.
 */
void MySQL_HostGroups_Manager::update_group_replication_set_read_only(char *_hostname, int _port, int _writer_hostgroup, char *_error) {
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=NULL;
	char *q=NULL;
	char *error=NULL;
	q=(char *)"SELECT hostgroup_id FROM mysql_servers JOIN mysql_group_replication_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=backup_writer_hostgroup OR hostgroup_id=offline_hostgroup WHERE hostname='%s' AND port=%d AND status<>3";
	query=(char *)malloc(strlen(q)+strlen(_hostname)+32);
	sprintf(query,q,_hostname,_port);
  mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset);
	if (error) {
		free(error);
		error=NULL;
	}
	free(query);
	if (resultset) { // we lock only if needed
		if (resultset->rows_count) {
			proxy_warning("Group Replication: setting host %s:%d (part of cluster with writer_hostgroup=%d) in read_only because: %s\n", _hostname, _port, _writer_hostgroup, _error);
			GloAdmin->mysql_servers_wrlock();
			mydb->execute("DELETE FROM mysql_servers_incoming");
			mydb->execute("INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers");
			// NOTE: Only updated the servers that have belong to the same cluster.
			q=(char *)"UPDATE OR IGNORE mysql_servers_incoming SET hostgroup_id=(SELECT reader_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d) WHERE hostname='%s' AND port=%d AND hostgroup_id IN ("
				" SELECT %d UNION ALL"
				" SELECT backup_writer_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d UNION ALL"
				" SELECT offline_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d"
			")";
			query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_writer_hostgroup,_hostname,_port,_writer_hostgroup,_writer_hostgroup,_writer_hostgroup);
			mydb->execute(query);
			// NOTE: Only delete the servers that have belong to the same cluster.
			q=(char*)"DELETE FROM mysql_servers_incoming WHERE hostname='%s' AND port=%d AND hostgroup_id IN ("
				" SELECT %d UNION ALL"
				" SELECT backup_writer_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d UNION ALL"
				" SELECT offline_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d"
			")";
			sprintf(query,q,_hostname,_port,_writer_hostgroup,_writer_hostgroup,_writer_hostgroup);
			mydb->execute(query);
			//free(query);
			// NOTE: In case of the server being 'OFFLINE_SOFT' we preserve this status. Otherwise we set the server as 'ONLINE'.
			q=(char *)"UPDATE mysql_servers_incoming SET status=(CASE "
				" (SELECT status FROM mysql_servers_incoming WHERE hostname='%s' AND port=%d AND"
					" hostgroup_id=(SELECT reader_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d)) WHEN 2 THEN 2 ELSE 0 END)"
				" WHERE hostname='%s' AND port=%d AND hostgroup_id=(SELECT reader_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d)";
			sprintf(query,q,_hostname,_port,_writer_hostgroup,_hostname,_port,_writer_hostgroup);
			mydb->execute(query);
			//free(query);
			converge_group_replication_config(_writer_hostgroup);
			commit();
			wrlock();
			SQLite3_result *resultset2=NULL;
			q=(char *)"SELECT writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_writer_hostgroup);
			mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset2);
			if (resultset2) {
				if (resultset2->rows_count) {
					for (std::vector<SQLite3_row *>::iterator it = resultset2->rows.begin() ; it != resultset2->rows.end(); ++it) {
						SQLite3_row *r=*it;
						int writer_hostgroup=atoi(r->fields[0]);
						int backup_writer_hostgroup=atoi(r->fields[1]);
						int reader_hostgroup=atoi(r->fields[2]);
						int offline_hostgroup=atoi(r->fields[3]);
						q=(char *)"DELETE FROM mysql_servers WHERE hostgroup_id IN (%d , %d , %d , %d)";
						sprintf(query,q,writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup);
						mydb->execute(query);
						generate_mysql_servers_table(&writer_hostgroup);
						generate_mysql_servers_table(&backup_writer_hostgroup);
						generate_mysql_servers_table(&reader_hostgroup);
						generate_mysql_servers_table(&offline_hostgroup);
					}
				}
				delete resultset2;
				resultset2=NULL;
			}
			wrunlock();
			GloAdmin->mysql_servers_wrunlock();
			free(query);
		}
	}
	if (resultset) {
		delete resultset;
		resultset=NULL;
	}
}

/**
 * @brief Set the server specified by the supplied 'hostname:port' and hostgroup as 'writer'.
 * @details Tries to find the server as an already present 'writer' in the desired hostgroup, in case of not
 *  finding it:
 *    1. Move the server to target writer, preserving status if required.
 *    2. Deletes the server from other hostgroups in the cluster (determined by 'writer_hostgroup').
 *    3. If 'writer_is_also_reader', place the server also in the 'reader_hostgroup'.
 *    4. Converge the current configuration and rebuild the hostgroups.
 *
 *  If the server is already found, no action should be taken, and no reconfiguration triggered.
 *
 *  FOUND_AS_SHUNNED: If writer is found as SHUNNED is considered as a found writer, since we don't take
 *  reconfiguration actions based on SHUNNED state.
 *
 *  FOUND_AS_BACKUP_WRITER: If server is found in the 'backup_writer_hostgroup' is because the server has been
 *  previously considered as a writer, and due to an exceeding number of writers, the server
 *  ended in the 'backup_writer_hostgroup'. If the server is to be removed from this hostgroup
 *  and placed in other one, is something that should be done when converging to the final state
 *  after other actions 'set_offline|set_read_only' (via 'converge_group_replication_config'),
 *  otherwise, we will continously trying to place the already WRITER server as WRITER and
 *  constantly retriggering a servers reconfiguration everytime the available number of writers
 *  exceeds 'max_writers'.
 *
 *  PRESERVE-OFFLINE_SOFT: When server is not found as writer, but is found as 'OFFLINE_SOFT' this state is
 *  present when setting this server in the 'writer_hostgroup'.
 *
 * @param _hostname Hostname of the target server to be set as writer.
 * @param _port Port of the target server to be set as writer.
 * @param _writer_hostgroup 'writer_hostgroup' of the cluster in which server is going to be placed as writer.
 */
void MySQL_HostGroups_Manager::update_group_replication_set_writer(char *_hostname, int _port, int _writer_hostgroup) {
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=NULL;
	char *q=NULL;
	char *error=NULL;
	q=(char *)"SELECT hostgroup_id, status FROM mysql_servers JOIN mysql_group_replication_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup OR hostgroup_id=backup_writer_hostgroup OR hostgroup_id=offline_hostgroup WHERE hostname='%s' AND port=%d AND status<>3";
	query=(char *)malloc(strlen(q)+strlen(_hostname)+32);
	sprintf(query,q,_hostname,_port);
  mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset);
	if (error) {
		free(error);
		error=NULL;
	}
	free(query);

	int writer_is_also_reader=0;
	bool found_writer=false;
	bool found_reader=false;
	int read_HG=-1;
	int offline_HG=-1;
	int backup_writer_HG=-1;
	bool need_converge=false;
	int status=0;
	bool offline_soft_found=false;

	if (resultset) {
		// let's get info about this cluster
		pthread_mutex_lock(&Group_Replication_Info_mutex);
		std::map<int , Group_Replication_Info *>::iterator it2;
		it2 = Group_Replication_Info_Map.find(_writer_hostgroup);
		Group_Replication_Info *info=NULL;
		if (it2!=Group_Replication_Info_Map.end()) {
			info=it2->second;
			writer_is_also_reader=info->writer_is_also_reader;
			read_HG=info->reader_hostgroup;
			offline_HG=info->offline_hostgroup;
			backup_writer_HG=info->backup_writer_hostgroup;
			need_converge=info->need_converge;
			info->need_converge=false;
		}
		pthread_mutex_unlock(&Group_Replication_Info_mutex);

		if (resultset->rows_count) {
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				int hostgroup=atoi(r->fields[0]);
				offline_soft_found = atoi(r->fields[1]) == 2 ? true : false;

				if (hostgroup==_writer_hostgroup) {
					status = atoi(r->fields[1]);
					if (status == 0 || status == 2) {
						found_writer=true;
					}
					// NOTE: 'SHUNNED' state is possible if server has reached 'myhgm.mysql_servers' table.
					// This can occur due to a reconfiguration that triggered a call to 'generate_mysql_servers_table'
					// (e.g. selecting from 'runtime_mysql_servers' would have this effect). In this case, we
					// don't want to trigger any reconfiguration as the server is indeed found and we don't perform
					// reconfigurations based on 'SHUNNED' state.
					if (status == 1) {
						found_writer=true;
					}
				}
				if (read_HG>=0) {
					if (hostgroup==read_HG) {
						found_reader=true;
					}
				}
				// NOTE: See 'FOUND_AS_BACKUP_WRITER' on function documentation.
				if (hostgroup == backup_writer_HG) {
					found_writer = true;
				}
			}
		}

		// NOTE: In case of a writer not being found but a 'OFFLINE_SOFT' status
		// is found in a hostgroup, 'OFFLINE_SOFT' status should be preserved.
		if (found_writer == false) {
			if (offline_soft_found) {
				status = 2;
			}
		}
		if (need_converge==false) {
			if (found_writer) { // maybe no-op
				if (
					(writer_is_also_reader==0 && found_reader==false)
					||
					(writer_is_also_reader > 0 && found_reader==true)
				) { // either both true or both false
					delete resultset;
					resultset=NULL;
				}
			}
		}
	}

	if (resultset) { // if we reach there, there is some action to perform
		if (resultset->rows_count) {
			need_converge=false;
			proxy_warning("Group Replication: setting host %s:%d as writer\n", _hostname, _port);

			GloAdmin->mysql_servers_wrlock();
			mydb->execute("DELETE FROM mysql_servers_incoming");
			mydb->execute("INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers");
			// NOTE: Only updated the servers that have belong to the same cluster.
			q=(char *)"UPDATE OR IGNORE mysql_servers_incoming SET hostgroup_id=%d WHERE hostname='%s' AND port=%d AND hostgroup_id IN (%d, %d, %d)";
			query=(char *)malloc(strlen(q)+strlen(_hostname)+256);
			sprintf(query,q,_writer_hostgroup,_hostname,_port,backup_writer_HG,read_HG,offline_HG);
			mydb->execute(query);
			// NOTE: Only delete the servers that have belong to the same cluster.
			q=(char *)"DELETE FROM mysql_servers_incoming WHERE hostname='%s' AND port=%d AND hostgroup_id IN (%d, %d, %d)";
			sprintf(query,q,_hostname,_port,backup_writer_HG,read_HG,offline_HG);
			mydb->execute(query);
			q=(char *)"UPDATE mysql_servers_incoming SET status=%d WHERE hostname='%s' AND port=%d AND hostgroup_id=%d";
			// NOTE: In case of the server being 'OFFLINE_SOFT' we preserve this status. Otherwise
			// we set the server as 'ONLINE'.
			sprintf(query, q, (status == 2 ? 2 : 0 ), _hostname, _port, _writer_hostgroup);
			mydb->execute(query);
			//free(query);
			if (writer_is_also_reader && read_HG>=0) {
				q=(char *)"INSERT OR IGNORE INTO mysql_servers_incoming (hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) SELECT %d,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers_incoming WHERE hostgroup_id=%d AND hostname='%s' AND port=%d";
				free(query);
				query=(char *)malloc(strlen(q)+strlen(_hostname)+256);
				sprintf(query,q,read_HG,_writer_hostgroup,_hostname,_port);
				mydb->execute(query);
			}
			converge_group_replication_config(_writer_hostgroup);
			commit();
			wrlock();
			SQLite3_result *resultset2=NULL;
			q=(char *)"SELECT writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, max_writers, writer_is_also_reader FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_writer_hostgroup);
			mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset2);
			if (resultset2) {
				if (resultset2->rows_count) {
					for (std::vector<SQLite3_row *>::iterator it = resultset2->rows.begin() ; it != resultset2->rows.end(); ++it) {
						SQLite3_row *r=*it;
						int writer_hostgroup=atoi(r->fields[0]);
						int backup_writer_hostgroup=atoi(r->fields[1]);
						int reader_hostgroup=atoi(r->fields[2]);
						int offline_hostgroup=atoi(r->fields[3]);
//						int max_writers=atoi(r->fields[4]);
//						int int_writer_is_also_reader=atoi(r->fields[5]);
						q=(char *)"DELETE FROM mysql_servers WHERE hostgroup_id IN (%d , %d , %d , %d)";
						sprintf(query,q,_writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup);
						mydb->execute(query);
						generate_mysql_servers_table(&writer_hostgroup);
						generate_mysql_servers_table(&backup_writer_hostgroup);
						generate_mysql_servers_table(&reader_hostgroup);
						generate_mysql_servers_table(&offline_hostgroup);
					}
				}
				delete resultset2;
				resultset2=NULL;
			}
			wrunlock();
			GloAdmin->mysql_servers_wrunlock();
			free(query);
		}
	}
	if (resultset) {
		delete resultset;
		resultset=NULL;
	}
}

/**
 * @brief Completes the tuning of 'mysql_servers_incoming', dealing with final writers placing.
 * @details This functions assumes this pre-conditions:
 *   - GloAdmin->mysql_servers_wrlock() was already called.
 *   - mysql_servers_incoming has already entries copied from mysql_servers and ready to be loaded.
 *
 *  Checks that the following conditions are met over the supplied hostgroup:
 *   1. Number of placed writers exceeds the max number of writers.
 *   2. Not enough writers are placed in the hostgroup, place 'backup_writers' if any.
 *   3. In case 'writer_is_also_reader' is '2', place *ONLY* 'backup_writers' as readers.
 *
 *  NOTE: Right now we consider 'SHUNNED' and 'ONLINE' writers equivalent in terms of server placement. This
 *  means that when counting writers for either placement or removal from 'backup_writer_hostgroup', we
 *  require taking into account 'SHUNNED' and 'ONLINE' writers.
 *
 * @param _writer_hostgroup Target hostgroup on which perform the final server placement.
 */
void MySQL_HostGroups_Manager::converge_group_replication_config(int _writer_hostgroup) {

	// we first gather info about the cluster
	pthread_mutex_lock(&Group_Replication_Info_mutex);
	std::map<int , Group_Replication_Info *>::iterator it2;
	it2 = Group_Replication_Info_Map.find(_writer_hostgroup);
	Group_Replication_Info *info=NULL;
	if (it2!=Group_Replication_Info_Map.end()) {
		info=it2->second;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		char *query=NULL;
		char *q=NULL;
		char *error=NULL;
		// We are required to consider both 'ONLINE' and 'SHUNNED' servers for 'backup_writer_hostgroup'
		// placement since they are equivalent for server placement. Check 'NOTE' at function @details.
		q=(char *)"SELECT hostgroup_id,hostname,port FROM mysql_servers_incoming WHERE status=0 OR status=1 AND hostgroup_id IN (%d, %d, %d, %d) ORDER BY weight DESC, hostname DESC, port DESC";
		query=(char *)malloc(strlen(q)+256);
		sprintf(query, q, info->writer_hostgroup, info->backup_writer_hostgroup, info->reader_hostgroup, info->offline_hostgroup);
		mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset);
		free(query);
		if (resultset) {
			if (resultset->rows_count) {
				int num_writers=0;
				int num_backup_writers=0;
				for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
					SQLite3_row *r=*it;
					int hostgroup=atoi(r->fields[0]);
					if (hostgroup==info->writer_hostgroup) {
						num_writers++;
					} else {
						if (hostgroup==info->backup_writer_hostgroup) {
							num_backup_writers++;
						}
					}
				}
				if (num_writers > info->max_writers) { // there are more writers than allowed
					int to_move=num_writers-info->max_writers;
					if (GloMTH->variables.hostgroup_manager_verbose > 1) {
						proxy_info("Group replication: max_writers=%d , moving %d nodes from writer HG %d to backup HG %d\n", info->max_writers, to_move, info->writer_hostgroup, info->backup_writer_hostgroup);
					}
					for (std::vector<SQLite3_row *>::reverse_iterator it = resultset->rows.rbegin() ; it != resultset->rows.rend(); ++it) {
						SQLite3_row *r=*it;
						if (to_move) {
							int hostgroup=atoi(r->fields[0]);
							if (hostgroup==info->writer_hostgroup) {
								q=(char *)"UPDATE OR REPLACE mysql_servers_incoming SET status=0, hostgroup_id=%d WHERE hostgroup_id=%d AND hostname='%s' AND port=%d";
								query=(char *)malloc(strlen(q)+strlen(r->fields[1])+128);
								sprintf(query,q,info->backup_writer_hostgroup,info->writer_hostgroup,r->fields[1],atoi(r->fields[2]));
								mydb->execute(query);
								free(query);
								to_move--;
							}
						}
					}
				} else {
					if (num_writers < info->max_writers && num_backup_writers) { // or way too low writer
						int to_move= ( (info->max_writers - num_writers) < num_backup_writers ? (info->max_writers - num_writers) : num_backup_writers);
						if (GloMTH->variables.hostgroup_manager_verbose) {
							proxy_info("Group replication: max_writers=%d , moving %d nodes from backup HG %d to writer HG %d\n", info->max_writers, to_move, info->backup_writer_hostgroup, info->writer_hostgroup);
						}
						for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
							SQLite3_row *r=*it;
							if (to_move) {
								int hostgroup=atoi(r->fields[0]);
								if (hostgroup==info->backup_writer_hostgroup) {
									q=(char *)"UPDATE OR REPLACE mysql_servers_incoming SET status=0, hostgroup_id=%d WHERE hostgroup_id=%d AND hostname='%s' AND port=%d";
									query=(char *)malloc(strlen(q)+strlen(r->fields[1])+128);
									sprintf(query,q,info->writer_hostgroup,info->backup_writer_hostgroup,r->fields[1],atoi(r->fields[2]));
									mydb->execute(query);
									free(query);
									to_move--;
								}
							}
						}
					}
				}
			}
		}
		if (resultset) {
			delete resultset;
			resultset=NULL;
		}
		if (info->writer_is_also_reader==2) {
			q=(char *)"SELECT hostgroup_id,hostname,port FROM mysql_servers_incoming WHERE status=0 AND hostgroup_id IN (%d, %d, %d, %d) ORDER BY weight DESC, hostname DESC, port DESC";
			query=(char *)malloc(strlen(q)+256);
			sprintf(query, q, info->writer_hostgroup, info->backup_writer_hostgroup, info->reader_hostgroup, info->offline_hostgroup);
			mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset);
			free(query);
			if (resultset) {
				if (resultset->rows_count) {
					int num_writers=0;
					int num_backup_writers=0;
					for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
						SQLite3_row *r=*it;
						int hostgroup=atoi(r->fields[0]);
						if (hostgroup==info->writer_hostgroup) {
							num_writers++;
						} else {
							if (hostgroup==info->backup_writer_hostgroup) {
								num_backup_writers++;
							}
						}
					}
					if (num_backup_writers) { // there are backup writers, only these will be used as readers
						q=(char *)"DELETE FROM mysql_servers_incoming WHERE hostgroup_id=%d";
						query=(char *)malloc(strlen(q) + 128);
						sprintf(query,q, info->reader_hostgroup);
						mydb->execute(query);
						free(query);
						q=(char *)"INSERT OR IGNORE INTO mysql_servers_incoming (hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) SELECT %d,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers_incoming WHERE hostgroup_id=%d";
						query=(char *)malloc(strlen(q) + 128);
						sprintf(query,q, info->reader_hostgroup, info->backup_writer_hostgroup);
						mydb->execute(query);
						free(query);
					}
				}
				delete resultset;
				resultset=NULL;
			}
		}
	} else {
		// we couldn't find the cluster, exits
	}
	pthread_mutex_unlock(&Group_Replication_Info_mutex);
}

void MySQL_HostGroups_Manager::update_group_replication_add_autodiscovered(
	const string& _host, int _port, int _wr_hg
) {
	pthread_mutex_lock(&Group_Replication_Info_mutex);
	const auto gr_info_map_it = this->Group_Replication_Info_Map.find(_wr_hg);
	int32_t reader_hg = -1;

	if (gr_info_map_it == Group_Replication_Info_Map.end()) {
		assert(0);
	} else {
		reader_hg = gr_info_map_it->second->reader_hostgroup;
	}
	pthread_mutex_unlock(&Group_Replication_Info_mutex);

	wrlock();

	MyHGC *myhgc = MyHGC_lookup(reader_hg);
	bool srv_found = false;
	bool srv_found_offline = false;

	for (uint32_t j = 0; j < myhgc->mysrvs->cnt(); j++) {
		MySrvC* mysrvc = static_cast<MySrvC*>(myhgc->mysrvs->servers->index(j));

		// If the server is found as 'OFFLINE_HARD' we reset the 'MySrvC' values corresponding with the
		// 'servers_defaults' (as in a new 'MySrvC' creation). We then later update these values with the
		// 'servers_defaults' attributes from its corresponding 'MyHGC'. This way we ensure uniform behavior
		// of new servers, and 'OFFLINE_HARD' ones when a user update 'servers_defaults' values, and reloads
		// the servers to runtime.
		if (strcmp(mysrvc->address,_host.c_str())==0 && mysrvc->port==_port) {
			srv_found = true;
			if (mysrvc->get_status() == MYSQL_SERVER_STATUS_OFFLINE_HARD) {
				reset_hg_attrs_server_defaults(mysrvc);
				update_hg_attrs_server_defaults(mysrvc, mysrvc->myhgc);
				proxy_info(
					"Found healthy previously discovered GR node %s:%d as 'OFFLINE_HARD', setting back as 'ONLINE' with:"
						" hostgroup=%d, weight=%ld, max_connections=%ld, use_ssl=%d\n",
					_host.c_str(), _port, reader_hg, mysrvc->weight, mysrvc->max_connections, mysrvc->use_ssl
				);
				mysrvc->set_status(MYSQL_SERVER_STATUS_ONLINE);
				srv_found_offline = true;
			}
		}
	}

	if (srv_found == false) {
		MySrvC* mysrvc = new MySrvC(
			const_cast<char*>(_host.c_str()), _port, 0, -1, MYSQL_SERVER_STATUS_ONLINE, 0, -1, 0, -1, 0, const_cast<char*>("")
		);
		add(mysrvc, reader_hg);
		proxy_info(
			"Adding new discovered GR node %s:%d with: hostgroup=%d, weight=%ld, max_connections=%ld, use_ssl=%d\n",
			_host.c_str(), _port, reader_hg, mysrvc->weight, mysrvc->max_connections, mysrvc->use_ssl
		);
	}

	if (srv_found == false || srv_found_offline) {
		purge_mysql_servers_table();

		mydb->execute("DELETE FROM mysql_servers");
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_servers\n");

		generate_mysql_servers_table();

		// Update the global checksums after 'mysql_servers' regeneration
		{
			unique_ptr<SQLite3_result> resultset { get_admin_runtime_mysql_servers(mydb) };
			string mysrvs_checksum { get_checksum_from_hash(resultset ? resultset->raw_checksum() : 0) };
			save_runtime_mysql_servers(resultset.release());
			proxy_info("Checksum for table %s is %s\n", "mysql_servers", mysrvs_checksum.c_str());

			pthread_mutex_lock(&GloVars.checksum_mutex);
			update_glovars_mysql_servers_checksum(mysrvs_checksum);
			pthread_mutex_unlock(&GloVars.checksum_mutex);
		}

		update_table_mysql_servers_for_monitor(false);
		generate_mysql_group_replication_hostgroups_monitor_resultset();
	}

	wrunlock();
}

Galera_Info::Galera_Info(int w, int b, int r, int o, int mw, int mtb, bool _a, int _w, char *c) {
	comment=NULL;
	if (c) {
		comment=strdup(c);
	}
	writer_hostgroup=w;
	backup_writer_hostgroup=b;
	reader_hostgroup=r;
	offline_hostgroup=o;
	max_writers=mw;
	max_transactions_behind=mtb;
	active=_a;
	writer_is_also_reader=_w;
	current_num_writers=0;
	current_num_backup_writers=0;
	current_num_readers=0;
	current_num_offline=0;
	__active=true;
	need_converge=true;
}

Galera_Info::~Galera_Info() {
	if (comment) {
		free(comment);
		comment=NULL;
	}
}

bool Galera_Info::update(int b, int r, int o, int mw, int mtb, bool _a, int _w, char *c) {
	bool ret=false;
	__active=true;
	if (backup_writer_hostgroup!=b) {
		backup_writer_hostgroup=b;
		ret=true;
	}
	if (reader_hostgroup!=r) {
		reader_hostgroup=r;
		ret=true;
	}
	if (offline_hostgroup!=o) {
		offline_hostgroup=o;
		ret=true;
	}
	if (max_writers!=mw) {
		max_writers=mw;
		ret=true;
	}
	if (max_transactions_behind!=mtb) {
		max_transactions_behind=mtb;
		ret=true;
	}
	if (active!=_a) {
		active=_a;
		ret=true;
	}
	if (writer_is_also_reader!=_w) {
		writer_is_also_reader=_w;
		ret=true;
	}
	// for comment we don't change return value
	if (comment) {
		if (c) {
			if (strcmp(comment,c)) {
				free(comment);
				comment=strdup(c);
			}
		} else {
			free(comment);
			comment=NULL;
		}
	} else {
		if (c) {
			comment=strdup(c);
		}
	}
	return ret;
}

/**
 * @brief Dumps to stderr the current info for the monitored Galera hosts ('Galera_Hosts_Map').
 * @details No action if `mysql_thread___hostgroup_manager_verbose=0`.
 */
static void print_galera_nodes_last_status() {
	if (!mysql_thread___hostgroup_manager_verbose) return;

	std::unique_ptr<SQLite3_result> result { new SQLite3_result(13) };

	result->add_column_definition(SQLITE_TEXT,"hostname");
	result->add_column_definition(SQLITE_TEXT,"port");
	result->add_column_definition(SQLITE_TEXT,"start_time");
	result->add_column_definition(SQLITE_TEXT,"check_time");
	result->add_column_definition(SQLITE_TEXT,"primary_partition");
	result->add_column_definition(SQLITE_TEXT,"read_only");
	result->add_column_definition(SQLITE_TEXT,"wsrep_local_recv_queue");
	result->add_column_definition(SQLITE_TEXT,"wsrep_local_state");
	result->add_column_definition(SQLITE_TEXT,"wsrep_desync");
	result->add_column_definition(SQLITE_TEXT,"wsrep_reject_queries");
	result->add_column_definition(SQLITE_TEXT,"wsrep_sst_donor_rejects_queries");
	result->add_column_definition(SQLITE_TEXT,"pxc_maint_mode");
	result->add_column_definition(SQLITE_TEXT,"error");

	pthread_mutex_lock(&GloMyMon->galera_mutex);

	for (auto node_it = GloMyMon->Galera_Hosts_Map.begin(); node_it != GloMyMon->Galera_Hosts_Map.end(); node_it++) {
		std::string s { node_it->first };
		std::size_t colon_pos { s.find_last_of(":") };
		std::string host { s.substr(0, colon_pos) };
		std::string port { s.substr(colon_pos + 1) };
		Galera_monitor_node* node { node_it->second };

		if (node->last_entry()->start_time) {
			std::string error { "" };

			if (node->last_entry()->error) {
				error = std::string { node->last_entry()->error };
			}

			result->add_row(
				host.c_str(),
				port.c_str(),
				std::to_string(node->last_entry()->start_time).c_str(),
				std::to_string(node->last_entry()->check_time).c_str(),
				std::to_string(node->last_entry()->primary_partition).c_str(),
				std::to_string(node->last_entry()->read_only).c_str(),
				std::to_string(node->last_entry()->wsrep_local_recv_queue).c_str(),
				std::to_string(node->last_entry()->wsrep_local_state).c_str(),
				std::to_string(node->last_entry()->wsrep_desync).c_str(),
				std::to_string(node->last_entry()->wsrep_reject_queries).c_str(),
				std::to_string(node->last_entry()->wsrep_sst_donor_rejects_queries).c_str(),
				std::to_string(node->last_entry()->pxc_maint_mode).c_str(),
				error.c_str(),
				NULL
			);
		}
	}

	pthread_mutex_unlock(&GloMyMon->galera_mutex);

	proxy_info("Galera: Node status changed by ProxySQL, dumping all galera nodes status:\n");
	result->dump_to_stderr();
}

void MySQL_HostGroups_Manager::update_galera_set_offline(char *_hostname, int _port, int _writer_hostgroup, char *_error, bool soft) {
	bool set_offline = false;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=NULL;
	char *q=NULL;
	char *error=NULL;
	q=(char *)"SELECT hostgroup_id FROM mysql_servers JOIN mysql_galera_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=backup_writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE hostname='%s' AND port=%d AND status=0";
	query=(char *)malloc(strlen(q)+strlen(_hostname)+1024); // increased this buffer as it is used for other queries too
	sprintf(query,q,_hostname,_port);
	mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
//		free(error);
		error=NULL;
	}
	//free(query);
	GloAdmin->mysql_servers_wrlock();
	if (resultset) { // we lock only if needed
		if (resultset->rows_count) {
			// the server was found. It needs to be set offline
			set_offline = true;
		} else { // the server is already offline, but we check if needs to be taken back online because there are no other writers
			SQLite3_result *numw_result = NULL;
			// we search for writers
			q=(char *)"SELECT 1 FROM mysql_servers WHERE hostgroup_id=%d AND status=0";
			//query=(char *)malloc(strlen(q) + (sizeof(_writer_hostgroup) * 8 + 1));
			sprintf(query,q,_writer_hostgroup);
			mydb->execute_statement(query, &error , &cols , &affected_rows , &numw_result);
			//free(query);
			if (numw_result) {
				if (numw_result->rows_count == 0) { // we have no writers
					set_offline = true;
				}
				delete numw_result;
			}
		}

		auto info = get_galera_node_info(_writer_hostgroup);
		if (set_offline && info) {
			mydb->execute("DELETE FROM mysql_servers_incoming");
			mydb->execute("INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers");
			if (soft==false) { // default behavior
				q=(char *)"UPDATE OR REPLACE mysql_servers_incoming SET hostgroup_id=%d, status=0 WHERE hostname='%s' AND port=%d AND hostgroup_id in (%d, %d, %d)";
				//query=(char *)malloc(strlen(q)+strlen(_hostname)+128);
				sprintf(query,q,info->offline_hostgroup,_hostname,_port,_writer_hostgroup, info->backup_writer_hostgroup, info->reader_hostgroup);
				mydb->execute(query);
				//free(query);
				q=(char *)"DELETE FROM mysql_servers_incoming WHERE hostname='%s' AND port=%d AND hostgroup_id in (%d, %d, %d)";
				//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
				sprintf(query,q,_hostname,_port,_writer_hostgroup, info->backup_writer_hostgroup, info->reader_hostgroup);
				mydb->execute(query);
				//free(query);
				q=(char *)"UPDATE mysql_servers_incoming SET status=0 WHERE hostname='%s' AND port=%d AND hostgroup_id in (%d, %d, %d)";
				//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
				sprintf(query,q,_hostname,_port,_writer_hostgroup, info->backup_writer_hostgroup, info->reader_hostgroup);
				mydb->execute(query);
				//free(query);
			} else {
				q=(char *)"INSERT OR REPLACE INTO mysql_servers_incoming SELECT %d, hostname, port, gtid_port, weight, 0, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers_incoming WHERE hostname='%s' AND port=%d AND hostgroup_id in (%d, %d, %d)";
				sprintf(query,q,info->offline_hostgroup,_hostname,_port,_writer_hostgroup, info->backup_writer_hostgroup, info->reader_hostgroup);
				mydb->execute(query);
				// we just delete the servers from the 'backup_writer_hostgroup', to keep servers from reader hostgroup,
				// so they can be 'SHUNNED'. See #3182
				q=(char *)"DELETE FROM mysql_servers_incoming WHERE hostname='%s' AND port=%d AND hostgroup_id=%d";
				sprintf(query,q,_hostname,_port, info->backup_writer_hostgroup);
				mydb->execute(query);
				// we update the servers from 'mysql_servers_incoming' to be SHUNNED in both, 'writer_hostgroup' and 'reader_hostgroup'
				// this way we prevent it's removal from the hostgroup, and the closing of its current connections. See #3182
				q=(char *)"UPDATE mysql_servers_incoming SET status=1 WHERE hostname='%s' AND port=%d AND hostgroup_id in (%d, %d)";
				sprintf(query,q,_hostname,_port,_writer_hostgroup,info->reader_hostgroup);
				mydb->execute(query);
			}
			converge_galera_config(_writer_hostgroup);
			uint64_t checksum_current = 0;
			uint64_t checksum_incoming = 0;
			{
				int cols=0;
				int affected_rows=0;
				SQLite3_result *resultset_servers=NULL;
				char *query_local=NULL;
				char *q1 = NULL;
				char *q2 = NULL;
				char *error=NULL;
				q1 = (char *)"SELECT DISTINCT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, mysql_servers.comment FROM mysql_servers JOIN mysql_galera_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=backup_writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE writer_hostgroup=%d ORDER BY hostgroup_id, hostname, port";
				q2 = (char *)"SELECT DISTINCT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, mysql_servers_incoming.comment FROM mysql_servers_incoming JOIN mysql_galera_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=backup_writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE writer_hostgroup=%d ORDER BY hostgroup_id, hostname, port";
				query_local = (char *)malloc(strlen(q2)+128);
				sprintf(query_local,q1,_writer_hostgroup);
				mydb->execute_statement(query_local, &error , &cols , &affected_rows , &resultset_servers);
				if (error == NULL) {
					if (resultset_servers) {
						checksum_current = resultset_servers->raw_checksum();
					}
				}
				if (resultset_servers) {
					delete resultset_servers;
					resultset_servers = NULL;
				}
				sprintf(query_local,q2,_writer_hostgroup);
				mydb->execute_statement(query_local, &error , &cols , &affected_rows , &resultset_servers);
				if (error == NULL) {
					if (resultset_servers) {
						checksum_incoming = resultset_servers->raw_checksum();
					}
				}
				if (resultset_servers) {
					delete resultset_servers;
					resultset_servers = NULL;
				}
				free(query_local);
			}
			if (checksum_incoming!=checksum_current) {
				proxy_warning("Galera: setting host %s:%d offline because: %s\n", _hostname, _port, _error);
				print_galera_nodes_last_status();
				commit();
				wrlock();
				SQLite3_result *resultset2=NULL;
				q=(char *)"SELECT writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup FROM mysql_galera_hostgroups WHERE writer_hostgroup=%d";
				//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
				sprintf(query,q,_writer_hostgroup);
				mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset2);
				if (resultset2) {
					if (resultset2->rows_count) {
						for (std::vector<SQLite3_row *>::iterator it = resultset2->rows.begin() ; it != resultset2->rows.end(); ++it) {
							SQLite3_row *r=*it;
							int writer_hostgroup=atoi(r->fields[0]);
							int backup_writer_hostgroup=atoi(r->fields[1]);
							int reader_hostgroup=atoi(r->fields[2]);
							int offline_hostgroup=atoi(r->fields[3]);
							q=(char *)"DELETE FROM mysql_servers WHERE hostgroup_id IN (%d , %d , %d , %d)";
							sprintf(query,q,_writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup);
							mydb->execute(query);
							generate_mysql_servers_table(&writer_hostgroup);
							generate_mysql_servers_table(&backup_writer_hostgroup);
							generate_mysql_servers_table(&reader_hostgroup);
							generate_mysql_servers_table(&offline_hostgroup);
						}
					}
					delete resultset2;
					resultset2=NULL;
				}
				wrunlock();
			} else {
				proxy_warning("Galera: skipping setting offline node %s:%d from hostgroup %d because won't change the list of ONLINE nodes\n", _hostname, _port, _writer_hostgroup);
				print_galera_nodes_last_status();
			}
		}
	}
	free(query);
	GloAdmin->mysql_servers_wrunlock();
	if (resultset) {
		delete resultset;
		resultset=NULL;
	}
}

void MySQL_HostGroups_Manager::update_galera_set_read_only(char *_hostname, int _port, int _writer_hostgroup, char *_error) {
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=NULL;
	char *q=NULL;
	char *error=NULL;
	q=(char *)"SELECT hostgroup_id FROM mysql_servers JOIN mysql_galera_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=backup_writer_hostgroup OR hostgroup_id=offline_hostgroup WHERE hostname='%s' AND port=%d";
	query=(char *)malloc(strlen(q)+strlen(_hostname)+32);
	sprintf(query,q,_hostname,_port);
  mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset);
	if (error) {
		free(error);
		error=NULL;
	}
	free(query);

	auto info = get_galera_node_info(_writer_hostgroup);
	if (resultset && info) { // we lock only if needed
		if (resultset->rows_count) {
			proxy_warning("Galera: setting host %s:%d (part of cluster with writer_hostgroup=%d) in read_only because: %s\n", _hostname, _port, _writer_hostgroup, _error);
			print_galera_nodes_last_status();
			GloAdmin->mysql_servers_wrlock();
			mydb->execute("DELETE FROM mysql_servers_incoming");
			mydb->execute("INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers");
			q=(char *)"UPDATE OR IGNORE mysql_servers_incoming SET hostgroup_id=%d WHERE hostname='%s' AND port=%d AND hostgroup_id in (%d, %d, %d)";
			query=(char *)malloc(strlen(q)+strlen(_hostname)+512);
			sprintf(query, q, info->reader_hostgroup, _hostname, _port, info->writer_hostgroup, info->backup_writer_hostgroup, info->offline_hostgroup);
			mydb->execute(query);
			//free(query);
			q=(char *)"DELETE FROM mysql_servers_incoming WHERE hostname='%s' AND port=%d AND hostgroup_id in (%d, %d, %d)";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_hostname,_port, info->offline_hostgroup, info->backup_writer_hostgroup, info->writer_hostgroup, info->writer_hostgroup);
			mydb->execute(query);
			//free(query);
			q=(char *)"UPDATE mysql_servers_incoming SET status=0 WHERE hostname='%s' AND port=%d AND hostgroup_id=%d";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_hostname,_port,info->reader_hostgroup);
			mydb->execute(query);
			//free(query);
			converge_galera_config(_writer_hostgroup);
			commit();
			wrlock();
			SQLite3_result *resultset2=NULL;
			q=(char *)"SELECT writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup FROM mysql_galera_hostgroups WHERE writer_hostgroup=%d";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_writer_hostgroup);
			mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset2);
			if (resultset2) {
				if (resultset2->rows_count) {
					for (std::vector<SQLite3_row *>::iterator it = resultset2->rows.begin() ; it != resultset2->rows.end(); ++it) {
						SQLite3_row *r=*it;
						int writer_hostgroup=atoi(r->fields[0]);
						int backup_writer_hostgroup=atoi(r->fields[1]);
						int reader_hostgroup=atoi(r->fields[2]);
						int offline_hostgroup=atoi(r->fields[3]);
						q=(char *)"DELETE FROM mysql_servers WHERE hostgroup_id IN (%d , %d , %d , %d)";
						sprintf(query,q,writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup);
						mydb->execute(query);
						generate_mysql_servers_table(&writer_hostgroup);
						generate_mysql_servers_table(&backup_writer_hostgroup);
						generate_mysql_servers_table(&reader_hostgroup);
						generate_mysql_servers_table(&offline_hostgroup);
					}
				}
				delete resultset2;
				resultset2=NULL;
			}
			wrunlock();
			GloAdmin->mysql_servers_wrunlock();
			free(query);
		}
	}
	if (resultset) {
		delete resultset;
		resultset=NULL;
	}
}

Galera_Info *MySQL_HostGroups_Manager::get_galera_node_info(int hostgroup) {
	pthread_mutex_lock(&Galera_Info_mutex);
	auto it2 = Galera_Info_Map.find(hostgroup);
	Galera_Info *info = nullptr;
	if (it2 != Galera_Info_Map.end()) {
		info = it2->second;
	}
	pthread_mutex_unlock(&Galera_Info_mutex);

	return info;
}

void MySQL_HostGroups_Manager::update_galera_set_writer(char *_hostname, int _port, int _writer_hostgroup) {
	std::lock_guard<std::mutex> lock(galera_set_writer_mutex);
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=NULL;
	char *q=NULL;
	char *error=NULL;
	q=(char *)"SELECT hostgroup_id,status FROM mysql_servers JOIN mysql_galera_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup OR hostgroup_id=backup_writer_hostgroup OR hostgroup_id=offline_hostgroup WHERE hostname='%s' AND port=%d";
	query=(char *)malloc(strlen(q)+strlen(_hostname)+32);
	sprintf(query,q,_hostname,_port);
	mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset);
	if (error) {
		free(error);
		error=NULL;
	}
	free(query);

	int writer_is_also_reader=0;
	bool found_writer=false;
	bool found_reader=false;
	int read_HG=-1;
	bool need_converge=false;
	int max_writers = 0;
	Galera_Info *info=NULL;

	if (resultset) {
		// let's get info about this cluster
		pthread_mutex_lock(&Galera_Info_mutex);
		std::map<int , Galera_Info *>::iterator it2;
		it2 = Galera_Info_Map.find(_writer_hostgroup);

		if (it2!=Galera_Info_Map.end()) {
			info=it2->second;
			writer_is_also_reader=info->writer_is_also_reader;
			read_HG=info->reader_hostgroup;
			need_converge=info->need_converge;
			info->need_converge=false;
			max_writers = info->max_writers;
		}
		pthread_mutex_unlock(&Galera_Info_mutex);

		if (resultset->rows_count) {
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				int hostgroup=atoi(r->fields[0]);
				if (hostgroup==_writer_hostgroup) {
					int status=atoi(r->fields[1]);
					if (status==0)
						found_writer=true;
				}
				if (read_HG>=0) {
					if (hostgroup==read_HG) {
						found_reader=true;
					}
				}
			}
		}

		if (need_converge == false) {
			SQLite3_result *resultset2=NULL;
			q = (char *)"SELECT COUNT(*) FROM mysql_servers WHERE hostgroup_id=%d AND status=0";
			query=(char *)malloc(strlen(q)+32);
			sprintf(query,q,_writer_hostgroup);
			mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset2);
			if (resultset2) {
				if (resultset2->rows_count) {
					for (std::vector<SQLite3_row *>::iterator it = resultset2->rows.begin() ; it != resultset2->rows.end(); ++it) {
						SQLite3_row *r=*it;
						int nwriters = atoi(r->fields[0]);
						if (nwriters > max_writers) {
							proxy_warning("Galera: too many writers in HG %d. Max=%d, current=%d\n", _writer_hostgroup, max_writers, nwriters);
							need_converge = true;
						}
					}
				}
				delete resultset2;
			}
			free(query);
		}

		if (need_converge==false) {
			if (found_writer) { // maybe no-op
				if (
					(writer_is_also_reader==0 && found_reader==false)
					||
					(writer_is_also_reader == 1 && found_reader==true)
					||
					(writer_is_also_reader == 2)
				) { // either both true or both false
					delete resultset;
					resultset=NULL;
				}
			}
		}
	}

	if (resultset) { // if we reach there, there is some action to perform
		if (resultset->rows_count) {
			need_converge=false;

			GloAdmin->mysql_servers_wrlock();
			mydb->execute("DELETE FROM mysql_servers_incoming");
			mydb->execute("INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers");
			q=(char *)"UPDATE OR IGNORE mysql_servers_incoming SET hostgroup_id=%d WHERE hostname='%s' AND port=%d AND hostgroup_id in (%d, %d, %d, %d)";
			query=(char *)malloc(strlen(q)+strlen(_hostname)+1024); // increased this buffer as it is used for other queries too
			sprintf(query,q,_writer_hostgroup,_hostname,_port,_writer_hostgroup, info->reader_hostgroup, info->backup_writer_hostgroup, info->offline_hostgroup);
			mydb->execute(query);
			q=(char *)"UPDATE mysql_servers_incoming SET status=0 WHERE hostname='%s' AND port=%d AND hostgroup_id=%d";
			sprintf(query,q,_hostname,_port,_writer_hostgroup);
			mydb->execute(query);
			//free(query);
			q=(char *)"DELETE FROM mysql_servers_incoming WHERE hostname='%s' AND port=%d AND hostgroup_id in (%d, %d, %d)";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_hostname,_port, info->reader_hostgroup, info->backup_writer_hostgroup, info->offline_hostgroup);
			mydb->execute(query);
			//free(query);
			q=(char *)"UPDATE mysql_servers_incoming SET status=0 WHERE hostname='%s' AND port=%d AND hostgroup_id=%d";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_hostname,_port,_writer_hostgroup);
			mydb->execute(query);
			//free(query);
			if (writer_is_also_reader && read_HG>=0) {
				q=(char *)"INSERT OR IGNORE INTO mysql_servers_incoming (hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) SELECT %d,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers_incoming WHERE hostgroup_id=%d AND hostname='%s' AND port=%d";
				sprintf(query,q,read_HG,_writer_hostgroup,_hostname,_port);
				mydb->execute(query);
			}
			converge_galera_config(_writer_hostgroup);
			uint64_t checksum_current = 0;
			uint64_t checksum_incoming = 0;
			{
				int cols=0;
				int affected_rows=0;
				SQLite3_result *resultset_servers=NULL;
				char *query=NULL;
				char *q1 = NULL;
				char *q2 = NULL;
				char *error=NULL;
				q1 = (char *)"SELECT DISTINCT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, mysql_servers.comment FROM mysql_servers JOIN mysql_galera_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=backup_writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE writer_hostgroup=%d ORDER BY hostgroup_id, hostname, port";
				q2 = (char *)"SELECT DISTINCT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, mysql_servers_incoming.comment FROM mysql_servers_incoming JOIN mysql_galera_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=backup_writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE writer_hostgroup=%d ORDER BY hostgroup_id, hostname, port";
				query = (char *)malloc(strlen(q2)+128);
				sprintf(query,q1,_writer_hostgroup);
				mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset_servers);
				if (error == NULL) {
					if (resultset_servers) {
						checksum_current = resultset_servers->raw_checksum();
					}
				}
				if (resultset_servers) {
					delete resultset_servers;
					resultset_servers = NULL;
				}
				sprintf(query,q2,_writer_hostgroup);
				mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset_servers);
				if (error == NULL) {
					if (resultset_servers) {
						checksum_incoming = resultset_servers->raw_checksum();
					}
				}
				if (resultset_servers) {
					delete resultset_servers;
					resultset_servers = NULL;
				}
				free(query);
			}
			if (checksum_incoming!=checksum_current) {
				proxy_warning("Galera: setting host %s:%d as writer\n", _hostname, _port);
				print_galera_nodes_last_status();
				commit();
				wrlock();
				SQLite3_result *resultset2=NULL;
				q=(char *)"SELECT writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, max_writers, writer_is_also_reader FROM mysql_galera_hostgroups WHERE writer_hostgroup=%d";
				sprintf(query,q,_writer_hostgroup);
				mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset2);
				if (resultset2) {
					if (resultset2->rows_count) {
						for (std::vector<SQLite3_row *>::iterator it = resultset2->rows.begin() ; it != resultset2->rows.end(); ++it) {
							SQLite3_row *r=*it;
							int writer_hostgroup=atoi(r->fields[0]);
							int backup_writer_hostgroup=atoi(r->fields[1]);
							int reader_hostgroup=atoi(r->fields[2]);
							int offline_hostgroup=atoi(r->fields[3]);
							q=(char *)"DELETE FROM mysql_servers WHERE hostgroup_id IN (%d , %d , %d , %d)";
							sprintf(query,q,_writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup);
							mydb->execute(query);
							generate_mysql_servers_table(&writer_hostgroup);
							generate_mysql_servers_table(&backup_writer_hostgroup);
							generate_mysql_servers_table(&reader_hostgroup);
							generate_mysql_servers_table(&offline_hostgroup);
						}
					}
					delete resultset2;
					resultset2=NULL;
				}
				wrunlock();
			} else {
				if (GloMTH->variables.hostgroup_manager_verbose > 1) {
					proxy_warning("Galera: skipping setting node %s:%d from hostgroup %d as writer because won't change the list of ONLINE nodes in writer hostgroup\n", _hostname, _port, _writer_hostgroup);
				}
			}
			GloAdmin->mysql_servers_wrunlock();
			free(query);
		}
	}
	if (resultset) {
		delete resultset;
		resultset=NULL;
	}
}

// this function completes the tuning of mysql_servers_incoming
// it assumes that before calling converge_galera_config()
// * GloAdmin->mysql_servers_wrlock() was already called
// * mysql_servers_incoming has already entries copied from mysql_servers and ready to be loaded
// at this moment, it is only used to check if there are more than one writer
void MySQL_HostGroups_Manager::converge_galera_config(int _writer_hostgroup) {

	// we first gather info about the cluster
	pthread_mutex_lock(&Galera_Info_mutex);
	std::map<int , Galera_Info *>::iterator it2;
	it2 = Galera_Info_Map.find(_writer_hostgroup);
	Galera_Info *info=NULL;
	if (it2!=Galera_Info_Map.end()) {
		info=it2->second;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		char *query=NULL;
		char *q=NULL;
		char *error=NULL;
		q=(char *)"SELECT hostgroup_id,hostname,port FROM mysql_servers_incoming WHERE status=0 AND hostgroup_id IN (%d, %d, %d, %d) ORDER BY weight DESC, hostname DESC, port DESC";
		query=(char *)malloc(strlen(q)+256);
		sprintf(query, q, info->writer_hostgroup, info->backup_writer_hostgroup, info->reader_hostgroup, info->offline_hostgroup);
		mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset);
		free(query);
		if (resultset) {
			if (resultset->rows_count) {
				int num_writers=0;
				int num_backup_writers=0;
				for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
					SQLite3_row *r=*it;
					int hostgroup=atoi(r->fields[0]);
					if (hostgroup==info->writer_hostgroup) {
						num_writers++;
					} else {
						if (hostgroup==info->backup_writer_hostgroup) {
							num_backup_writers++;
						}
					}
				}
				if (num_writers > info->max_writers) { // there are more writers than allowed
					int to_move=num_writers-info->max_writers;
					int to_keep = info->max_writers;
					if (GloMTH->variables.hostgroup_manager_verbose > 1) {
						proxy_info("Galera: max_writers=%d , moving %d nodes from writer HG %d to backup HG %d\n", info->max_writers, to_move, info->writer_hostgroup, info->backup_writer_hostgroup);
					}
					//for (std::vector<SQLite3_row *>::reverse_iterator it = resultset->rows.rbegin() ; it != resultset->rows.rend(); ++it) {
					// note: we change the iterator from reverse_iterator to forward iterator
					for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
						SQLite3_row *r=*it;
						int hostgroup=atoi(r->fields[0]);
						if (hostgroup==info->writer_hostgroup) {
							if (to_keep) {
								q=(char *)"UPDATE OR REPLACE mysql_servers_incoming SET status=0 WHERE hostgroup_id=%d AND hostname='%s' AND port=%d";
								query=(char *)malloc(strlen(q)+strlen(r->fields[1])+128);
								sprintf(query,q,info->writer_hostgroup,r->fields[1],atoi(r->fields[2]));
								mydb->execute(query);
								free(query);
								to_keep--;
								continue;
							}
							if (to_move) {
								// if the  server is already in writer hostgroup, we set to shunned #2656
								q=(char *)"UPDATE OR REPLACE mysql_servers_incoming SET status=1 WHERE hostgroup_id=%d AND hostname='%s' AND port=%d";
								query=(char *)malloc(strlen(q)+strlen(r->fields[1])+128);
								sprintf(query,q,info->writer_hostgroup,r->fields[1],atoi(r->fields[2]));
								mydb->execute(query);
								free(query);
								//q=(char *)"UPDATE OR REPLACE mysql_servers_incoming SET status=0, hostgroup_id=%d WHERE hostgroup_id=%d AND hostname='%s' AND port=%d";
								// we copy the server from the writer hostgroup in the backup writer hostgroup #2656
								q=(char *)"INSERT OR IGNORE INTO mysql_servers_incoming SELECT %d, hostname, port, gtid_port, weight, 0, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers_incoming WHERE hostgroup_id=%d AND hostname='%s' AND port=%d";
								query=(char *)malloc(strlen(q)+strlen(r->fields[1])+128);
								sprintf(query,q,info->backup_writer_hostgroup,info->writer_hostgroup,r->fields[1],atoi(r->fields[2]));
								mydb->execute(query);
								free(query);
								to_move--;
							}
						}
					}
				} else {
					if (num_writers < info->max_writers && num_backup_writers) { // or way too low writer
						int to_move= ( (info->max_writers - num_writers) < num_backup_writers ? (info->max_writers - num_writers) : num_backup_writers);
						if (GloMTH->variables.hostgroup_manager_verbose) {
							proxy_info("Galera: max_writers=%d , moving %d nodes from backup HG %d to writer HG %d\n", info->max_writers, to_move, info->backup_writer_hostgroup, info->writer_hostgroup);
						}
						for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
							SQLite3_row *r=*it;
							if (to_move) {
								int hostgroup=atoi(r->fields[0]);
								if (hostgroup==info->backup_writer_hostgroup) {
									q=(char *)"UPDATE OR REPLACE mysql_servers_incoming SET status=0, hostgroup_id=%d WHERE hostgroup_id=%d AND hostname='%s' AND port=%d";
									query=(char *)malloc(strlen(q)+strlen(r->fields[1])+128);
									sprintf(query,q,info->writer_hostgroup,info->backup_writer_hostgroup,r->fields[1],atoi(r->fields[2]));
									if (GloMTH->variables.hostgroup_manager_verbose) {
										proxy_info("Galera: %s\n", query);
									}
									mydb->execute(query);
									free(query);
									to_move--;
								}
							}
						}
					} else {
						if (num_writers == 0 && num_backup_writers == 0) {
							proxy_warning("Galera: we couldn't find any healthy node for writer HG %d\n", info->writer_hostgroup);
							// ask Monitor to get the status of the whole cluster
							std::vector<string> * pn = GloMyMon->galera_find_possible_last_nodes(info->writer_hostgroup);
							if (pn->size()) {
								std::vector<string>::iterator it2;
								for (it2=pn->begin(); it2!=pn->end(); ++it2) {
									string s0 = *it2;
									proxy_info("Galera: possible writer candidate for HG %d: %s\n", info->writer_hostgroup, s0.c_str());
								}
								char *error=NULL;
								int cols;
								int affected_rows;
								SQLite3_result *resultset2=NULL;
								q = (char *)"SELECT hostname, port FROM mysql_servers_incoming WHERE hostgroup_id IN (%d, %d, %d, %d) ORDER BY weight DESC, hostname DESC, port DESC";
								query=(char *)malloc(strlen(q) + 256);
								sprintf(query,q, info->writer_hostgroup, info->backup_writer_hostgroup, info->reader_hostgroup, info->offline_hostgroup);
								mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset2);
								free(query);
								if (resultset2) {
									bool stop = false;
									for (std::vector<SQLite3_row *>::iterator it = resultset2->rows.begin() ; (it != resultset2->rows.end()) && !stop ; ++it) {
										SQLite3_row *r=*it;
										char *h = r->fields[0];
										int p = atoi(r->fields[1]);
										if (h) {
											for (it2=pn->begin(); (it2!=pn->end()) && !stop; ++it2) {
												std::string s = string(*it2);
												std::size_t found=s.find_last_of(":");
												std::string host=s.substr(0,found);
												std::string port=s.substr(found+1);
												int port_n = atoi(port.c_str());
												if (strcmp(h,host.c_str())==0) {
													if (p == port_n) {
														stop = true; // we found a host to make a writer
														proxy_info("Galera: trying to use server %s:%s as a writer for HG %d\n", host.c_str(), port.c_str(), info->writer_hostgroup);
														q=(char *)"UPDATE OR REPLACE mysql_servers_incoming SET status=0, hostgroup_id=%d WHERE hostgroup_id IN (%d, %d, %d, %d)  AND hostname='%s' AND port=%d";
														query=(char *)malloc(strlen(q) + s.length() + 512);
														sprintf(query,q,info->writer_hostgroup, info->writer_hostgroup, info->backup_writer_hostgroup, info->reader_hostgroup, info->offline_hostgroup, host.c_str(), port_n);
														mydb->execute(query);
														free(query);
														int writer_is_also_reader = info->writer_is_also_reader;
														if (writer_is_also_reader) {
															int read_HG = info->reader_hostgroup;
															q=(char *)"INSERT OR IGNORE INTO mysql_servers_incoming (hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) SELECT %d,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers_incoming WHERE hostgroup_id=%d AND hostname='%s' AND port=%d";
															query=(char *)malloc(strlen(q) + s.length() + 128);
															sprintf(query,q,read_HG, info->writer_hostgroup, host.c_str(), port_n);
															mydb->execute(query);
															free(query);
														}
													}
												}
											}
										}
									}
									delete resultset2;
								}
							}
							delete pn;
						}
					}
				}
			}
		}
		if (resultset) {
			delete resultset;
			resultset=NULL;
		}
		if (info->writer_is_also_reader==2) {
			q=(char *)"SELECT hostgroup_id,hostname,port FROM mysql_servers_incoming WHERE status=0 AND hostgroup_id IN (%d, %d, %d, %d) ORDER BY weight DESC, hostname DESC, port DESC";
			query=(char *)malloc(strlen(q)+256);
			sprintf(query, q, info->writer_hostgroup, info->backup_writer_hostgroup, info->reader_hostgroup, info->offline_hostgroup);
			mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset);
			free(query);
			if (resultset) {
				if (resultset->rows_count) {
					int num_writers=0;
					int num_backup_writers=0;
					for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
						SQLite3_row *r=*it;
						int hostgroup=atoi(r->fields[0]);
						if (hostgroup==info->writer_hostgroup) {
							num_writers++;
						} else {
							if (hostgroup==info->backup_writer_hostgroup) {
								num_backup_writers++;
							}
						}
					}
					// just delete the readers which are right now part of the writer hostgroup, preserving
					// any current reader which is only in the reader hostgroup. This is because if a server
					// is only part of the reader hostgroup at this point, means that it's there because of a
					// reason beyond ProxySQL control, e.g. having READ_ONLY=1.
					// Update for #3182:
					// We just want to remove 'readers' which are 'ONLINE' right now, otherwise,
					// we could be removing the introduced 'SHUNNED' readers, placed there by an 'offline soft'
					// operation.
					q=(char*)"DELETE FROM mysql_servers_incoming where hostgroup_id=%d and (hostname,port) in (SELECT hostname,port FROM mysql_servers_incoming WHERE hostgroup_id=%d AND status=0)";
					query=(char*)malloc(strlen(q) + 128);
					sprintf(query, q, info->reader_hostgroup, info->writer_hostgroup);
					mydb->execute(query);
					free(query);

					if (num_backup_writers) { // there are backup writers, only these will be used as readers
						q=(char *)"INSERT OR IGNORE INTO mysql_servers_incoming (hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) SELECT %d,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers_incoming WHERE hostgroup_id=%d";
						query=(char *)malloc(strlen(q) + 128);
						sprintf(query,q, info->reader_hostgroup, info->backup_writer_hostgroup);
						mydb->execute(query);
						free(query);
					}
				}
				delete resultset;
				resultset=NULL;
			}
		}
	} else {
		// we couldn't find the cluster, exits
	}
	pthread_mutex_unlock(&Galera_Info_mutex);
}

void MySQL_HostGroups_Manager::p_update_mysql_gtid_executed() {
	pthread_rwlock_wrlock(&gtid_rwlock);

	std::unordered_map<string, GTID_Server_Data*>::iterator it = gtid_map.begin();
	while(it != gtid_map.end()) {
		GTID_Server_Data* gtid_si = it->second;
		std::string address {};
		std::string port {};
		std::string endpoint_id {};

		if (gtid_si) {
			address = std::string(gtid_si->address);
			port = std::to_string(gtid_si->mysql_port);
		} else {
			std::string s = it->first;
			std::size_t found = s.find_last_of(":");
			address = s.substr(0, found);
			port = s.substr(found + 1);
		}
		endpoint_id = address + ":" + port;

		const auto& gitd_id_counter = this->status.p_gtid_executed_map.find(endpoint_id);
		prometheus::Counter* gtid_counter = nullptr;

		if (gitd_id_counter == this->status.p_gtid_executed_map.end()) {
			auto& gitd_counter =
				this->status.p_dyn_counter_array[p_hg_dyn_counter::gtid_executed];

			gtid_counter = std::addressof(gitd_counter->Add({
				{ "hostname", address },
				{ "port", port },
			}));

			this->status.p_gtid_executed_map.insert(
				{
					endpoint_id,
					gtid_counter
				}
			);
		} else {
			gtid_counter = gitd_id_counter->second;
		}

		if (gtid_si) {
			const auto& cur_executed_gtid = gtid_counter->Value();
			gtid_counter->Increment(gtid_si->events_read - cur_executed_gtid);
		}

		it++;
	}

	pthread_rwlock_unlock(&gtid_rwlock);
}

SQLite3_result * MySQL_HostGroups_Manager::get_stats_mysql_gtid_executed() {
	const int colnum = 4;
	SQLite3_result * result = new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT,"hostname");
	result->add_column_definition(SQLITE_TEXT,"port");
	result->add_column_definition(SQLITE_TEXT,"gtid_executed");
	result->add_column_definition(SQLITE_TEXT,"events");
	int k;
	pthread_rwlock_wrlock(&gtid_rwlock);
	std::unordered_map<string, GTID_Server_Data *>::iterator it = gtid_map.begin();
	while(it != gtid_map.end()) {
		GTID_Server_Data * gtid_si = it->second;
		char buf[64];
		char **pta=(char **)malloc(sizeof(char *)*colnum);
		if (gtid_si) {
			pta[0]=strdup(gtid_si->address);
			sprintf(buf,"%d", (int)gtid_si->mysql_port);
			pta[1]=strdup(buf);
			//sprintf(buf,"%d", mysrvc->port);
			string s1 = gtid_executed_to_string(gtid_si->gtid_executed);
			pta[2]=strdup(s1.c_str());
			sprintf(buf,"%llu", gtid_si->events_read);
			pta[3]=strdup(buf);
		} else {
			std::string s = it->first;
			std::size_t found=s.find_last_of(":");
			std::string host=s.substr(0,found);
			std::string port=s.substr(found+1);
			pta[0]=strdup(host.c_str());
			pta[1]=strdup(port.c_str());
			pta[2]=strdup((char *)"NULL");
			pta[3]=strdup((char *)"0");
		}
		result->add_row(pta);
		for (k=0; k<colnum; k++) {
			if (pta[k])
				free(pta[k]);
		}
		free(pta);
		it++;
	}
	pthread_rwlock_unlock(&gtid_rwlock);
	return result;
}



class MySQL_Errors_stats {
	public:
	int hostgroup;
	char *hostname;
	int port;
	char *username;
	char *client_address;
	char *schemaname;
	int err_no;
	char *last_error;
	time_t first_seen;
	time_t last_seen;
	unsigned long long count_star;
	MySQL_Errors_stats(int hostgroup_, char *hostname_, int port_, char *username_, char *address_, char *schemaname_, int err_no_, char *last_error_, time_t tn) {
		hostgroup = hostgroup_;
		if (hostname_) {
			hostname = strdup(hostname_);
		} else {
			hostname = strdup((char *)"");
		}
		port = port_;
		if (username_) {
			username = strdup(username_);
		} else {
			username = strdup((char *)"");
		}
		if (address_) {
			client_address = strdup(address_);
		} else {
			client_address = strdup((char *)"");
		}
		if (schemaname_) {
			schemaname = strdup(schemaname_);
		} else {
			schemaname = strdup((char *)"");
		}
		err_no = err_no_;
		if (last_error_) {
			last_error = strdup(last_error_);
		} else {
			last_error = strdup((char *)"");
		}
		last_seen = tn;
		first_seen = tn;
		count_star = 1;
	}
	~MySQL_Errors_stats() {
		if (hostname) {
			free(hostname);
			hostname=NULL;
		}
		if (username) {
			free(username);
			username=NULL;
		}
		if (client_address) {
			free(client_address);
			client_address=NULL;
		}
		if (schemaname) {
			free(schemaname);
			schemaname=NULL;
		}
		if (last_error) {
			free(last_error);
			last_error=NULL;
		}
	}
	char **get_row() {
		char buf[128];
		char **pta=(char **)malloc(sizeof(char *)*MYSQL_ERRORS_STATS_FIELD_NUM);
		sprintf(buf,"%d",hostgroup);
		pta[0]=strdup(buf);
		assert(hostname);
		pta[1]=strdup(hostname);
		sprintf(buf,"%d",port);
		pta[2]=strdup(buf);
		assert(username);
		pta[3]=strdup(username);
		assert(client_address);
		pta[4]=strdup(client_address);
		assert(schemaname);
		pta[5]=strdup(schemaname);
		sprintf(buf,"%d",err_no);
		pta[6]=strdup(buf);

		sprintf(buf,"%llu",count_star);
		pta[7]=strdup(buf);

		sprintf(buf,"%ld", first_seen);
		pta[8]=strdup(buf);

		sprintf(buf,"%ld", last_seen);
		pta[9]=strdup(buf);

		assert(last_error);
		pta[10]=strdup(last_error);
		return pta;
	}
	void add_time(unsigned long long n, char *le) {
		count_star++;
		if (first_seen==0) {
			first_seen=n;
		}
		last_seen=n;
		if (strcmp(last_error,le)){
			free(last_error);
			last_error=strdup(le);
		}
	}
	void free_row(char **pta) {
		int i;
		for (i=0;i<MYSQL_ERRORS_STATS_FIELD_NUM;i++) {
			assert(pta[i]);
			free(pta[i]);
		}
		free(pta);
	}
};

void MySQL_HostGroups_Manager::add_mysql_errors(int hostgroup, char *hostname, int port, char *username, char *address, char *schemaname, int err_no, char *last_error) {
	SpookyHash myhash;
	uint64_t hash1;
	uint64_t hash2;
	MySQL_Errors_stats *mes = NULL;
	size_t rand_del_len=strlen(rand_del);
	time_t tn = time(NULL);
	myhash.Init(11,4);
	myhash.Update(&hostgroup,sizeof(hostgroup));
	myhash.Update(rand_del,rand_del_len);
	if (hostname) {
		myhash.Update(hostname,strlen(hostname));
	}
	myhash.Update(rand_del,rand_del_len);
	myhash.Update(&port,sizeof(port));
	if (username) {
		myhash.Update(username,strlen(username));
	}
	myhash.Update(rand_del,rand_del_len);
	if (address) {
		myhash.Update(address,strlen(address));
	}
	myhash.Update(rand_del,rand_del_len);
	if (schemaname) {
		myhash.Update(schemaname,strlen(schemaname));
	}
	myhash.Update(rand_del,rand_del_len);
	myhash.Update(&err_no,sizeof(err_no));

	myhash.Final(&hash1,&hash2);

	std::unordered_map<uint64_t, void *>::iterator it;
	pthread_mutex_lock(&mysql_errors_mutex);

	it=mysql_errors_umap.find(hash1);

	if (it != mysql_errors_umap.end()) {
		// found
		mes=(MySQL_Errors_stats *)it->second;
		mes->add_time(tn, last_error);
/*
		mes->last_seen = tn;
		if (strcmp(mes->last_error,last_error)) {
			free(mes->last_error);
			mes->last_error = strdup(last_error);
			mes->count_star++;
		}
*/
	} else {
		mes = new MySQL_Errors_stats(hostgroup, hostname, port, username, address, schemaname, err_no, last_error, tn);
		mysql_errors_umap.insert(std::make_pair(hash1,(void *)mes));
	}
	pthread_mutex_unlock(&mysql_errors_mutex);
}

SQLite3_result * MySQL_HostGroups_Manager::get_mysql_errors(bool reset) {
	SQLite3_result *result=new SQLite3_result(MYSQL_ERRORS_STATS_FIELD_NUM);
	pthread_mutex_lock(&mysql_errors_mutex);
	result->add_column_definition(SQLITE_TEXT,"hid");
	result->add_column_definition(SQLITE_TEXT,"hostname");
	result->add_column_definition(SQLITE_TEXT,"port");
	result->add_column_definition(SQLITE_TEXT,"username");
	result->add_column_definition(SQLITE_TEXT,"client_address");
	result->add_column_definition(SQLITE_TEXT,"schemaname");
	result->add_column_definition(SQLITE_TEXT,"err_no");
	result->add_column_definition(SQLITE_TEXT,"count_star");
	result->add_column_definition(SQLITE_TEXT,"first_seen");
	result->add_column_definition(SQLITE_TEXT,"last_seen");
	result->add_column_definition(SQLITE_TEXT,"last_error");
	for (std::unordered_map<uint64_t, void *>::iterator it=mysql_errors_umap.begin(); it!=mysql_errors_umap.end(); ++it) {
		MySQL_Errors_stats *mes=(MySQL_Errors_stats *)it->second;
		char **pta=mes->get_row();
		result->add_row(pta);
		mes->free_row(pta);
		if (reset) {
			delete mes;
		}
	}
	if (reset) {
		mysql_errors_umap.erase(mysql_errors_umap.begin(),mysql_errors_umap.end());
	}
	pthread_mutex_unlock(&mysql_errors_mutex);
	return result;
}

AWS_Aurora_Info::AWS_Aurora_Info(int w, int r, int _port, char *_end_addr, int maxl, int al, int minl, int lnc, int ci, int ct, bool _a, int wiar, int nrw, char *c) {
	comment=NULL;
	if (c) {
		comment=strdup(c);
	}
	writer_hostgroup=w;
	reader_hostgroup=r;
	max_lag_ms=maxl;
	add_lag_ms=al;
	min_lag_ms=minl;
	lag_num_checks=lnc;
	check_interval_ms=ci;
	check_timeout_ms=ct;
	writer_is_also_reader=wiar;
	new_reader_weight=nrw;
	active=_a;
	__active=true;
	//need_converge=true;
	aurora_port = _port;
	domain_name = strdup(_end_addr);
}

AWS_Aurora_Info::~AWS_Aurora_Info() {
	if (comment) {
		free(comment);
		comment=NULL;
	}
	if (domain_name) {
		free(domain_name);
		domain_name=NULL;
	}
}

bool AWS_Aurora_Info::update(int r, int _port, char *_end_addr, int maxl, int al, int minl, int lnc, int ci, int ct, bool _a, int wiar, int nrw, char *c) {
	bool ret=false;
	__active=true;
	if (reader_hostgroup!=r) {
		reader_hostgroup=r;
		ret=true;
	}
	if (max_lag_ms!=maxl) {
		max_lag_ms=maxl;
		ret=true;
	}
	if (add_lag_ms!=al) {
		add_lag_ms=al;
		ret=true;
	}
	if (min_lag_ms!=minl) {
		min_lag_ms=minl;
		ret=true;
	}
	if (lag_num_checks!=lnc) {
		lag_num_checks=lnc;
		ret=true;
	}
	if (check_interval_ms!=ci) {
		check_interval_ms=ci;
		ret=true;
	}
	if (check_timeout_ms!=ct) {
		check_timeout_ms=ct;
		ret=true;
	}
	if (writer_is_also_reader != wiar) {
		writer_is_also_reader = wiar;
		ret = true;
	}
	if (new_reader_weight != nrw) {
		new_reader_weight = nrw;
		ret = true;
	}
	if (active!=_a) {
		active=_a;
		ret=true;
	}
	if (aurora_port != _port) {
		aurora_port = _port;
		ret = true;
	}
	if (domain_name) {
		if (_end_addr) {
			if (strcmp(domain_name,_end_addr)) {
				free(domain_name);
				domain_name = strdup(_end_addr);
				ret = true;
			}
		} else {
			free(domain_name);
			domain_name=NULL;
			ret = true;
		}
	} else {
		if (_end_addr) {
			domain_name=strdup(_end_addr);
			ret = true;
		}
	}
	// for comment we don't change return value
	if (comment) {
		if (c) {
			if (strcmp(comment,c)) {
				free(comment);
				comment=strdup(c);
			}
		} else {
			free(comment);
			comment=NULL;
		}
	} else {
		if (c) {
			comment=strdup(c);
		}
	}
	return ret;
}

/**
 * @brief Initializes the supplied 'MyHGC' with the specified 'hostgroup_settings'.
 * @details Input verification is performed in the supplied 'hostgroup_settings'. It's expected to be a valid
 *  JSON that may contain the following fields:
 *   - handle_warnings: Value must be >= 0.
 *
 *  In case input verification fails for a field, supplied 'MyHGC' is NOT updated for that field. An error
 *  message is logged specifying the source of the error.
 *
 * @param hostgroup_settings String containing a JSON defined in 'mysql_hostgroup_attributes'.
 * @param myhgc The 'MyHGC' of the target hostgroup of the supplied 'hostgroup_settings'.
 */
void init_myhgc_hostgroup_settings(const char* hostgroup_settings, MyHGC* myhgc) {
	const uint32_t hid = myhgc->hid;

	if (hostgroup_settings[0] != '\0') {
		try {
			nlohmann::json j = nlohmann::json::parse(hostgroup_settings);

			const auto handle_warnings_check = [](int8_t handle_warnings) -> bool { return handle_warnings == 0 || handle_warnings == 1; };
			const int8_t handle_warnings = j_get_srv_default_int_val<int8_t>(j, hid, "handle_warnings", handle_warnings_check);
			myhgc->attributes.handle_warnings = handle_warnings;

			const auto monitor_slave_lag_when_null_check = [](int32_t monitor_slave_lag_when_null) -> bool 
				{ return (monitor_slave_lag_when_null >= 0 && monitor_slave_lag_when_null <= 604800); };
			const int32_t monitor_slave_lag_when_null = j_get_srv_default_int_val<int32_t>(j, hid, "monitor_slave_lag_when_null", monitor_slave_lag_when_null_check);
			myhgc->attributes.monitor_slave_lag_when_null = monitor_slave_lag_when_null;
		}
		catch (const json::exception& e) {
			proxy_error(
				"JSON parsing for 'mysql_hostgroup_attributes.hostgroup_settings' for hostgroup %d failed with exception `%s`.\n",
				hid, e.what()
			);
		}
	}
}

/**
 * @brief Initializes the supplied 'MyHGC' with the specified 'servers_defaults'.
 * @details Input verification is performed in the supplied 'server_defaults'. It's expected to be a valid
 *  JSON that may contain the following fields:
 *   - weight: Must be an unsigned integer >= 0.
 *   - max_connections: Must be an unsigned integer >= 0.
 *   - use_ssl: Must be a integer with either value 0 or 1.
 *
 *  In case input verification fails for a field, supplied 'MyHGC' is NOT updated for that field. An error
 *  message is logged specifying the source of the error.
 *
 * @param servers_defaults String containing a JSON defined in 'mysql_hostgroup_attributes'.
 * @param myhgc The 'MyHGC' of the target hostgroup of the supplied 'servers_defaults'.
 */
void init_myhgc_servers_defaults(char* servers_defaults, MyHGC* myhgc) {
	uint32_t hid = myhgc->hid;

	if (strcmp(servers_defaults, "") != 0) {
		try {
		    nlohmann::json j = nlohmann::json::parse(servers_defaults);

			const auto weight_check = [] (int64_t weight) -> bool { return weight >= 0; };
			int64_t weight = j_get_srv_default_int_val<int64_t>(j, hid, "weight", weight_check);

			myhgc->servers_defaults.weight = weight;

			const auto max_conns_check = [] (int64_t max_conns) -> bool { return max_conns >= 0; };
			int64_t max_conns = j_get_srv_default_int_val<int64_t>(j, hid, "max_connections", max_conns_check);

			myhgc->servers_defaults.max_connections = max_conns;

			const auto use_ssl_check = [] (int32_t use_ssl) -> bool { return use_ssl == 0 || use_ssl == 1; };
			int32_t use_ssl = j_get_srv_default_int_val<int32_t>(j, hid, "use_ssl", use_ssl_check);

			myhgc->servers_defaults.use_ssl = use_ssl;
		} catch (const json::exception& e) {
			proxy_error(
				"JSON parsing for 'mysql_hostgroup_attributes.servers_defaults' for hostgroup %d failed with exception `%s`.\n",
				hid, e.what()
			);
		}
	}
}

void MySQL_HostGroups_Manager::generate_mysql_hostgroup_attributes_table() {
	if (incoming_hostgroup_attributes==NULL) {
		return;
	}
	int rc;
	sqlite3_stmt *statement=NULL;

	const char * query=(const char *)"INSERT INTO mysql_hostgroup_attributes ( "
		"hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, "
		"init_connect, multiplex, connection_warming, throttle_connections_per_sec, "
		"ignore_session_variables, hostgroup_settings, servers_defaults, comment) VALUES "
		"(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query, -1, &statement, 0);
	rc = mydb->prepare_v2(query, &statement);
	ASSERT_SQLITE_OK(rc, mydb);
	proxy_info("New mysql_hostgroup_attributes table\n");
	bool current_configured[MyHostGroups->len];
	// set configured = false to all
	// in this way later we can known which HG were updated
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		current_configured[i] = myhgc->attributes.configured;
		myhgc->attributes.configured = false;
	}

	/**
	 * @brief We iterate the whole resultset incoming_hostgroup_attributes and configure
	 * both the hostgroup in memory, but also pupulate table mysql_hostgroup_attributes
	 *   connection errors.
	 * @details for each row in incoming_hostgroup_attributes:
	 *   1. it finds (or create) the hostgroup
	 *   2. it writes the in mysql_hostgroup_attributes
	 *   3. it finds (or create) the attributes of the hostgroup
	*/
	for (std::vector<SQLite3_row *>::iterator it = incoming_hostgroup_attributes->rows.begin() ; it != incoming_hostgroup_attributes->rows.end(); ++it) {
		SQLite3_row *r=*it;
		unsigned int hid = (unsigned int)atoi(r->fields[0]);
		MyHGC *myhgc = MyHGC_lookup(hid); // note: MyHGC_lookup() will create the HG if doesn't exist!
		int max_num_online_servers       = atoi(r->fields[1]);
		int autocommit                   = atoi(r->fields[2]);
		int free_connections_pct         = atoi(r->fields[3]);
		char * init_connect              = r->fields[4];
		int multiplex                    = atoi(r->fields[5]);
		int connection_warming           = atoi(r->fields[6]);
		int throttle_connections_per_sec = atoi(r->fields[7]);
		char * ignore_session_variables  = r->fields[8];
		char * hostgroup_settings		 = r->fields[9];
		char * servers_defaults          = r->fields[10];
		char * comment                   = r->fields[11];
		proxy_info("Loading MySQL Hostgroup Attributes info for (%d,%d,%d,%d,\"%s\",%d,%d,%d,\"%s\",\"%s\",\"%s\",\"%s\")\n",
			hid, max_num_online_servers, autocommit, free_connections_pct,
			init_connect, multiplex, connection_warming, throttle_connections_per_sec,
			ignore_session_variables, hostgroup_settings, servers_defaults, comment
		);
		rc=(*proxy_sqlite3_bind_int64)(statement, 1, hid);                          ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 2, max_num_online_servers);       ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 3, autocommit);                   ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 4, free_connections_pct);         ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_text)(statement,  5, init_connect,              -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 6, multiplex);                    ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 7, connection_warming);           ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 8, throttle_connections_per_sec); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_text)(statement,  9, ignore_session_variables,  -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_text)(statement, 10, hostgroup_settings,		-1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_text)(statement, 11, servers_defaults,          -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_text)(statement, 12, comment,                   -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
		SAFE_SQLITE3_STEP2(statement);
		rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, mydb);
		myhgc->attributes.configured                   = true;
		myhgc->attributes.max_num_online_servers       = max_num_online_servers;
		myhgc->attributes.autocommit                   = autocommit;
		myhgc->attributes.free_connections_pct         = free_connections_pct;
		myhgc->attributes.multiplex                    = multiplex;
		myhgc->attributes.connection_warming           = connection_warming;
		myhgc->attributes.throttle_connections_per_sec = throttle_connections_per_sec;
		if (myhgc->attributes.init_connect != NULL)
			free(myhgc->attributes.init_connect);
		myhgc->attributes.init_connect = strdup(init_connect);
		if (myhgc->attributes.comment != NULL)
			free(myhgc->attributes.comment);
		myhgc->attributes.comment = strdup(comment);
		// for ignore_session_variables we store 2 versions:
		// 1. the text
		// 2. the JSON
		// Because calling JSON functions is expensive, we first verify if it changes
		if (myhgc->attributes.ignore_session_variables_text == NULL) {
			myhgc->attributes.ignore_session_variables_text = strdup(ignore_session_variables);
			if (strlen(ignore_session_variables) != 0) { // only if there is a valid JSON
				if (myhgc->attributes.ignore_session_variables_json != nullptr) { delete myhgc->attributes.ignore_session_variables_json; }
				myhgc->attributes.ignore_session_variables_json = new json(json::parse(ignore_session_variables));
			}
		} else {
			if (strcmp(myhgc->attributes.ignore_session_variables_text, ignore_session_variables) != 0) {
				free(myhgc->attributes.ignore_session_variables_text);
				myhgc->attributes.ignore_session_variables_text = strdup(ignore_session_variables);
				if (strlen(ignore_session_variables) != 0) { // only if there is a valid JSON
					if (myhgc->attributes.ignore_session_variables_json != nullptr) { delete myhgc->attributes.ignore_session_variables_json; }
					myhgc->attributes.ignore_session_variables_json = new json(json::parse(ignore_session_variables));
				}
				// TODO: assign the variables
			}
		}
		init_myhgc_hostgroup_settings(hostgroup_settings, myhgc);
		init_myhgc_servers_defaults(servers_defaults, myhgc);
	}
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		if (myhgc->attributes.configured == false) {
			if (current_configured[i] == true) {
				// if configured == false and previously it was configured == true , reset to defaults
				proxy_info("Resetting hostgroup attributes for hostgroup %u\n", myhgc->hid);
				myhgc->reset_attributes();
			}
		}
	}

	(*proxy_sqlite3_finalize)(statement);
	delete incoming_hostgroup_attributes;
	incoming_hostgroup_attributes=NULL;
}

void MySQL_HostGroups_Manager::generate_mysql_servers_ssl_params_table() {
	if (incoming_mysql_servers_ssl_params==NULL) {
		return;
	}
	int rc;
	sqlite3_stmt *statement=NULL;

	const char * query = (const char *)"INSERT INTO mysql_servers_ssl_params ("
		"hostname, port, username, ssl_ca, ssl_cert, ssl_key, ssl_capath, "
		"ssl_crl, ssl_crlpath, ssl_cipher, tls_version, comment) VALUES "
		"(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

	rc = mydb->prepare_v2(query, &statement);
	ASSERT_SQLITE_OK(rc, mydb);
	proxy_info("New mysql_servers_ssl_params table\n");
	std::lock_guard<std::mutex> lock(Servers_SSL_Params_map_mutex);
	Servers_SSL_Params_map.clear();

	for (std::vector<SQLite3_row *>::iterator it = incoming_mysql_servers_ssl_params->rows.begin() ; it != incoming_mysql_servers_ssl_params->rows.end(); ++it) {
		SQLite3_row *r=*it;
		proxy_info("Loading MySQL Server SSL Params for (%s,%s,%s)\n",
			r->fields[0], r->fields[1], r->fields[2]
		);

		rc=(*proxy_sqlite3_bind_text)(statement,  1,  r->fields[0]  , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb); // hostname
		rc=(*proxy_sqlite3_bind_int64)(statement, 2,  atoi(r->fields[1]));                   ASSERT_SQLITE_OK(rc, mydb); // port
		rc=(*proxy_sqlite3_bind_text)(statement,  3,  r->fields[2]  , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb); // username
		rc=(*proxy_sqlite3_bind_text)(statement,  4,  r->fields[3]  , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb); // ssl_ca
		rc=(*proxy_sqlite3_bind_text)(statement,  5,  r->fields[4]  , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb); // ssl_cert
		rc=(*proxy_sqlite3_bind_text)(statement,  6,  r->fields[5]  , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb); // ssl_key
		rc=(*proxy_sqlite3_bind_text)(statement,  7,  r->fields[6]  , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb); // ssl_capath
		rc=(*proxy_sqlite3_bind_text)(statement,  8,  r->fields[7]  , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb); // ssl_crl
		rc=(*proxy_sqlite3_bind_text)(statement,  9,  r->fields[8]  , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb); // ssl_crlpath
		rc=(*proxy_sqlite3_bind_text)(statement,  10, r->fields[9]  , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb); // ssl_cipher
		rc=(*proxy_sqlite3_bind_text)(statement,  11, r->fields[10] , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb); // tls_version
		rc=(*proxy_sqlite3_bind_text)(statement,  12, r->fields[11] , -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb); // comment

		SAFE_SQLITE3_STEP2(statement);
		rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, mydb);

		MySQLServers_SslParams MSSP(
			r->fields[0], atoi(r->fields[1]), r->fields[2],
			r->fields[3], r->fields[4],  r->fields[5],
			r->fields[6], r->fields[7],  r->fields[8],
			r->fields[9], r->fields[10], r->fields[11]
		);
		string MapKey = MSSP.getMapKey(rand_del);
		Servers_SSL_Params_map.emplace(MapKey, MSSP);
	}
	(*proxy_sqlite3_finalize)(statement);
	delete incoming_mysql_servers_ssl_params;
	incoming_mysql_servers_ssl_params=NULL;
}

void MySQL_HostGroups_Manager::generate_mysql_aws_aurora_hostgroups_table() {
	if (incoming_aws_aurora_hostgroups==NULL) {
		return;
	}
	int rc;
	sqlite3_stmt *statement=NULL;
	//sqlite3 *mydb3=mydb->get_db();
	char *query=(char *)"INSERT INTO mysql_aws_aurora_hostgroups(writer_hostgroup,reader_hostgroup,active,aurora_port,domain_name,max_lag_ms,check_interval_ms,"
					    "check_timeout_ms,writer_is_also_reader,new_reader_weight,add_lag_ms,min_lag_ms,lag_num_checks,comment) VALUES "
					    "(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)";
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query, -1, &statement, 0);
	rc = mydb->prepare_v2(query, &statement);
	ASSERT_SQLITE_OK(rc, mydb);
	proxy_info("New mysql_aws_aurora_hostgroups table\n");
	pthread_mutex_lock(&AWS_Aurora_Info_mutex);
	for (std::map<int , AWS_Aurora_Info *>::iterator it1 = AWS_Aurora_Info_Map.begin() ; it1 != AWS_Aurora_Info_Map.end(); ++it1) {
		AWS_Aurora_Info *info=NULL;
		info=it1->second;
		info->__active=false;
	}
	for (std::vector<SQLite3_row *>::iterator it = incoming_aws_aurora_hostgroups->rows.begin() ; it != incoming_aws_aurora_hostgroups->rows.end(); ++it) {
		SQLite3_row *r=*it;
		int writer_hostgroup=atoi(r->fields[0]);
		int reader_hostgroup=atoi(r->fields[1]);
		int active=atoi(r->fields[2]);
		int aurora_port = atoi(r->fields[3]);
		int max_lag_ms = atoi(r->fields[5]);
		int check_interval_ms = atoi(r->fields[6]);
		int check_timeout_ms = atoi(r->fields[7]);
		int writer_is_also_reader = atoi(r->fields[8]);
		int new_reader_weight = atoi(r->fields[9]);
		int add_lag_ms = atoi(r->fields[10]);
		int min_lag_ms = atoi(r->fields[11]);
		int lag_num_checks = atoi(r->fields[12]);
		proxy_info("Loading AWS Aurora info for (%d,%d,%s,%d,\"%s\",%d,%d,%d,%d,%d,%d,\"%s\")\n", writer_hostgroup,reader_hostgroup,(active ? "on" : "off"),aurora_port,
				   r->fields[4],max_lag_ms,add_lag_ms,min_lag_ms,lag_num_checks,check_interval_ms,check_timeout_ms,r->fields[13]);
		rc=(*proxy_sqlite3_bind_int64)(statement, 1, writer_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 2, reader_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 3, active); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 4, aurora_port); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_text)(statement, 5, r->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 6, max_lag_ms); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 7, check_interval_ms); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 8, check_timeout_ms); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 9, writer_is_also_reader); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 10, new_reader_weight); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 11, add_lag_ms); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 12, min_lag_ms); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement, 13, lag_num_checks); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_text)(statement, 14, r->fields[13], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);

		SAFE_SQLITE3_STEP2(statement);
		rc=(*proxy_sqlite3_clear_bindings)(statement); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_reset)(statement); ASSERT_SQLITE_OK(rc, mydb);
		std::map<int , AWS_Aurora_Info *>::iterator it2;
		it2 = AWS_Aurora_Info_Map.find(writer_hostgroup);
		AWS_Aurora_Info *info=NULL;
		if (it2!=AWS_Aurora_Info_Map.end()) {
			info=it2->second;
			bool changed=false;
			changed=info->update(reader_hostgroup, aurora_port, r->fields[4], max_lag_ms, add_lag_ms, min_lag_ms, lag_num_checks, check_interval_ms, check_timeout_ms,  (bool)active, writer_is_also_reader, new_reader_weight, r->fields[10]);
			if (changed) {
				//info->need_converge=true;
			}
		} else {
			info=new AWS_Aurora_Info(writer_hostgroup, reader_hostgroup, aurora_port, r->fields[4], max_lag_ms, add_lag_ms, min_lag_ms, lag_num_checks, check_interval_ms, check_timeout_ms,  (bool)active, writer_is_also_reader, new_reader_weight, r->fields[10]);
			//info->need_converge=true;
			AWS_Aurora_Info_Map.insert(AWS_Aurora_Info_Map.begin(), std::pair<int, AWS_Aurora_Info *>(writer_hostgroup,info));
		}
	}
	(*proxy_sqlite3_finalize)(statement);
	delete incoming_aws_aurora_hostgroups;
	incoming_aws_aurora_hostgroups=NULL;

	// remove missing ones
	for (auto it3 = AWS_Aurora_Info_Map.begin(); it3 != AWS_Aurora_Info_Map.end(); ) {
		AWS_Aurora_Info *info=it3->second;
		if (info->__active==false) {
			delete info;
			it3 = AWS_Aurora_Info_Map.erase(it3);
		} else {
			it3++;
		}
	}
	// TODO: it is now time to compute all the changes


	// it is now time to build a new structure in Monitor
	pthread_mutex_lock(&GloMyMon->aws_aurora_mutex);
	update_aws_aurora_hosts_monitor_resultset(false);
	pthread_mutex_unlock(&GloMyMon->aws_aurora_mutex);

	pthread_mutex_unlock(&AWS_Aurora_Info_mutex);
}



//void MySQL_HostGroups_Manager::aws_aurora_replication_lag_action(int _whid, int _rhid, char *address, unsigned int port, float current_replication_lag, bool enable, bool verbose) {
// this function returns false is the server is in the wrong HG
bool MySQL_HostGroups_Manager::aws_aurora_replication_lag_action(int _whid, int _rhid, char *_server_id, float current_replication_lag_ms, bool enable, bool is_writer, bool verbose) {
	bool ret = false; // return false by default
	bool reader_found_in_whg = false;
	if (is_writer) {
		// if the server is a writer, we will set ret back to true once found
		ret = false;
	}
	unsigned port = 3306;
	char *domain_name = strdup((char *)"");
	{
		pthread_mutex_lock(&AWS_Aurora_Info_mutex);
		std::map<int , AWS_Aurora_Info *>::iterator it2;
		it2 = AWS_Aurora_Info_Map.find(_whid);
		AWS_Aurora_Info *info=NULL;
		if (it2!=AWS_Aurora_Info_Map.end()) {
			info=it2->second;
			if (info->domain_name) {
				free(domain_name);
				domain_name = strdup(info->domain_name);
			}
			port = info->aurora_port;
		}
		pthread_mutex_unlock(&AWS_Aurora_Info_mutex);
	}
	char *address = (char *)malloc(strlen(_server_id)+strlen(domain_name)+1);
	sprintf(address,"%s%s",_server_id,domain_name);
	GloAdmin->mysql_servers_wrlock();
	wrlock();
	int i,j;
	for (i=0; i<(int)MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		if (_whid!=(int)myhgc->hid && _rhid!=(int)myhgc->hid) continue;
		for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
			MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
			if (strcmp(mysrvc->address,address)==0 && mysrvc->port==port) {
				// we found the server
				if (enable==false) {
					if (mysrvc->get_status() == MYSQL_SERVER_STATUS_ONLINE) {
						if (verbose) {
							proxy_warning("Shunning server %s:%d from HG %u with replication lag of %f microseconds\n", address, port, myhgc->hid, current_replication_lag_ms);
						}
						mysrvc->set_status(MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG);
					}
				} else {
					if (mysrvc->get_status() == MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) {
						if (verbose) {
							proxy_warning("Re-enabling server %s:%d from HG %u with replication lag of %f microseconds\n", address, port, myhgc->hid, current_replication_lag_ms);
						}
						mysrvc->set_status(MYSQL_SERVER_STATUS_ONLINE);
					}
				}
				mysrvc->aws_aurora_current_lag_us = current_replication_lag_ms * 1000;
				if (mysrvc->get_status() == MYSQL_SERVER_STATUS_ONLINE || mysrvc->get_status() == MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) {
					// we perform check only if ONLINE or lagging
					if (ret) {
						if (_whid==(int)myhgc->hid && is_writer==false) {
							// the server should be a reader
							// but it is in the writer hostgroup
							ret = false;
							reader_found_in_whg = true;
						}
					} else {
						if (is_writer==true) {
							if (_whid==(int)myhgc->hid) {
								// the server should be a writer
								// and we found it in the writer hostgroup
								ret = true;
							}
						} else {
							if (_rhid==(int)myhgc->hid) {
								// the server should be a reader
								// and we found it in the reader hostgroup
								ret = true;
							}
						}
					}
				}
				if (ret==false)
					if (is_writer==true)
						if (enable==true)
							if (_whid==(int)myhgc->hid)
								if (mysrvc->get_status() == MYSQL_SERVER_STATUS_OFFLINE_HARD) {
									mysrvc->set_status(MYSQL_SERVER_STATUS_ONLINE);
									proxy_warning("Re-enabling server %s:%d from HG %u because it is a writer\n", address, port, myhgc->hid);
									ret = true;
								}
				//goto __exit_aws_aurora_replication_lag_action;
			}
		}
	}
//__exit_aws_aurora_replication_lag_action:
	wrunlock();
	GloAdmin->mysql_servers_wrunlock();
	if (ret == true) {
		if (reader_found_in_whg == true) {
			ret = false;
		}
	}
	free(address);
	free(domain_name);
	return ret;
}

int MySQL_HostGroups_Manager::create_new_server_in_hg(
	uint32_t hid, const srv_info_t& srv_info, const srv_opts_t& srv_opts
) {
	int32_t res = -1;
	MySrvC* mysrvc = find_server_in_hg(hid, srv_info.addr, srv_info.port);

	if (mysrvc == nullptr) {
		char* c_hostname { const_cast<char*>(srv_info.addr.c_str()) };
		MySrvC* mysrvc = new MySrvC(
			c_hostname, srv_info.port, 0, srv_opts.weigth, MYSQL_SERVER_STATUS_ONLINE, 0, srv_opts.max_conns, 0,
			srv_opts.use_ssl, 0, const_cast<char*>("")
		);
		add(mysrvc,hid);
		proxy_info(
			"Adding new discovered %s node %s:%d with: hostgroup=%d, weight=%ld, max_connections=%ld, use_ssl=%d\n",
			srv_info.kind.c_str(), c_hostname, srv_info.port, hid, mysrvc->weight, mysrvc->max_connections,
			mysrvc->use_ssl
		);

		res = 0;
	} else {
		// If the server is found as 'OFFLINE_HARD' we reset the 'MySrvC' values corresponding with the
		// 'servers_defaults' (as in a new 'MySrvC' creation). We then later update these values with the
		// 'servers_defaults' attributes from its corresponding 'MyHGC'. This way we ensure uniform behavior
		// of new servers, and 'OFFLINE_HARD' ones when a user update 'servers_defaults' values, and reloads
		// the servers to runtime.
		if (mysrvc && mysrvc->get_status() == MYSQL_SERVER_STATUS_OFFLINE_HARD) {
			reset_hg_attrs_server_defaults(mysrvc);
			update_hg_attrs_server_defaults(mysrvc, mysrvc->myhgc);
			mysrvc->set_status(MYSQL_SERVER_STATUS_ONLINE);

			proxy_info(
				"Found healthy previously discovered %s node %s:%d as 'OFFLINE_HARD', setting back as 'ONLINE' with:"
					" hostgroup=%d, weight=%ld, max_connections=%ld, use_ssl=%d\n",
				srv_info.kind.c_str(), srv_info.addr.c_str(), srv_info.port, hid, mysrvc->weight,
				mysrvc->max_connections, mysrvc->use_ssl
			);

			res = 0;
		}
	}

	return res;
}

int MySQL_HostGroups_Manager::remove_server_in_hg(uint32_t hid, const string& addr, uint16_t port) {
	MySrvC* mysrvc = find_server_in_hg(hid, addr, port);
	if (mysrvc == nullptr) {
		return -1;
	}

	uint64_t mysrvc_addr = reinterpret_cast<uint64_t>(mysrvc);

	proxy_warning(
		"Removed server at address %ld, hostgroup %d, address %s port %d."
		" Setting status OFFLINE HARD and immediately dropping all free connections."
		" Used connections will be dropped when trying to use them\n",
		mysrvc_addr, hid, mysrvc->address, mysrvc->port
	);

	// Set the server status
	mysrvc->set_status(MYSQL_SERVER_STATUS_OFFLINE_HARD);
	mysrvc->ConnectionsFree->drop_all_connections();

	// TODO-NOTE: This is only required in case the caller isn't going to perform:
	//   - Full deletion of servers in the target 'hid'.
	//   - Table regeneration for the servers in the target 'hid'.
	// This is a very common pattern when further operations have been performed over the
	// servers, e.g. a set of servers additions and deletions over the target hostgroups.
	// ////////////////////////////////////////////////////////////////////////

	// Remove the server from the table
	const string del_srv_query { "DELETE FROM mysql_servers WHERE mem_pointer=" + std::to_string(mysrvc_addr) };
	mydb->execute(del_srv_query.c_str());

	// ////////////////////////////////////////////////////////////////////////

	return 0;
}

// FIXME: complete this!!
void MySQL_HostGroups_Manager::update_aws_aurora_set_writer(int _whid, int _rhid, char *_server_id, bool verbose) {
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=NULL;
	char *q=NULL;
	char *error=NULL;
	//q=(char *)"SELECT hostgroup_id FROM mysql_servers JOIN mysql_galera_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup OR hostgroup_id=backup_writer_hostgroup OR hostgroup_id=offline_hostgroup WHERE hostname='%s' AND port=%d AND status<>3";
	q=(char *)"SELECT hostgroup_id FROM mysql_servers JOIN mysql_aws_aurora_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE hostname='%s%s' AND port=%d AND status<>3 AND hostgroup_id IN (%d, %d)";

	int writer_is_also_reader=0;
	int new_reader_weight = 1;
	bool found_writer=false;
	bool found_reader=false;
	int _writer_hostgroup = _whid;
	int aurora_port = 3306;
	char *domain_name = strdup((char *)"");
	int read_HG=-1;
	{
		pthread_mutex_lock(&AWS_Aurora_Info_mutex);
		std::map<int , AWS_Aurora_Info *>::iterator it2;
		it2 = AWS_Aurora_Info_Map.find(_writer_hostgroup);
		AWS_Aurora_Info *info=NULL;
		if (it2!=AWS_Aurora_Info_Map.end()) {
			info=it2->second;
			writer_is_also_reader=info->writer_is_also_reader;
			new_reader_weight = info->new_reader_weight;
			read_HG = info->reader_hostgroup;
			if (info->domain_name) {
				free(domain_name);
				domain_name = strdup(info->domain_name);
			}
			aurora_port = info->aurora_port;
		}
		pthread_mutex_unlock(&AWS_Aurora_Info_mutex);
	}

	query=(char *)malloc(strlen(q)+strlen(_server_id)+strlen(domain_name)+1024*1024);
	sprintf(query, q, _server_id, domain_name, aurora_port, _whid, _rhid);
	mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset);
	if (error) {
		free(error);
		error=NULL;
	}

	if (resultset) {
		if (resultset->rows_count) {
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				int hostgroup=atoi(r->fields[0]);
				if (hostgroup==_writer_hostgroup) {
					found_writer=true;
				}
				if (read_HG>=0) {
					if (hostgroup==read_HG) {
						found_reader=true;
					}
				}
			}
		}

		if (found_writer) { // maybe no-op
			if (
				(writer_is_also_reader==0 && found_reader==false)
				||
				(writer_is_also_reader > 0 && found_reader==true)
			) { // either both true or both false
				delete resultset;
				resultset=NULL;
			}
		}
	}

	if (resultset) {
		// If we reach there, there is some action to perform.
		// This should be the case most of the time,
		// because the calling function knows if an action is required.
		if (resultset->rows_count) {
			GloAdmin->mysql_servers_wrlock();
			mydb->execute("DELETE FROM mysql_servers_incoming");
			q=(char *)"INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers WHERE hostgroup_id=%d";
			sprintf(query,q,_rhid);
			mydb->execute(query);
			q=(char *)"INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers WHERE hostgroup_id=%d AND hostname='%s%s' AND port=%d";
			sprintf(query, q, _writer_hostgroup, _server_id, domain_name, aurora_port);
			mydb->execute(query);
			q=(char *)"UPDATE OR IGNORE mysql_servers_incoming SET hostgroup_id=%d WHERE hostname='%s%s' AND port=%d AND hostgroup_id<>%d";
			sprintf(query, q, _writer_hostgroup, _server_id, domain_name, aurora_port, _writer_hostgroup);
			mydb->execute(query);
			q=(char *)"DELETE FROM mysql_servers_incoming WHERE hostname='%s%s' AND port=%d AND hostgroup_id<>%d";
			sprintf(query, q, _server_id, domain_name, aurora_port, _writer_hostgroup);
			mydb->execute(query);
			q=(char *)"UPDATE mysql_servers_incoming SET status=0 WHERE hostname='%s%s' AND port=%d AND hostgroup_id=%d";
			sprintf(query, q, _server_id, domain_name, aurora_port, _writer_hostgroup);
			mydb->execute(query);

			// we need to move the old writer into the reader HG
			q=(char *)"DELETE FROM mysql_servers_incoming WHERE status=3 AND hostgroup_id=%d";
			sprintf(query,q,_rhid);
			mydb->execute(query);
			q=(char *)"INSERT OR IGNORE INTO mysql_servers_incoming SELECT %d, hostname, port, gtid_port, %d, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers WHERE hostgroup_id=%d AND status=0";
			sprintf(query,q,_rhid, new_reader_weight, _whid);
			mydb->execute(query);

			if (writer_is_also_reader && read_HG>=0) {
				q=(char *)"INSERT OR IGNORE INTO mysql_servers_incoming (hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) SELECT %d,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers_incoming WHERE hostgroup_id=%d AND hostname='%s%s' AND port=%d";
				sprintf(query, q, read_HG, _writer_hostgroup, _server_id, domain_name, aurora_port);
				mydb->execute(query);
				q = (char *)"UPDATE mysql_servers_incoming SET weight=%d WHERE hostgroup_id=%d AND hostname='%s%s' AND port=%d";
				sprintf(query, q, new_reader_weight, read_HG, _server_id, domain_name, aurora_port);
				mydb->execute(query);
			}
			uint64_t checksum_current = 0;
			uint64_t checksum_incoming = 0;
			{
				int cols=0;
				int affected_rows=0;
				SQLite3_result *resultset_servers=NULL;
				char *query=NULL;
				char *q1 = NULL;
				char *q2 = NULL;
				char *error=NULL;
				q1 = (char *)"SELECT DISTINCT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, mysql_servers.comment FROM mysql_servers JOIN mysql_aws_aurora_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE writer_hostgroup=%d ORDER BY hostgroup_id, hostname, port";
				q2 = (char *)"SELECT DISTINCT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, mysql_servers_incoming.comment FROM mysql_servers_incoming JOIN mysql_aws_aurora_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE writer_hostgroup=%d ORDER BY hostgroup_id, hostname, port";
				query = (char *)malloc(strlen(q2)+128);
				sprintf(query,q1,_writer_hostgroup);
				mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset_servers);
				if (error == NULL) {
					if (resultset_servers) {
						checksum_current = resultset_servers->raw_checksum();
					}
				}
				if (resultset_servers) {
					delete resultset_servers;
					resultset_servers = NULL;
				}
				sprintf(query,q2,_writer_hostgroup);
				mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset_servers);
				if (error == NULL) {
					if (resultset_servers) {
						checksum_incoming = resultset_servers->raw_checksum();
					}
				}
				if (resultset_servers) {
					delete resultset_servers;
					resultset_servers = NULL;
				}
				free(query);
			}
			if (checksum_incoming!=checksum_current) {
				proxy_warning("AWS Aurora: setting host %s%s:%d as writer\n", _server_id, domain_name, aurora_port);
				q = (char *)"INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers WHERE hostgroup_id NOT IN (%d, %d)";
				sprintf(query, q, _rhid, _whid);
				mydb->execute(query);
				commit();
				wrlock();
				q=(char *)"DELETE FROM mysql_servers WHERE hostgroup_id IN (%d , %d)";
				sprintf(query,q,_whid,_rhid);
				mydb->execute(query);
				generate_mysql_servers_table(&_whid);
				generate_mysql_servers_table(&_rhid);
				wrunlock();
			} else {
				if (GloMTH->variables.hostgroup_manager_verbose > 1) {
					proxy_warning("AWS Aurora: skipping setting node %s%s:%d from hostgroup %d as writer because won't change the list of ONLINE nodes in writer hostgroup\n", _server_id, domain_name, aurora_port, _writer_hostgroup);
				}
			}
			GloAdmin->mysql_servers_wrunlock();
			free(query);
			query = NULL;
		} else {
			string full_hostname { string { _server_id } + string { domain_name } };

			GloAdmin->mysql_servers_wrlock();
			wrlock();

			srv_info_t srv_info { full_hostname, static_cast<uint16_t>(aurora_port), "Aurora AWS" };
			srv_opts_t wr_srv_opts { -1, -1, -1 };

			int wr_res = create_new_server_in_hg(_writer_hostgroup, srv_info, wr_srv_opts);
			int rd_res = -1;

			// WRITER can also be placed as READER, or could previously be one
			if (writer_is_also_reader && read_HG >= 0) {
				srv_opts_t rd_srv_opts { new_reader_weight, -1, -1 };
				rd_res = create_new_server_in_hg(read_HG, srv_info, rd_srv_opts);
			}

			// A new server has been created, or an OFFLINE_HARD brought back as ONLINE
			if (wr_res == 0 || rd_res == 0) {
				proxy_info(
					"AWS Aurora: setting new auto-discovered host %s:%d as writer\n", full_hostname.c_str(), aurora_port
				);
				purge_mysql_servers_table();

				const char del_srvs_query_t[] { "DELETE FROM mysql_servers WHERE hostgroup_id IN (%d , %d)" };
				const string del_srvs_query { cstr_format(del_srvs_query_t, _whid, _rhid).str };
				mydb->execute(del_srvs_query.c_str());

				generate_mysql_servers_table(&_whid);
				generate_mysql_servers_table(&_rhid);

				// Update the global checksums after 'mysql_servers' regeneration
				{
					unique_ptr<SQLite3_result> resultset { get_admin_runtime_mysql_servers(mydb) };
					string mysrvs_checksum { get_checksum_from_hash(resultset ? resultset->raw_checksum() : 0) };
					save_runtime_mysql_servers(resultset.release());
					proxy_info("Checksum for table %s is %s\n", "mysql_servers", mysrvs_checksum.c_str());

					pthread_mutex_lock(&GloVars.checksum_mutex);
					update_glovars_mysql_servers_checksum(mysrvs_checksum);
					pthread_mutex_unlock(&GloVars.checksum_mutex);
				}

				// Because 'commit' isn't called, we are required to update 'mysql_servers_for_monitor'.
				update_table_mysql_servers_for_monitor(false);
				// Update AWS Aurora resultset used for monitoring
				update_aws_aurora_hosts_monitor_resultset(true);
			}

			wrunlock();
			GloAdmin->mysql_servers_wrunlock();
		}
	}
	if (resultset) {
		delete resultset;
		resultset=NULL;
	}
	if (query) {
		free(query);
	}
	free(domain_name);
}

void MySQL_HostGroups_Manager::update_aws_aurora_set_reader(int _whid, int _rhid, char *_server_id) {
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=NULL;
	char *q=NULL;
	char *error=NULL;
	int _writer_hostgroup = _whid;
	int aurora_port = 3306;
	int new_reader_weight = 0;
	char *domain_name = strdup((char *)"");
	{
		pthread_mutex_lock(&AWS_Aurora_Info_mutex);
		std::map<int , AWS_Aurora_Info *>::iterator it2;
		it2 = AWS_Aurora_Info_Map.find(_writer_hostgroup);
		AWS_Aurora_Info *info=NULL;
		if (it2!=AWS_Aurora_Info_Map.end()) {
			info=it2->second;
			if (info->domain_name) {
				free(domain_name);
				domain_name = strdup(info->domain_name);
			}
			aurora_port = info->aurora_port;
			new_reader_weight = info->new_reader_weight;
		}
		pthread_mutex_unlock(&AWS_Aurora_Info_mutex);
	}
	q = (char*)"SELECT hostgroup_id FROM mysql_servers JOIN mysql_aws_aurora_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE hostname='%s%s' AND port=%d AND status<>3 AND hostgroup_id IN (%d,%d)";
	query=(char *)malloc(strlen(q)+strlen(_server_id)+strlen(domain_name)+32+32+32);
	sprintf(query, q, _server_id, domain_name, aurora_port, _whid, _rhid);
	mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset);
	if (error) {
		free(error);
		error=NULL;
	}
	free(query);
	if (resultset) { // we lock only if needed
		if (resultset->rows_count) {
			proxy_warning("AWS Aurora: setting host %s%s:%d (part of cluster with writer_hostgroup=%d) in a reader, moving from writer_hostgroup %d to reader_hostgroup %d\n", _server_id, domain_name, aurora_port, _whid, _whid, _rhid);
			GloAdmin->mysql_servers_wrlock();
			mydb->execute("DELETE FROM mysql_servers_incoming");
			mydb->execute("INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers");
			// If server present as WRITER try moving it to 'reader_hostgroup'.
			q=(char *)"UPDATE OR IGNORE mysql_servers_incoming SET hostgroup_id=%d WHERE hostname='%s%s' AND port=%d AND hostgroup_id=%d";
			query=(char *)malloc(strlen(q)+strlen(_server_id)+strlen(domain_name)+512);
			sprintf(query, q, _rhid, _server_id, domain_name, aurora_port, _whid);
			mydb->execute(query);
			// Reader could previously be also a reader, in which case previous operation 'UPDATE OR IGNORE'
			// did nothing. If server is still in the 'writer_hostgroup', we should remove it.
			q=(char *)"DELETE FROM mysql_servers_incoming WHERE hostname='%s%s' AND port=%d AND hostgroup_id=%d";
			sprintf(query, q, _server_id, domain_name, aurora_port, _whid);
			mydb->execute(query);
			q=(char *)"UPDATE mysql_servers_incoming SET status=0 WHERE hostname='%s%s' AND port=%d AND hostgroup_id=%d";
			sprintf(query, q, _server_id, domain_name, aurora_port, _rhid);
			mydb->execute(query);
			commit();
			wrlock();

			q=(char *)"DELETE FROM mysql_servers WHERE hostgroup_id IN (%d , %d)";
			sprintf(query,q,_whid,_rhid);
			mydb->execute(query);
			generate_mysql_servers_table(&_whid);
			generate_mysql_servers_table(&_rhid);

			wrunlock();
			GloAdmin->mysql_servers_wrunlock();
			free(query);
		} else {
			// we couldn't find the server
			// autodiscovery algorithm here
			string full_hostname { string { _server_id } + string { domain_name } };
			GloAdmin->mysql_servers_wrlock();
			wrlock();

			srv_info_t srv_info { full_hostname, static_cast<uint16_t>(aurora_port), "Aurora AWS" };
			srv_opts_t srv_opts { new_reader_weight, -1, -1 };
			int wr_res = create_new_server_in_hg(_rhid, srv_info, srv_opts);

			// A new server has been created, or an OFFLINE_HARD brought back as ONLINE
			if (wr_res == 0) {
				purge_mysql_servers_table();

				const char del_srvs_query_t[] { "DELETE FROM mysql_servers WHERE hostgroup_id IN (%d , %d)" };
				const string del_srvs_query { cstr_format(del_srvs_query_t, _whid, _rhid).str };
				mydb->execute(del_srvs_query.c_str());

				generate_mysql_servers_table(&_whid);
				generate_mysql_servers_table(&_rhid);

				// Update the global checksums after 'mysql_servers' regeneration
				{
					unique_ptr<SQLite3_result> resultset { get_admin_runtime_mysql_servers(mydb) };
					string mysrvs_checksum { get_checksum_from_hash(resultset ? resultset->raw_checksum() : 0) };
					save_runtime_mysql_servers(resultset.release());
					proxy_info("Checksum for table %s is %s\n", "mysql_servers", mysrvs_checksum.c_str());

					pthread_mutex_lock(&GloVars.checksum_mutex);
					update_glovars_mysql_servers_checksum(mysrvs_checksum);
					pthread_mutex_unlock(&GloVars.checksum_mutex);
				}

				// Because 'commit' isn't called, we are required to update 'mysql_servers_for_monitor'.
				update_table_mysql_servers_for_monitor(false);
				// Update AWS Aurora resultset used for monitoring
				update_aws_aurora_hosts_monitor_resultset(true);
			}

			wrunlock();
			GloAdmin->mysql_servers_wrunlock();
		}
	}
	if (resultset) {
		delete resultset;
		resultset=NULL;
	}
	free(domain_name);
}

const char SELECT_AWS_AURORA_SERVERS_FOR_MONITOR[] {
	"SELECT writer_hostgroup, reader_hostgroup, hostname, port, MAX(use_ssl) use_ssl, max_lag_ms, check_interval_ms,"
		" check_timeout_ms, add_lag_ms, min_lag_ms, lag_num_checks FROM mysql_servers"
	" JOIN mysql_aws_aurora_hostgroups ON"
		" hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE active=1 AND status NOT IN (2,3)"
	" GROUP BY writer_hostgroup, hostname, port"
};

void MySQL_HostGroups_Manager::update_aws_aurora_hosts_monitor_resultset(bool lock) {
	if (lock) {
		pthread_mutex_lock(&AWS_Aurora_Info_mutex);
		pthread_mutex_lock(&GloMyMon->aws_aurora_mutex);
	}

	SQLite3_result* resultset = nullptr;
	{
		char* error = nullptr;
		int cols = 0;
		int affected_rows = 0;
		mydb->execute_statement(SELECT_AWS_AURORA_SERVERS_FOR_MONITOR, &error, &cols, &affected_rows, &resultset);
	}

	if (resultset) {
		if (GloMyMon->AWS_Aurora_Hosts_resultset) {
			delete GloMyMon->AWS_Aurora_Hosts_resultset;
		}
		GloMyMon->AWS_Aurora_Hosts_resultset=resultset;
		GloMyMon->AWS_Aurora_Hosts_resultset_checksum=resultset->raw_checksum();
	}

	if (lock) {
		pthread_mutex_unlock(&GloMyMon->aws_aurora_mutex);
		pthread_mutex_unlock(&AWS_Aurora_Info_mutex);
	}
}

MySrvC* MySQL_HostGroups_Manager::find_server_in_hg(unsigned int _hid, const std::string& addr, int port) {
	MySrvC* f_server = nullptr;

	MyHGC* myhgc = nullptr;
	for (uint32_t i = 0; i < MyHostGroups->len; i++) {
		myhgc = static_cast<MyHGC*>(MyHostGroups->index(i));

		if (myhgc->hid == _hid) {
			break;
		}
	}

	if (myhgc != nullptr) {
		for (uint32_t j = 0; j < myhgc->mysrvs->cnt(); j++) {
			MySrvC* mysrvc = static_cast<MySrvC*>(myhgc->mysrvs->servers->index(j));

			if (strcmp(mysrvc->address, addr.c_str()) == 0 && mysrvc->port == port) {
				f_server = mysrvc;
			}
		}
	}

	return f_server;
}

void MySQL_HostGroups_Manager::HostGroup_Server_Mapping::copy_if_not_exists(Type dest_type, Type src_type) {

	assert(dest_type != src_type);

	const std::vector<Node>& src_nodes = mapping[src_type];

	if (src_nodes.empty()) return;

	std::vector<Node>& dest_nodes = mapping[dest_type];
	std::list<Node> append;

	for (const auto& src_node : src_nodes) {

		for (const auto& dest_node : dest_nodes) {

			if (src_node.reader_hostgroup_id == dest_node.reader_hostgroup_id &&
				src_node.writer_hostgroup_id == dest_node.writer_hostgroup_id) {
				goto __skip;
			}
		}

		append.push_back(src_node);

	__skip:
		continue;
	}

	if (append.empty()) {
		return;
	}

	if (dest_nodes.capacity() < (dest_nodes.size() + append.size()))
		dest_nodes.reserve(dest_nodes.size() + append.size());

	for (auto& node : append) {

		if (node.srv->get_status() == MYSQL_SERVER_STATUS_SHUNNED ||
			node.srv->get_status() == MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) {
			// Status updated from "*SHUNNED" to "ONLINE" as "read_only" value was successfully 
			// retrieved from the backend server, indicating server is now online.
			node.srv->set_status(MYSQL_SERVER_STATUS_ONLINE);
		}

		MySrvC* new_srv = insert_HGM(get_hostgroup_id(dest_type, node), node.srv);
			
		if (!new_srv) assert(0);
			
		node.srv = new_srv;
		dest_nodes.push_back(node);
	}
}

void MySQL_HostGroups_Manager::HostGroup_Server_Mapping::remove(Type type, size_t index) {

	std::vector<Node>& nodes = mapping[type];

	// ensure that we're not attempting to access out of the bounds of the container.
	assert(index < nodes.size());

	remove_HGM(nodes[index].srv);

	//Swap the element with the back element, except in the case when we're the last element.
	if (index + 1 != nodes.size())
		std::swap(nodes[index], nodes.back());

	//Pop the back of the container, deleting our old element.
	nodes.pop_back();
}

void MySQL_HostGroups_Manager::HostGroup_Server_Mapping::clear(Type type) {

	for (const auto& node : mapping[type]) {
		remove_HGM(node.srv);
	}

	mapping[type].clear();
}

unsigned int MySQL_HostGroups_Manager::HostGroup_Server_Mapping::get_hostgroup_id(Type type, const Node& node) const {

	if (type == Type::WRITER)
		return node.writer_hostgroup_id;
	else if (type == Type::READER)
		return node.reader_hostgroup_id;
	else
		assert(0);
}

MySrvC* MySQL_HostGroups_Manager::HostGroup_Server_Mapping::insert_HGM(unsigned int hostgroup_id, const MySrvC* srv) {

	MyHGC* myhgc = myHGM->MyHGC_lookup(hostgroup_id);

	if (!myhgc)
		return NULL;

	MySrvC* ret_srv = NULL;
	
	for (uint32_t j = 0; j < myhgc->mysrvs->cnt(); j++) {
		MySrvC* mysrvc = static_cast<MySrvC*>(myhgc->mysrvs->servers->index(j));
		if (strcmp(mysrvc->address, srv->address) == 0 && mysrvc->port == srv->port) {
			if (mysrvc->get_status() == MYSQL_SERVER_STATUS_OFFLINE_HARD) {
				
				mysrvc->gtid_port = srv->gtid_port;
				mysrvc->weight = srv->weight;
				mysrvc->compression = srv->compression;
				mysrvc->max_connections = srv->max_connections;
				mysrvc->max_replication_lag = srv->max_replication_lag;
				mysrvc->use_ssl = srv->use_ssl;
				mysrvc->max_latency_us = srv->max_latency_us;
				mysrvc->comment = strdup(srv->comment);
				mysrvc->set_status(MYSQL_SERVER_STATUS_ONLINE);

				if (GloMTH->variables.hostgroup_manager_verbose) {
					proxy_info(
						"Found server node in Host Group Container %s:%d as 'OFFLINE_HARD', setting back as 'ONLINE' with:"
						" hostgroup_id=%d, gtid_port=%d, weight=%ld, compression=%d, max_connections=%ld, use_ssl=%d,"
						" max_replication_lag=%d, max_latency_ms=%d, comment=%s\n",
						mysrvc->address, mysrvc->port, hostgroup_id, mysrvc->gtid_port, mysrvc->weight, mysrvc->compression,
						mysrvc->max_connections, mysrvc->use_ssl, mysrvc->max_replication_lag, (mysrvc->max_latency_us / 1000),
						mysrvc->comment
					);
				}
				ret_srv = mysrvc;
				break;
			}
		}
	}
	
	if (!ret_srv) {
		if (GloMTH->variables.hostgroup_manager_verbose) {
			proxy_info("Creating new server in HG %d : %s:%d , gtid_port=%d, weight=%ld, status=%d\n", hostgroup_id, srv->address, srv->port, srv->gtid_port, srv->weight, (int)srv->get_status());
		}

		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Adding new server %s:%d , weight=%ld, status=%d, mem_ptr=%p into hostgroup=%d\n", srv->address, srv->port, srv->weight, (int)srv->get_status(), srv, hostgroup_id);

		ret_srv = new MySrvC(srv->address, srv->port, srv->gtid_port, srv->weight, srv->get_status(), srv->compression,
			srv->max_connections, srv->max_replication_lag, srv->use_ssl, (srv->max_latency_us / 1000), srv->comment);

		myhgc->mysrvs->add(ret_srv);
	}

	return ret_srv;
}

void MySQL_HostGroups_Manager::HostGroup_Server_Mapping::remove_HGM(MySrvC* srv) {
	proxy_warning("Removed server at address %p, hostgroup %d, address %s port %d. Setting status OFFLINE HARD and immediately dropping all free connections. Used connections will be dropped when trying to use them\n", (void*)srv, srv->myhgc->hid, srv->address, srv->port);
	srv->set_status(MYSQL_SERVER_STATUS_OFFLINE_HARD);
	srv->ConnectionsFree->drop_all_connections();
}

MySQLServers_SslParams * MySQL_HostGroups_Manager::get_Server_SSL_Params(char *hostname, int port, char *username) {
	string MapKey = string(hostname) + string(rand_del) + to_string(port) + string(rand_del) + string(username);
	std::lock_guard<std::mutex> lock(Servers_SSL_Params_map_mutex);
	auto it = Servers_SSL_Params_map.find(MapKey);
	if (it != Servers_SSL_Params_map.end()) {
		MySQLServers_SslParams * MSSP = new MySQLServers_SslParams(it->second);
		return MSSP;
	} else {
		MapKey = string(hostname) + string(rand_del) + to_string(port) + string(rand_del) + ""; // search for empty username
		it = Servers_SSL_Params_map.find(MapKey);
		if (it != Servers_SSL_Params_map.end()) {
			MySQLServers_SslParams * MSSP = new MySQLServers_SslParams(it->second);
			return MSSP;
		}
	}
	return NULL;
}

/**
* @brief Updates replication hostgroups by adding autodiscovered mysql servers.
* @details Adds each server from 'new_servers' to the 'runtime_mysql_servers' table.
* We then rebuild the 'mysql_servers' table as well as the internal 'hostname_hostgroup_mapping'.
* @param new_servers A vector of tuples where each tuple contains the values needed to add each new server.
*/
void MySQL_HostGroups_Manager::add_discovered_servers_to_mysql_servers_and_replication_hostgroups(
	const vector<tuple<string, int, int>>& new_servers
) {
	int added_new_server = -1;

	GloAdmin->mysql_servers_wrlock();
	wrlock();

	// Add the discovered server with default values
	for (const tuple<string, int, int>& s : new_servers) {
		string host = std::get<0>(s);
		uint16_t port = std::get<1>(s);
		long int hostgroup_id = std::get<2>(s);
			
		srv_info_t srv_info { host.c_str(), port, "AWS RDS" };
		srv_opts_t srv_opts { -1, -1, -1 };

		added_new_server = create_new_server_in_hg(hostgroup_id, srv_info, srv_opts);
	}

	// If servers were added, perform necessary updates to internal structures
	if (added_new_server > -1) {
		purge_mysql_servers_table();
		mydb->execute("DELETE FROM mysql_servers");
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_servers\n");
		generate_mysql_servers_table();

		// Update the global checksums after 'mysql_servers' regeneration
		{
			unique_ptr<SQLite3_result> resultset { get_admin_runtime_mysql_servers(mydb) };
			string mysrvs_checksum { get_checksum_from_hash(resultset ? resultset->raw_checksum() : 0) };
			save_runtime_mysql_servers(resultset.release());

			// Update the runtime_mysql_servers checksum with the new checksum
	    	uint64_t raw_checksum = this->runtime_mysql_servers ? this->runtime_mysql_servers->raw_checksum() : 0;
	    	table_resultset_checksum[HGM_TABLES::MYSQL_SERVERS] = raw_checksum;

			// This is required for preserving coherence in the checksums, otherwise they would be inconsistent with `commit` generated checksums
			SpookyHash rep_hgs_hash {};
			bool init = false;
			uint64_t servers_v2_hash = table_resultset_checksum[HGM_TABLES::MYSQL_SERVERS_V2];

			if (servers_v2_hash) {
				if (init == false) {
					init = true;
					rep_hgs_hash.Init(19, 3);
				}
						
				rep_hgs_hash.Update(&servers_v2_hash, sizeof(servers_v2_hash));
			}

			CUCFT1(
				rep_hgs_hash, init, "mysql_replication_hostgroups", "writer_hostgroup",
				table_resultset_checksum[HGM_TABLES::MYSQL_REPLICATION_HOSTGROUPS]
			);

			proxy_info("Checksum for table %s is %s\n", "mysql_servers", mysrvs_checksum.c_str());

			pthread_mutex_lock(&GloVars.checksum_mutex);
			update_glovars_mysql_servers_checksum(mysrvs_checksum);
			pthread_mutex_unlock(&GloVars.checksum_mutex);
		}

		update_table_mysql_servers_for_monitor(false);
		update_hostgroup_manager_mappings();
	}

	wrunlock();
	GloAdmin->mysql_servers_wrunlock();
}
