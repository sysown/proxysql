#include "MySQL_HostGroups_Manager.h"

class MySrvConnList;
class MySrvC;
class MySrvList;
class MyHGC;

MySrvC::MySrvC(
	char* add, uint16_t p, uint16_t gp, int64_t _weight, enum MySerStatus _status, unsigned int _compression,
	int64_t _max_connections, unsigned int _max_replication_lag, int32_t _use_ssl, unsigned int _max_latency_ms,
	char* _comment
) {
	address=strdup(add);
	port=p;
	gtid_port=gp;
	weight=_weight;
	status=_status;
	compression=_compression;
	max_connections=_max_connections;
	max_replication_lag=_max_replication_lag;
	use_ssl=_use_ssl;
	cur_replication_lag=0;
	cur_replication_lag_count=0;
	max_latency_us=_max_latency_ms*1000;
	current_latency_us=0;
	aws_aurora_current_lag_us = 0;
	connect_OK=0;
	connect_ERR=0;
	queries_sent=0;
	bytes_sent=0;
	bytes_recv=0;
	max_connections_used=0;
	queries_gtid_sync=0;
	time_last_detected_error=0;
	connect_ERR_at_time_last_detected_error=0;
	shunned_automatic=false;
	shunned_and_kill_all_connections=false;	// false to default
	//charset=_charset;
	myhgc=NULL;
	comment=strdup(_comment);
	ConnectionsUsed=new MySrvConnList(this);
	ConnectionsFree=new MySrvConnList(this);
}

void MySrvC::connect_error(int err_num, bool get_mutex) {
	// NOTE: this function operates without any mutex
	// although, it is not extremely important if any counter is lost
	// as a single connection failure won't make a significant difference
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Connect failed with code '%d'\n", err_num);
	__sync_fetch_and_add(&connect_ERR,1);
	__sync_fetch_and_add(&MyHGM->status.server_connections_aborted,1);
	if (err_num >= 1048 && err_num <= 1052)
		return;
	if (err_num >= 1054 && err_num <= 1075)
		return;
	if (err_num >= 1099 && err_num <= 1104)
		return;
	if (err_num >= 1106 && err_num <= 1113)
		return;
	if (err_num >= 1116 && err_num <= 1118)
		return;
	if (err_num == 1136 || (err_num >= 1138 && err_num <= 1149))
		return;
	switch (err_num) {
		case 1007: // Can't create database
		case 1008: // Can't drop database
		case 1044: // access denied
		case 1045: // access denied
/*
		case 1048: // Column cannot be null
		case 1049: // Unknown database
		case 1050: // Table already exists
		case 1051: // Unknown table
		case 1052: // Column is ambiguous
*/
		case 1120:
		case 1203: // User %s already has more than 'max_user_connections' active connections
		case 1226: // User '%s' has exceeded the '%s' resource (current value: %ld)
		case 3118: // Access denied for user '%s'. Account is locked..
			return;
			break;
		default:
			break;
	}
	time_t t=time(NULL);
	if (t > time_last_detected_error) {
		time_last_detected_error=t;
		connect_ERR_at_time_last_detected_error=1;
	} else {
		if (t < time_last_detected_error) {
			// time_last_detected_error is in the future
			// this means that monitor has a ping interval too big and tuned that in the future
			return;
		}
		// same time
		/**
		 * @brief The expected configured retries set by 'mysql-connect_retries_on_failure' + '2' extra expected
		 *   connection errors.
		 * @details This two extra connections errors are expected:
		 *   1. An initial connection error generated by the datastream and the connection when being created,
		 *     this is, right after the session has requested a connection to the connection pool. This error takes
		 *     places directly in the state machine from 'MySQL_Connection'. Because of this, we consider this
		 *     additional error to be a consequence of the two states machines, and it's not considered for
		 *     'connect_retries'.
		 *   2. A second connection connection error, which is the initial connection error generated by 'MySQL_Session'
		 *     when already in the 'CONNECTING_SERVER' state. This error is an 'extra error' to always consider, since
		 *     it's not part of the retries specified by 'mysql_thread___connect_retries_on_failure', thus, we set the
		 *     'connect_retries' to be 'mysql_thread___connect_retries_on_failure + 1'.
		 */
		int connect_retries = mysql_thread___connect_retries_on_failure + 1;
		int max_failures = mysql_thread___shun_on_failures > connect_retries ? connect_retries : mysql_thread___shun_on_failures;

		if (__sync_add_and_fetch(&connect_ERR_at_time_last_detected_error,1) >= (unsigned int)max_failures) {
			bool _shu=false;
			if (get_mutex==true)
				MyHGM->wrlock(); // to prevent race conditions, lock here. See #627
			if (status==MYSQL_SERVER_STATUS_ONLINE) {
				status=MYSQL_SERVER_STATUS_SHUNNED;
				shunned_automatic=true;
				_shu=true;
			} else {
				_shu=false;
			}
			if (get_mutex==true)
				MyHGM->wrunlock();
			if (_shu) {
			proxy_error("Shunning server %s:%d with %u errors/sec. Shunning for %u seconds\n", address, port, connect_ERR_at_time_last_detected_error , mysql_thread___shun_recovery_time_sec);
			}
		}
	}
}

void MySrvC::shun_and_killall() {
	status=MYSQL_SERVER_STATUS_SHUNNED;
	shunned_automatic=true;
	shunned_and_kill_all_connections=true;
}

MySrvC::~MySrvC() {
	if (address) free(address);
	if (comment) free(comment);
	delete ConnectionsUsed;
	delete ConnectionsFree;
}