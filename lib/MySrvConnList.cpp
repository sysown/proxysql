#include "MySQL_HostGroups_Manager.h"
#include "ConnectionPoolDecision.h"

#include "MySQL_Data_Stream.h"

extern ProxySQL_Admin *GloAdmin;

extern MySQL_Threads_Handler *GloMTH;

extern MySQL_Monitor *GloMyMon;

class MySrvConnList;
class MySrvC;
class MySrvList;
class MyHGC;

MySQL_Connection *MySrvConnList::index(unsigned int _k) {
	return (MySQL_Connection *)conns->index(_k);
}

MySQL_Connection * MySrvConnList::remove(int _k) {
	return (MySQL_Connection *)conns->remove_index_fast(_k);
}

MySrvConnList::MySrvConnList(MySrvC *_mysrvc) {
	mysrvc=_mysrvc;
	conns=new PtrArray();
}

void MySrvConnList::add(MySQL_Connection *c) {
	conns->add(c);
}

MySrvConnList::~MySrvConnList() {
	mysrvc=NULL;
	while (conns_length()) {
		MySQL_Connection *conn=(MySQL_Connection *)conns->remove_index_fast(0);
		delete conn;
	}
	delete conns;
}

void MySrvConnList::drop_all_connections() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Dropping all connections (%u total) on MySrvConnList %p for server %s:%d , hostgroup=%d , status=%d\n", conns_length(), this, mysrvc->address, mysrvc->port, mysrvc->myhgc->hid, (int)mysrvc->get_status());
	while (conns_length()) {
		MySQL_Connection *conn=(MySQL_Connection *)conns->remove_index_fast(0);
		delete conn;
	}
}

void MySrvConnList::mark_connections_unhealthy() {
	for (unsigned int i = 0; i < conns_length(); i++) {
		MySQL_Connection *conn = index(i);
		conn->healthy=false;
		conn->reusable=false;
	}
}

unsigned int calculate_eviction_count(unsigned int conns_free, unsigned int conns_used, unsigned int max_connections) {
	if (conns_free < 1) return 0;
	unsigned int pct_max_connections = (3 * max_connections) / 4;
	unsigned int total = conns_free + conns_used;
	if (pct_max_connections <= total) {
		unsigned int count = total - pct_max_connections;
		return (count == 0) ? 1 : count;
	}
	return 0;
}

bool should_throttle_connection_creation(unsigned int new_connections_now, unsigned int throttle_connections_per_sec) {
	return new_connections_now > throttle_connections_per_sec;
}

ConnectionPoolDecision evaluate_pool_state(
	unsigned int conns_free,
	unsigned int conns_used,
	unsigned int max_connections,
	unsigned int connection_quality_level,
	bool connection_warming,
	int free_connections_pct
) {
	ConnectionPoolDecision decision = { false, false, 0, false };

	// Check connection warming threshold first
	if (connection_warming) {
		unsigned int total = conns_free + conns_used;
		unsigned int expected_warm = (unsigned int)(free_connections_pct) * max_connections / 100;
		if (total < expected_warm) {
			decision.needs_warming = true;
			decision.create_new_connection = true;
			return decision;
		}
	}

	switch (connection_quality_level) {
		case 0: // no good match — must create new, possibly after evicting stale free connections
			decision.create_new_connection = true;
			decision.num_to_evict = calculate_eviction_count(conns_free, conns_used, max_connections);
			decision.evict_connections = (decision.num_to_evict > 0);
			break;
		case 1: // tracked options OK but CHANGE_USER / session reset required — may create new
			if ((conns_used > conns_free) && (max_connections > (conns_free / 2 + conns_used / 2))) {
				decision.create_new_connection = true;
			}
			break;
		case 2: // partial match — reuse
		case 3: // perfect match — reuse
			decision.create_new_connection = false;
			break;
		default:
			decision.create_new_connection = true;
			break;
	}

	return decision;
}

void MySrvConnList::get_random_MyConn_inner_search(unsigned int start, unsigned int end, unsigned int& conn_found_idx, unsigned int& connection_quality_level, unsigned int& number_of_matching_session_variables, const MySQL_Connection * client_conn) {
	char *schema = client_conn->userinfo->schemaname;
	MySQL_Connection * conn=NULL;
	unsigned int k;
	for (k = start;  k < end; k++) {
		conn = (MySQL_Connection *)conns->index(k);
		if (conn->match_tracked_options(client_conn)) {
			if (connection_quality_level == 0) {
				// this is our best candidate so far
				connection_quality_level = 1;
				conn_found_idx = k;
			}
			if (conn->requires_CHANGE_USER(client_conn)==false) {
				if (connection_quality_level == 1) {
					// this is our best candidate so far
					connection_quality_level = 2;
					conn_found_idx = k;
				}
				unsigned int cnt_match = 0; // number of matching session variables
				unsigned int not_match = 0; // number of not matching session variables
				cnt_match = conn->number_of_matching_session_variables(client_conn, not_match);
				if (strcmp(conn->userinfo->schemaname,schema)==0) {
					cnt_match++;
				} else {
					not_match++;
				}
				if (not_match==0) {
					// it seems we found the perfect connection
					number_of_matching_session_variables = cnt_match;
					connection_quality_level = 3;
					conn_found_idx = k;
					return; // exit immediately, we found the perfect connection
				} else {
					// we didn't find the perfect connection
					// but maybe is better than what we have so far?
					if (cnt_match > number_of_matching_session_variables) {
						// this is our best candidate so far
						number_of_matching_session_variables = cnt_match;
						conn_found_idx = k;
					}
				}
			} else {
				if (connection_quality_level == 1) {
					int rca = mysql_thread___reset_connection_algorithm;
					if (rca==1) {
						int ql = GloMTH->variables.connpoll_reset_queue_length;
						if (ql==0) {
							// if:
							// mysql-reset_connection_algorithm=1 and
							// mysql-connpoll_reset_queue_length=0
							// we will not return a connection with connection_quality_level == 1
							// because we want to run COM_CHANGE_USER
							// This change was introduced to work around Galera bug
							// https://github.com/codership/galera/issues/613
							connection_quality_level = 0;
						}
					}
				}
			}
		}
	}
}



MySQL_Connection * MySrvConnList::get_random_MyConn(MySQL_Session *sess, bool ff) {
	MySQL_Connection * conn=NULL;
	unsigned int i;
	unsigned int conn_found_idx = 0;
	unsigned int l=conns_length();
	unsigned int connection_quality_level = 0;
	// connection_quality_level:
	// 0 : not found any good connection, tracked options are not OK
	// 1 : tracked options are OK , but CHANGE USER is required
	// 2 : tracked options are OK , CHANGE USER is not required, but some SET statement or INIT_DB needs to be executed
	// 3 : tracked options are OK , CHANGE USER is not required, and it seems that SET statements or INIT_DB ARE not required
	unsigned int number_of_matching_session_variables = 0; // this includes session variables AND schema
	bool connection_warming = mysql_thread___connection_warming;
	int free_connections_pct = mysql_thread___free_connections_pct;
	if (mysrvc->myhgc->attributes.configured == true) {
		// mysql_hostgroup_attributes takes priority
		connection_warming = mysrvc->myhgc->attributes.connection_warming;
		free_connections_pct = mysrvc->myhgc->attributes.free_connections_pct;
	}
	unsigned int conns_free = mysrvc->ConnectionsFree->conns_length();
	unsigned int conns_used = mysrvc->ConnectionsUsed->conns_length();
	bool needs_warming = false;
	if (connection_warming == true) {
		unsigned int total_connections = conns_free + conns_used;
		unsigned int expected_warm_connections = (unsigned int)free_connections_pct * mysrvc->max_connections / 100;
		if (total_connections < expected_warm_connections) {
			needs_warming = true;
		}
	}
	if (l && ff==false && needs_warming==false) {
		i=rand_fast()%l;
		if (sess && sess->client_myds && sess->client_myds->myconn && sess->client_myds->myconn->userinfo) {
			MySQL_Connection * client_conn = sess->client_myds->myconn;
			get_random_MyConn_inner_search(i, l, conn_found_idx, connection_quality_level, number_of_matching_session_variables, client_conn);
			if (connection_quality_level !=3 ) { // we didn't find the perfect connection
				get_random_MyConn_inner_search(0, i, conn_found_idx, connection_quality_level, number_of_matching_session_variables, client_conn);
			}
			// Evaluate pool state to determine create-vs-reuse and eviction (warming already handled above)
			ConnectionPoolDecision decision = evaluate_pool_state(
				conns_free, conns_used, (unsigned int)mysrvc->max_connections,
				connection_quality_level, false, 0
			);
			// connection_quality_level:
			// 1 : tracked options are OK , but CHANGE USER is required
			// 2 : tracked options are OK , CHANGE USER is not required, but some SET statement or INIT_DB needs to be executed
			switch (connection_quality_level) {
				case 0: // not found any good connection, tracked options are not OK
					// we must check if connections need to be freed before
					// creating a new connection
					{
						if (decision.evict_connections) {
							unsigned int cur_free = conns_free;
							unsigned int connections_to_free = decision.num_to_evict;
							while (cur_free && connections_to_free) {
								MySQL_Connection* c = mysrvc->ConnectionsFree->remove(0);
								delete c;

								cur_free = mysrvc->ConnectionsFree->conns_length();
								connections_to_free -= 1;
							}
						}

						// we must create a new connection
						conn = new MySQL_Connection();
						conn->parent=mysrvc;
						// if attributes.multiplex == true , STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG is set to false. And vice-versa
						conn->set_status(!conn->parent->myhgc->attributes.multiplex, STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG);
						__sync_fetch_and_add(&MyHGM->status.server_connections_created, 1);
						proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
					}
					break;
				case 1: //tracked options are OK , but CHANGE USER is required
					// we may consider creating a new connection
					{
					if (decision.create_new_connection) {
						conn = new MySQL_Connection();
						conn->parent=mysrvc;
						// if attributes.multiplex == true , STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG is set to false. And vice-versa
						conn->set_status(!conn->parent->myhgc->attributes.multiplex, STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG);
						__sync_fetch_and_add(&MyHGM->status.server_connections_created, 1);
						proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
					} else {
						conn=(MySQL_Connection *)conns->remove_index_fast(conn_found_idx);
					}
					}
					break;
				case 2: // tracked options are OK , CHANGE USER is not required, but some SET statement or INIT_DB needs to be executed
				case 3: // tracked options are OK , CHANGE USER is not required, and it seems that SET statements or INIT_DB ARE not required
					// here we return the best connection we have, no matter if connection_quality_level is 2 or 3
					conn=(MySQL_Connection *)conns->remove_index_fast(conn_found_idx);
					break;
				default: // this should never happen
					// LCOV_EXCL_START
					assert(0);
					break;
					// LCOV_EXCL_STOP
			}
		} else {
			conn=(MySQL_Connection *)conns->remove_index_fast(i);
		}
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
		return conn;
	} else {
		unsigned long long curtime = monotonic_time();
		curtime = curtime / 1000 / 1000; // convert to second
		MyHGC *_myhgc = mysrvc->myhgc;
		if (curtime > _myhgc->current_time_now) {
			_myhgc->current_time_now = curtime;
			_myhgc->new_connections_now = 0;
		}
		_myhgc->new_connections_now++;
		unsigned int throttle_connections_per_sec_to_hostgroup = (unsigned int) mysql_thread___throttle_connections_per_sec_to_hostgroup;
		if (_myhgc->attributes.configured == true) {
			// mysql_hostgroup_attributes takes priority
			throttle_connections_per_sec_to_hostgroup = _myhgc->attributes.throttle_connections_per_sec;
		}
		if (should_throttle_connection_creation(_myhgc->new_connections_now, throttle_connections_per_sec_to_hostgroup)) {
			__sync_fetch_and_add(&MyHGM->status.server_connections_delayed, 1);
			return NULL;
		} else {
			conn = new MySQL_Connection();
			conn->parent=mysrvc;
			// if attributes.multiplex == true , STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG is set to false. And vice-versa
			conn->set_status(!conn->parent->myhgc->attributes.multiplex, STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG);
			__sync_fetch_and_add(&MyHGM->status.server_connections_created, 1);
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
			return  conn;
		}
	}
	return NULL; // never reach here
}
