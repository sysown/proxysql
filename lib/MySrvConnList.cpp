#include "MySQL_HostGroups_Manager.h"

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
	unsigned int conn_found_idx;
	unsigned int l=conns_length();
	unsigned int connection_quality_level = 0;
	bool needs_warming = false;
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
	if (connection_warming == true) {
		unsigned int total_connections = mysrvc->ConnectionsFree->conns_length()+mysrvc->ConnectionsUsed->conns_length();
		unsigned int expected_warm_connections = free_connections_pct*mysrvc->max_connections/100;
		if (total_connections < expected_warm_connections) {
			needs_warming = true;
		}
	}
	if (l && ff==false && needs_warming==false) {
		if (l>32768) {
			i=rand()%l;
		} else {
			i=fastrand()%l;
		}
		if (sess && sess->client_myds && sess->client_myds->myconn && sess->client_myds->myconn->userinfo) {
			MySQL_Connection * client_conn = sess->client_myds->myconn;
			get_random_MyConn_inner_search(i, l, conn_found_idx, connection_quality_level, number_of_matching_session_variables, client_conn);
			if (connection_quality_level !=3 ) { // we didn't find the perfect connection
				get_random_MyConn_inner_search(0, i, conn_found_idx, connection_quality_level, number_of_matching_session_variables, client_conn);
			}
			// connection_quality_level:
			// 1 : tracked options are OK , but CHANGE USER is required
			// 2 : tracked options are OK , CHANGE USER is not required, but some SET statement or INIT_DB needs to be executed
			switch (connection_quality_level) {
				case 0: // not found any good connection, tracked options are not OK
					// we must check if connections need to be freed before
					// creating a new connection
					{
						unsigned int conns_free = mysrvc->ConnectionsFree->conns_length();
						unsigned int conns_used = mysrvc->ConnectionsUsed->conns_length();
						unsigned int pct_max_connections = (3 * mysrvc->max_connections) / 4;
						unsigned int connections_to_free = 0;

						if (conns_free >= 1) {
							// connection cleanup is triggered when connections exceed 3/4 of the total
							// allowed max connections, this cleanup ensures that at least *one connection*
							// will be freed.
							if (pct_max_connections <= (conns_free + conns_used)) {
								connections_to_free = (conns_free + conns_used) - pct_max_connections;
								if (connections_to_free == 0) connections_to_free = 1;
							}

							while (conns_free && connections_to_free) {
								MySQL_Connection* conn = mysrvc->ConnectionsFree->remove(0);
								delete conn;

								conns_free = mysrvc->ConnectionsFree->conns_length();
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
					unsigned int conns_free = mysrvc->ConnectionsFree->conns_length();
					unsigned int conns_used = mysrvc->ConnectionsUsed->conns_length();
					if ((conns_used > conns_free) && (mysrvc->max_connections > (conns_free/2 + conns_used/2)) ) {
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
		if (_myhgc->new_connections_now > (unsigned int) throttle_connections_per_sec_to_hostgroup) {
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

