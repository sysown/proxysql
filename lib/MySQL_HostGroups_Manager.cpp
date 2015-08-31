#include "proxysql.h"
#include "cpp.h"

#define char_malloc (char *)malloc
#define itostr(__s, __i)  { __s=char_malloc(32); sprintf(__s, "%lld", __i); }


//#define MYHGM_MYSQL_SERVERS "CREATE TABLE mysql_servers ( hostgroup_id INT NOT NULL DEFAULT 0, hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306, weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , status INT CHECK (status IN (0, 1, 2, 3)) NOT NULL DEFAULT 0, PRIMARY KEY (hostgroup_id, hostname, port) )"



extern MySQL_Threads_Handler *GloMTH;


class MySrvConnList;
class MySrvC;
class MySrvList;
class MyHGC;


MySrvConnList::MySrvConnList(MySrvC *_mysrvc) {
	mysrvc=_mysrvc;
	conns=new PtrArray();
}

void MySrvConnList::add(MySQL_Connection *c) {
	conns->add(c);
}

MySrvConnList::~MySrvConnList() {
	mysrvc=NULL;
	while (conns->len) {
		MySQL_Connection *conn=(MySQL_Connection *)conns->remove_index_fast(0);
		delete conn;
	}
	delete conns;
}

MySrvList::MySrvList(MyHGC *_myhgc) {
	myhgc=_myhgc;
	servers=new PtrArray();
}

void MySrvList::add(MySrvC *s) {
	if (s->myhgc==NULL) {
		s->myhgc=myhgc;
	}
	servers->add(s);
}


int MySrvList::find_idx(MySrvC *s) {
  for (unsigned int i=0; i<servers->len; i++) {
    MySrvC *mysrv=(MySrvC *)servers->index(i);
    if (mysrv==s) {
      return (unsigned int)i;
    }
  }
  return -1;
}

/*
int MySrvList::find_idx(MySQL_Connection *c) {
  for (unsigned int i=0; i<servers->len; i++) {
    MySrvC *mysrv=(MySrvC *)servers->index(i);
    if (mysrv->port==c->port && !strcasecmp(mysrv->address,c->address)) {
      return (unsigned int)i;
    }
  }
  return -1;
}
*/

void MySrvList::remove(MySrvC *s) {
	int i=find_idx(s);
	assert(i>=0);
	servers->remove_index_fast((unsigned int)i);
}

int MySrvConnList::find_idx(MySQL_Connection *c) {
  for (unsigned int i=0; i<conns->len; i++) {
    MySQL_Connection *conn=(MySQL_Connection *)conns->index(i);
    if (conn==c) {
      return (unsigned int)i;
    }
  }
  return -1;
}

void MySrvConnList::remove(MySQL_Connection *c) {
	int i=find_idx(c);
	assert(i>=0);
	conns->remove_index_fast((unsigned int)i);
}

void MySrvConnList::drop_all_connections() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Dropping all connections (%lu total) on MySrvConnList %p for server %s:%d , hostgroup=%d , status=%d\n", conns->len, this, mysrvc->address, mysrvc->port, mysrvc->myhgc->hid, mysrvc->status);
	while (conns->len) {
		MySQL_Connection *conn=(MySQL_Connection *)conns->remove_index_fast(0);
		delete conn;
	}
}


MySrvC::MySrvC(char *add, uint16_t p, unsigned int _weight, enum MySerStatus _status, unsigned int _compression /*, uint8_t _charset */, unsigned int _max_connections, unsigned int _max_replication_lag) {
	address=strdup(add);
	port=p;
	weight=_weight;
	status=_status;
	compression=_compression;
	max_connections=_max_connections;
	max_replication_lag=_max_replication_lag;
	connect_OK=0;
	connect_ERR=0;
	queries_sent=0;
	bytes_sent=0;
	bytes_recv=0;
	time_last_detected_error=0;
	connect_ERR_at_time_last_detected_error=0;
	shunned_automatic=false;
	//charset=_charset;
	myhgc=NULL;
	ConnectionsUsed=new MySrvConnList(this);
	ConnectionsFree=new MySrvConnList(this);
}

void MySrvC::connect_error() {
	// NOTE: this function operates without any mutex
	// although, it is not extremely important if any counter is lost
	// as a single connection failure won't make a significant difference
	__sync_fetch_and_add(&connect_ERR,1);
	time_t t=time(NULL);
	if (t!=time_last_detected_error) {
		time_last_detected_error=t;
		connect_ERR_at_time_last_detected_error=1;
	} else {
		int max_failures = ( mysql_thread___shun_on_failures > mysql_thread___connect_retries_on_failure ? mysql_thread___connect_retries_on_failure : mysql_thread___shun_on_failures) ;
		if (__sync_add_and_fetch(&connect_ERR_at_time_last_detected_error,1) >= (unsigned int)max_failures) {
			status=MYSQL_SERVER_STATUS_SHUNNED;
			shunned_automatic=true;
		}
	}
}

MySrvC::~MySrvC() {
	if (address) free(address);
	delete ConnectionsUsed;
	delete ConnectionsFree;
}

MySrvList::~MySrvList() {
	myhgc=NULL;
	while (servers->len) {
		MySrvC *mysrvc=(MySrvC *)servers->remove_index_fast(0);
		delete mysrvc;
	}
	delete servers;
}


MyHGC::MyHGC(int _hid) {
	hid=_hid;
	mysrvs=new MySrvList(this);
}


MyHGC::~MyHGC() {
	delete mysrvs;
}



/*
class MySrvConnList {
  private:
  MySrvC *mysrvc;
  PtrArray *conns;
};

class MySrvC {  // MySQL Server Container
  public:
  MyHGC *myhgc;
  char *address;
  uint16_t port;
  uint16_t flags;
  unsigned int weight;
  enum MySerStatus status;
  MySrvConnList *ConnectionsUsed;
  MySrvConnList *ConnectionsFree;
};

class MySrvList { // MySQL Server List
  private:
  MyHGC *myhgc;
  PtrArray *servers;
  public:
  MySrvList(MyHGC *_myhgc) {
	}
};

class MyHGC { // MySQL Host Group Container
  public:
  unsigned int hid;
  MySrvList *mysrvs;
  MyHGC(int _hid) {
	}
  ~MyHGC();
};
*/



MySQL_HostGroups_Manager::MySQL_HostGroups_Manager() {
	status.client_connections=0;
	status.client_connections_aborted=0;
	status.client_connections_created=0;
	status.myconnpoll_get=0;
	status.myconnpoll_get_ok=0;
	status.myconnpoll_get_ping=0;
	status.myconnpoll_push=0;
	status.myconnpoll_destroy=0;
	spinlock_rwlock_init(&rwlock);
	mydb=new SQLite3DB();
	mydb->open((char *)"file:mem_mydb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	mydb->execute(MYHGM_MYSQL_SERVERS);
	mydb->execute(MYHGM_MYSQL_SERVERS_INCOMING);
	MyHostGroups=new PtrArray();
}

MySQL_HostGroups_Manager::~MySQL_HostGroups_Manager() {
	while (MyHostGroups->len) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->remove_index_fast(0);
		delete myhgc;
	}
	delete MyHostGroups;
	delete mydb;
}

void MySQL_HostGroups_Manager::rdlock() {
	spin_wrlock(&rwlock);
}

void MySQL_HostGroups_Manager::rdunlock() {
	spin_wrunlock(&rwlock);
}


// wrlock() is only required during commit()
void MySQL_HostGroups_Manager::wrlock() {
	spin_wrlock(&rwlock);
}

void MySQL_HostGroups_Manager::wrunlock() {
	spin_wrunlock(&rwlock);
}

// add a new row in mysql_servers_incoming
// we always assume that the calling thread has acquired a rdlock()
bool MySQL_HostGroups_Manager::server_add(unsigned int hid, char *add, uint16_t p, unsigned int _weight, enum MySerStatus status, unsigned int _comp /*, uint8_t _charset */, unsigned int _max_connections, unsigned int _max_replication_lag) {
	bool ret;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Adding in mysql_servers_incoming server %s:%d in hostgroup %u with weight %u , status %u, %s compression, max_connections %d, max_replication_lag %u\n", add,p,hid,_weight,status, (_comp ? "with" : "without") /*, _charset */ , _max_connections, _max_replication_lag);
	char *q=(char *)"INSERT INTO mysql_servers_incoming VALUES (%u, \"%s\", %u, %u, %u, %u, %u, %u)";
	char *query=(char *)malloc(strlen(q)+strlen(add)+100);
	sprintf(query,q,hid,add,p,_weight,status,_comp /*,_charset */, _max_connections, _max_replication_lag);
	ret=mydb->execute(query);
	free(query);
	return ret;
}


SQLite3_result * MySQL_HostGroups_Manager::execute_query(char *query, char **error) {
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	wrlock();
  mydb->execute_statement(query, error , &cols , &affected_rows , &resultset);
	wrunlock();
	return resultset;
}

bool MySQL_HostGroups_Manager::commit() {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
  char *query=NULL;
	wrlock();
	query=(char *)"SELECT mem_pointer, t1.hostgroup_id, t1.hostname, t1.port FROM mysql_servers t1 LEFT OUTER JOIN mysql_servers_incoming t2 ON (t1.hostgroup_id=t2.hostgroup_id AND t1.hostname=t2.hostname AND t1.port=t2.port) WHERE t2.hostgroup_id IS NULL";
  mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			long long ptr=atoll(r->fields[0]);
			proxy_warning("Removed server at address %lld, hostgroup %s, address %s port %s. Setting status OFFLINE HARD and immediately dropping all free connections. Used connections will be dropped when trying to use them\n", ptr, r->fields[1], r->fields[2], r->fields[3]);
			MySrvC *mysrvc=(MySrvC *)ptr;
			mysrvc->status=MYSQL_SERVER_STATUS_OFFLINE_HARD;
			mysrvc->ConnectionsFree->drop_all_connections();
		}
	}
	if (resultset) { delete resultset; resultset=NULL; }

// INSERT OR IGNORE INTO mysql_servers SELECT ... FROM mysql_servers_incoming
//	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "INSERT OR IGNORE INTO mysql_servers(hostgroup_id, hostname, port, weight, status, compression, max_connections) SELECT hostgroup_id, hostname, port, weight, status, compression, max_connections FROM mysql_servers_incoming\n");
	mydb->execute("INSERT OR IGNORE INTO mysql_servers(hostgroup_id, hostname, port, weight, status, compression, max_connections, max_replication_lag) SELECT hostgroup_id, hostname, port, weight, status, compression, max_connections, max_replication_lag FROM mysql_servers_incoming");


	// SELECT FROM mysql_servers whatever is not identical in mysql_servers_incoming, or where mem_pointer=0 (where there is no pointer yet)
	query=(char *)"SELECT t1.*, t2.weight, t2.status, t2.compression, t2.max_connections, t2.max_replication_lag FROM mysql_servers t1 JOIN mysql_servers_incoming t2 ON (t1.hostgroup_id=t2.hostgroup_id AND t1.hostname=t2.hostname AND t1.port=t2.port) WHERE mem_pointer=0 OR t1.weight<>t2.weight OR t1.status<>t2.status OR t1.compression<>t2.compression OR t1.max_connections<>t2.max_connections OR t1.max_replication_lag<>t2.max_replication_lag";
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
  mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			long long ptr=atoll(r->fields[8]);
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d , weight=%d, status=%d, mem_pointer=%llu, hostgroup=%d, compression=%d\n", r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), (MySerStatus) atoi(r->fields[4]), ptr, atoi(r->fields[0]), atoi(r->fields[5]));
			//fprintf(stderr,"%lld\n", ptr);
			if (ptr==0) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Creating new server %s:%d , weight=%d, status=%d, compression=%d\n", r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), (MySerStatus) atoi(r->fields[4]), atoi(r->fields[5]) );
				MySrvC *mysrvc=new MySrvC(r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), (MySerStatus) atoi(r->fields[4]), atoi(r->fields[5]), atoi(r->fields[6]), atoi(r->fields[7]));
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Adding new server %s:%d , weight=%d, status=%d, mem_ptr=%p into hostgroup=%d\n", r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), (MySerStatus) atoi(r->fields[4]), mysrvc, atoi(r->fields[0]));
				add(mysrvc,atoi(r->fields[0]));
			} else {
				MySrvC *mysrvc=(MySrvC *)ptr;
				if (atoi(r->fields[3])!=atoi(r->fields[9])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing weight for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[3] , mysrvc->weight , atoi(r->fields[9]));
					mysrvc->weight=atoi(r->fields[9]);
				}
				if (atoi(r->fields[4])!=atoi(r->fields[10])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing status for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[4] , mysrvc->status , atoi(r->fields[10]));
					mysrvc->status=(MySerStatus)atoi(r->fields[10]);
					if (mysrvc->status==MYSQL_SERVER_STATUS_SHUNNED) {
						mysrvc->shunned_automatic=false;
					}
				}
				if (atoi(r->fields[5])!=atoi(r->fields[11])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing compression for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[4] , mysrvc->compression , atoi(r->fields[11]));
					mysrvc->compression=atoi(r->fields[11]);
				}
				if (atoi(r->fields[6])!=atoi(r->fields[12])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing max_connections for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[4] , mysrvc->max_connections , atoi(r->fields[12]));
					mysrvc->max_connections=atoi(r->fields[12]);
				}
				if (atoi(r->fields[7])!=atoi(r->fields[13])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing max_replication_lag for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[4] , mysrvc->max_replication_lag , atoi(r->fields[13]));
					mysrvc->max_replication_lag=atoi(r->fields[13]);
				}
			}
		}
	}
	if (resultset) { delete resultset; resultset=NULL; }
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_servers_incoming\n");
	mydb->execute("DELETE FROM mysql_servers_incoming");	

	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_servers\n");
	mydb->execute("DELETE FROM mysql_servers");

	// FIXME: scan all servers and recreate mysql_servers
	generate_mysql_servers_table();

	wrunlock();
	if (GloMTH) {
		GloMTH->signal_all_threads(1);
	}
	return true;
}

void MySQL_HostGroups_Manager::generate_mysql_servers_table() {
	proxy_info("New mysql_servers table\n");
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		MySrvC *mysrvc=NULL;
		for (unsigned int j=0; j<myhgc->mysrvs->servers->len; j++) {
			mysrvc=myhgc->mysrvs->idx(j);
			uintptr_t ptr=(uintptr_t)mysrvc;
			char *q=(char *)"INSERT INTO mysql_servers VALUES(%d,\"%s\",%d,%d,%d,%u,%u,%u,%llu)";
			char *query=(char *)malloc(strlen(q)+8+strlen(mysrvc->address)+8+8+8+8+8+16+32);
			sprintf(query, q, mysrvc->myhgc->hid, mysrvc->address, mysrvc->port, mysrvc->weight, mysrvc->status, mysrvc->compression, mysrvc->max_connections, mysrvc->max_replication_lag, ptr);
			char *st;
			switch (mysrvc->status) {
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
					st=(char *)"SHUNNED";
					break;
			}
			fprintf(stderr,"HID: %d , address: %s , port: %d , weight: %d , status: %s , max_connections: %u , max_replication_lag: %u\n", mysrvc->myhgc->hid, mysrvc->address, mysrvc->port, mysrvc->weight, st, mysrvc->max_connections, mysrvc->max_replication_lag);
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
			//fprintf(stderr,"%s\n",query);
			mydb->execute(query);
			free(query);
		}
	}
}

SQLite3_result * MySQL_HostGroups_Manager::dump_table_mysql_servers() {
	wrlock();
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT hostgroup_id, hostname, port, weight, CASE status WHEN 0 THEN \"ONLINE\" WHEN 1 THEN \"SHUNNED\" WHEN 2 THEN \"OFFLINE_SOFT\" WHEN 3 THEN \"OFFLINE_HARD\" END, compression, max_connections, max_replication_lag FROM mysql_servers";
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
	mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	wrunlock();
	return resultset;
}

MyHGC * MySQL_HostGroups_Manager::MyHGC_create(unsigned int _hid) {
	MyHGC *myhgc=new MyHGC(_hid);
	return myhgc;
}

MyHGC * MySQL_HostGroups_Manager::MyHGC_find(unsigned int _hid) {
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		if (myhgc->hid==_hid) {
			return myhgc;
		}
	}
	return NULL;
}

MyHGC * MySQL_HostGroups_Manager::MyHGC_lookup(unsigned int _hid) {
	MyHGC *myhgc=NULL;
	myhgc=MyHGC_find(_hid);
	if (myhgc==NULL) {
		myhgc=MyHGC_create(_hid);
	} else {
		return myhgc;
	}
	assert(myhgc);
	MyHostGroups->add(myhgc);
	return myhgc;
}

/*
MySrvC * MyHGC::MySrvC_lookup_with_coordinates(MySQL_Connection *c) {
	int i;
	i=MySrvList->find_idx(c);
	assert(i>=0);
}
*/

//MyHGC * MySQL_HostGroups_Manager::MyConn_add_to_pool(MySQL_Connection *c, int _hid) {
void MySQL_HostGroups_Manager::push_MyConn_to_pool(MySQL_Connection *c) {
	assert(c->parent);
	MySrvC *mysrvc=NULL;
//	if (c->parent) {
	//mysrvc=(MySrvC *)(c->parent);
//	} else {
//		MyHGC=MyHGC_lookup(_hid);
//		MySrvC=MyHGC->MySrvC_lookup_with_coordinates(c);
//	}
	wrlock();
	status.myconnpoll_push++;
	mysrvc=(MySrvC *)c->parent;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL_Connection %p, server %s:%d with status %d\n", c, mysrvc->address, mysrvc->port, mysrvc->status);
  mysrvc->ConnectionsUsed->remove(c);
	if (c->largest_query_length > (unsigned int)mysql_thread___threshold_query_length) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d with status %d . largest_query_length = %lu\n", c, mysrvc->address, mysrvc->port, mysrvc->status, c->largest_query_length);
		delete c;
		goto __exit_push_MyConn_to_pool;
	}
	if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) {
		if (c->async_state_machine==ASYNC_IDLE) {
			mysrvc->ConnectionsFree->add(c);
		} else {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d with status %d\n", c, mysrvc->address, mysrvc->port, mysrvc->status);
			delete c;
		}
	} else {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d with status %d\n", c, mysrvc->address, mysrvc->port, mysrvc->status);
		delete c;
	}
__exit_push_MyConn_to_pool:
	wrunlock();
}



MySrvC *MyHGC::get_random_MySrvC() {
	MySrvC *mysrvc=NULL;
	unsigned int j;
	unsigned int sum=0;
	unsigned int l=mysrvs->cnt();
	if (l) {
		//int j=0;
		for (j=0; j<l; j++) {
			mysrvc=mysrvs->idx(j);
			if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) { // consider this server only if ONLINE
				if (mysrvc->ConnectionsUsed->conns->len < mysrvc->max_connections) { // consider this server only if didn't reach max_connections
					sum+=mysrvc->weight;
				}
			} else {
				if (mysrvc->status==MYSQL_SERVER_STATUS_SHUNNED) {
					// try to recover shunned servers
					if (mysrvc->shunned_automatic && mysql_thread___shun_recovery_time) {
						time_t t;
						t=time(NULL);
						// we do all these changes without locking . We assume the server is not used from long
						// even if the server is still in used and any of the follow command fails it is not critical
						// because this is only an attempt to recover a server that is probably dead anyway
						if ((t - mysrvc->time_last_detected_error) > mysql_thread___shun_recovery_time) {
							mysrvc->status=MYSQL_SERVER_STATUS_ONLINE;
							mysrvc->shunned_automatic=false;
							mysrvc->connect_ERR_at_time_last_detected_error=0;
							mysrvc->time_last_detected_error=0;
						}
					}
				}
			}
		}
		if (sum==0) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC NULL because no backend ONLINE or with weight\n");
			return NULL; // if we reach here, we couldn't find any target
		}
		unsigned int k=rand()%sum;
  	k++;
		sum=0;

		for (j=0; j<l; j++) {
			mysrvc=mysrvs->idx(j);
			if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) { // consider this server only if ONLINE
				if (mysrvc->ConnectionsUsed->conns->len < mysrvc->max_connections) { // consider this server only if didn't reach max_connections
					sum+=mysrvc->weight;
					if (k<=sum) {
						proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC %p, server %s:%d\n", mysrvc, mysrvc->address, mysrvc->port);
						return mysrvc;
					}
				}
			}
		}
/*
		i=rand()%l;
		mysrvc=mysrvs->idx(i);
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC %p, server %s:%d\n", mysrvc, mysrvc->address, mysrvc->port);
		return mysrvc;
*/
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC NULL\n");
	return NULL; // if we reach here, we couldn't find any target
}

unsigned int MySrvList::cnt() {
	return servers->len;
}

MySrvC * MySrvList::idx(unsigned int i) { return (MySrvC *)servers->index(i); }

MySQL_Connection * MySrvConnList::get_random_MyConn() {
	MySQL_Connection * conn=NULL;
	unsigned int i;
	unsigned int l=conns->len;
	if (l) {
		i=rand()%l;
		conn=(MySQL_Connection *)conns->remove_index_fast(i);
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
		return conn;
	} else {
		conn = new MySQL_Connection();
		conn->parent=mysrvc;
		//conn->options.charset=mysrvc->charset;
		conn->options.server_capabilities=0;
		if (mysql_thread___have_compress==true && mysrvc->compression) {
			conn->options.server_capabilities|=CLIENT_COMPRESS;
			conn->options.compression_min_length=mysrvc->compression;
		}
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
		return  conn;
	}
	return NULL; // never reach here
}

MySQL_Connection * MySQL_HostGroups_Manager::get_MyConn_from_pool(unsigned int _hid) {
	MySQL_Connection * conn=NULL;
	wrlock();
	status.myconnpoll_get++;
	MyHGC *myhgc=MyHGC_lookup(_hid);
	MySrvC *mysrvc=myhgc->get_random_MySrvC();
	if (mysrvc) { // a MySrvC exists. If not, we return NULL = no targets
		//conn=mysrvc->ConnectionsUsed->get_random_MyConn();
		//mysrvc->ConnectionsFree->add(conn);
		conn=mysrvc->ConnectionsFree->get_random_MyConn();
		mysrvc->ConnectionsUsed->add(conn);
		status.myconnpoll_get_ok++;
	}
//	conn->parent=mysrvc;
	wrunlock();
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, (conn ? conn->parent->address : "") , (conn ? conn->parent->port : 0 ));
	return conn;
}

void MySQL_HostGroups_Manager::destroy_MyConn_from_pool(MySQL_Connection *c) {
	wrlock();
	MySrvC *mysrvc=(MySrvC *)c->parent;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d\n", c, mysrvc->address, mysrvc->port);
	mysrvc->ConnectionsUsed->remove(c);
	delete c;
	status.myconnpoll_destroy++;
	wrunlock();
}



void MySQL_HostGroups_Manager::add(MySrvC *mysrvc, unsigned int _hid) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Adding MySrvC %p (%s:%d) for hostgroup %d\n", mysrvc, mysrvc->address, mysrvc->port, _hid);
	MyHGC *myhgc=MyHGC_lookup(_hid);
	myhgc->mysrvs->add(mysrvc);
}


void MySQL_HostGroups_Manager::replication_lag_action(int _hid, char *address, unsigned int port, int current_replication_lag) {
	wrlock();
	int i,j;
	for (i=0; i<(int)MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		if (_hid >= 0 && _hid!=(int)myhgc->hid) continue;
		for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
			MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
			if (strcmp(mysrvc->address,address)==0 && mysrvc->port==port) {
				if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) {
					if (
						(current_replication_lag==-1 )
						||
						(current_replication_lag>=0 && ((unsigned int)current_replication_lag > mysrvc->max_replication_lag))
					) {
						mysrvc->status=MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG;
					}
				} else {
					if (mysrvc->status==MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) {
						if (current_replication_lag>=0 && ((unsigned int)current_replication_lag <= mysrvc->max_replication_lag)) {
							mysrvc->status=MYSQL_SERVER_STATUS_ONLINE;
						}
					}
				}
				goto __exit_replication_lag_action;
			}
		}
	}
__exit_replication_lag_action:
	wrunlock();
}


int MySQL_HostGroups_Manager::get_multiple_idle_connections(int _hid, unsigned long long _max_last_time_used, MySQL_Connection **conn_list, int num_conn) {
	wrlock();
	int num_conn_current=0;
	int i,j, k;
	for (i=0; i<(int)MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		if (_hid >= 0 && _hid!=(int)myhgc->hid) continue;
		for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
			MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
			if (mysrvc->status!=MYSQL_SERVER_STATUS_ONLINE) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d is not online\n", mysrvc->address, mysrvc->port);
				mysrvc->ConnectionsFree->drop_all_connections();
			}
			
			// drop idle connections if beyond max_connection
			while (mysrvc->ConnectionsFree->conns->len && mysrvc->ConnectionsUsed->conns->len+mysrvc->ConnectionsFree->conns->len > mysrvc->max_connections) {
				MySQL_Connection *conn=(MySQL_Connection *)mysrvc->ConnectionsFree->conns->remove_index_fast(0);
				delete conn;
			}

			
			PtrArray *pa=mysrvc->ConnectionsFree->conns;
			for (k=0; k<(int)pa->len; k++) {
				MySQL_Connection *mc=(MySQL_Connection *)pa->index(k);
				if (mc->last_time_used < _max_last_time_used) {
					if (pa->len > mysql_thread___free_connections_pct*mysrvc->max_connections/100) {
						// the idle connection are more than mysql_thread___free_connections_pct of max_connections
						// we will drop this connection instead of pinging it
						mc=(MySQL_Connection *)pa->remove_index_fast(k);
						delete mc;
						continue;
					}
					mc=(MySQL_Connection *)pa->remove_index_fast(k);
					mysrvc->ConnectionsUsed->add(mc);
					k--;
					conn_list[num_conn_current]=mc;
					num_conn_current++;
					if (num_conn_current>=num_conn) goto __exit_get_multiple_idle_connections;
				}
			}
		}
	}
__exit_get_multiple_idle_connections:
	status.myconnpoll_get_ping+=num_conn_current;
	wrunlock();
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning %d idle connections\n", num_conn_current);
	return num_conn_current;
}

SQLite3_result * MySQL_HostGroups_Manager::SQL3_Connection_Pool() {
  const int colnum=11;
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
  result->add_column_definition(SQLITE_TEXT,"Queries");
  result->add_column_definition(SQLITE_TEXT,"Bytes_sent");
  result->add_column_definition(SQLITE_TEXT,"Bytes_recv");
	wrlock();
	int i,j, k;
	for (i=0; i<(int)MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
			MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
			if (mysrvc->status!=MYSQL_SERVER_STATUS_ONLINE) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d is not online\n", mysrvc->address, mysrvc->port);
				mysrvc->ConnectionsFree->drop_all_connections();
			}
			// drop idle connections if beyond max_connection
			while (mysrvc->ConnectionsFree->conns->len && mysrvc->ConnectionsUsed->conns->len+mysrvc->ConnectionsFree->conns->len > mysrvc->max_connections) {
				MySQL_Connection *conn=(MySQL_Connection *)mysrvc->ConnectionsFree->conns->remove_index_fast(0);
				delete conn;
			}
			char buf[1024];
			char **pta=(char **)malloc(sizeof(char *)*colnum);
			sprintf(buf,"%d", (int)myhgc->hid);
			pta[0]=strdup(buf);
			pta[1]=strdup(mysrvc->address);
			sprintf(buf,"%d", mysrvc->port);
			pta[2]=strdup(buf);
			switch (mysrvc->status) {
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
					assert(0);
					break;
			}
			sprintf(buf,"%u", mysrvc->ConnectionsUsed->conns->len);
			pta[4]=strdup(buf);
			sprintf(buf,"%u", mysrvc->ConnectionsFree->conns->len);
			pta[5]=strdup(buf);
			sprintf(buf,"%u", mysrvc->connect_OK);
			pta[6]=strdup(buf);
			sprintf(buf,"%u", mysrvc->connect_ERR);
			pta[7]=strdup(buf);
			sprintf(buf,"%llu", mysrvc->queries_sent);
			pta[8]=strdup(buf);
			sprintf(buf,"%llu", mysrvc->bytes_sent);
			pta[9]=strdup(buf);
			sprintf(buf,"%llu", mysrvc->bytes_recv);
			pta[10]=strdup(buf);
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
