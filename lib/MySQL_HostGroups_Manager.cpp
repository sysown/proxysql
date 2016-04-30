#include "proxysql.h"
#include "cpp.h"

#define char_malloc (char *)malloc
#define itostr(__s, __i)  { __s=char_malloc(32); sprintf(__s, "%lld", __i); }


//#define MYHGM_MYSQL_SERVERS "CREATE TABLE mysql_servers ( hostgroup_id INT NOT NULL DEFAULT 0, hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306, weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , status INT CHECK (status IN (0, 1, 2, 3)) NOT NULL DEFAULT 0, PRIMARY KEY (hostgroup_id, hostname, port) )"


extern ProxySQL_Admin *GloAdmin;

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


MySrvC::MySrvC(char *add, uint16_t p, unsigned int _weight, enum MySerStatus _status, unsigned int _compression /*, uint8_t _charset */, unsigned int _max_connections, unsigned int _max_replication_lag, unsigned int _use_ssl, unsigned int _max_latency_ms) {
	address=strdup(add);
	port=p;
	weight=_weight;
	status=_status;
	compression=_compression;
	max_connections=_max_connections;
	max_replication_lag=_max_replication_lag;
	use_ssl=_use_ssl;
	max_latency_us=_max_latency_ms*1000;
	current_latency_us=0;
	connect_OK=0;
	connect_ERR=0;
	queries_sent=0;
	bytes_sent=0;
	bytes_recv=0;
	time_last_detected_error=0;
	connect_ERR_at_time_last_detected_error=0;
	shunned_automatic=false;
	shunned_and_kill_all_connections=false;	// false to default
	//charset=_charset;
	myhgc=NULL;
	ConnectionsUsed=new MySrvConnList(this);
	ConnectionsFree=new MySrvConnList(this);
}

void MySrvC::connect_error(int err_num) {
	// NOTE: this function operates without any mutex
	// although, it is not extremely important if any counter is lost
	// as a single connection failure won't make a significant difference
	__sync_fetch_and_add(&connect_ERR,1);
	__sync_fetch_and_add(&MyHGM->status.server_connections_aborted,1);
	switch (err_num) {
		case 1044: // access denied
		case 1045: // access denied
		case 1049: //Unknown databas
			return;
			break;
		default:
			break;
	}
	time_t t=time(NULL);
	if (t!=time_last_detected_error) {
		time_last_detected_error=t;
		connect_ERR_at_time_last_detected_error=1;
	} else {
		int max_failures = ( mysql_thread___shun_on_failures > mysql_thread___connect_retries_on_failure ? mysql_thread___connect_retries_on_failure : mysql_thread___shun_on_failures) ;
		if (__sync_add_and_fetch(&connect_ERR_at_time_last_detected_error,1) >= (unsigned int)max_failures) {
			proxy_info("Shunning server %s:%d with %u errors/sec. Shunning for %u seconds\n", address, port, connect_ERR_at_time_last_detected_error , mysql_thread___shun_recovery_time_sec);
			status=MYSQL_SERVER_STATUS_SHUNNED;
			shunned_automatic=true;
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
	status.server_connections_connected=0;
	status.server_connections_aborted=0;
	status.server_connections_created=0;
	status.servers_table_version=0;
	status.myconnpoll_get=0;
	status.myconnpoll_get_ok=0;
	status.myconnpoll_get_ping=0;
	status.myconnpoll_push=0;
	status.myconnpoll_destroy=0;
	status.autocommit_cnt=0;
	status.commit_cnt=0;
	status.rollback_cnt=0;
	status.autocommit_cnt_filtered=0;
	status.commit_cnt_filtered=0;
	status.rollback_cnt_filtered=0;
	spinlock_rwlock_init(&rwlock);
	admindb=NULL;	// initialized only if needed
	mydb=new SQLite3DB();
	mydb->open((char *)"file:mem_mydb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	mydb->execute(MYHGM_MYSQL_SERVERS);
	mydb->execute(MYHGM_MYSQL_SERVERS_INCOMING);
	mydb->execute(MYHGM_MYSQL_REPLICATION_HOSTGROUPS);
	MyHostGroups=new PtrArray();
	incoming_replication_hostgroups=NULL;
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

unsigned int MySQL_HostGroups_Manager::get_servers_table_version() {
	return __sync_fetch_and_add(&status.servers_table_version,0);
}

// add a new row in mysql_servers_incoming
// we always assume that the calling thread has acquired a rdlock()
bool MySQL_HostGroups_Manager::server_add(unsigned int hid, char *add, uint16_t p, unsigned int _weight, enum MySerStatus status, unsigned int _comp /*, uint8_t _charset */, unsigned int _max_connections, unsigned int _max_replication_lag, unsigned int _use_ssl, unsigned int _max_latency_ms ) {
	bool ret;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Adding in mysql_servers_incoming server %s:%d in hostgroup %u with weight %u , status %u, %s compression, max_connections %d, max_replication_lag %u, use_ssl=%u, max_latency_ms=%u\n", add,p,hid,_weight,status, (_comp ? "with" : "without") /*, _charset */ , _max_connections, _max_replication_lag, _use_ssl, _max_latency_ms);
	char *q=(char *)"INSERT INTO mysql_servers_incoming VALUES (%u, \"%s\", %u, %u, %u, %u, %u, %u, %u, %u)";
	char *query=(char *)malloc(strlen(q)+strlen(add)+128);
	sprintf(query,q,hid,add,p,_weight,status,_comp /*,_charset */, _max_connections, _max_replication_lag, _use_ssl, _max_latency_ms);
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

	// purge table
	purge_mysql_servers_table();

	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_servers\n");
	mydb->execute("DELETE FROM mysql_servers");
	generate_mysql_servers_table();

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
			//__sync_fetch_and_sub(&status.server_connections_connected, mysrvc->ConnectionsFree->conns->len);
			mysrvc->ConnectionsFree->drop_all_connections();
		}
	}
	if (resultset) { delete resultset; resultset=NULL; }

	mydb->execute("DELETE FROM mysql_servers");
	generate_mysql_servers_table();

// INSERT OR IGNORE INTO mysql_servers SELECT ... FROM mysql_servers_incoming
//	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "INSERT OR IGNORE INTO mysql_servers(hostgroup_id, hostname, port, weight, status, compression, max_connections) SELECT hostgroup_id, hostname, port, weight, status, compression, max_connections FROM mysql_servers_incoming\n");
	mydb->execute("INSERT OR IGNORE INTO mysql_servers(hostgroup_id, hostname, port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms) SELECT hostgroup_id, hostname, port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms FROM mysql_servers_incoming");


	// SELECT FROM mysql_servers whatever is not identical in mysql_servers_incoming, or where mem_pointer=0 (where there is no pointer yet)
	query=(char *)"SELECT t1.*, t2.weight, t2.status, t2.compression, t2.max_connections, t2.max_replication_lag, t2.use_ssl, t2.max_latency_ms FROM mysql_servers t1 JOIN mysql_servers_incoming t2 ON (t1.hostgroup_id=t2.hostgroup_id AND t1.hostname=t2.hostname AND t1.port=t2.port) WHERE mem_pointer=0 OR t1.weight<>t2.weight OR t1.status<>t2.status OR t1.compression<>t2.compression OR t1.max_connections<>t2.max_connections OR t1.max_replication_lag<>t2.max_replication_lag OR t1.use_ssl<>t2.use_ssl OR t1.max_latency_ms<>t2.max_latency_ms";
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
  mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			long long ptr=atoll(r->fields[10]); // increase this index every time a new column is added
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d , weight=%d, status=%d, mem_pointer=%llu, hostgroup=%d, compression=%d\n", r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), (MySerStatus) atoi(r->fields[4]), ptr, atoi(r->fields[0]), atoi(r->fields[5]));
			//fprintf(stderr,"%lld\n", ptr);
			if (ptr==0) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Creating new server %s:%d , weight=%d, status=%d, compression=%d\n", r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), (MySerStatus) atoi(r->fields[4]), atoi(r->fields[5]) );
				MySrvC *mysrvc=new MySrvC(r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), (MySerStatus) atoi(r->fields[4]), atoi(r->fields[5]), atoi(r->fields[6]), atoi(r->fields[7]), atoi(r->fields[8]), atoi(r->fields[9])); // add new fields here if adding more columns in mysql_servers
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Adding new server %s:%d , weight=%d, status=%d, mem_ptr=%p into hostgroup=%d\n", r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), (MySerStatus) atoi(r->fields[4]), mysrvc, atoi(r->fields[0]));
				add(mysrvc,atoi(r->fields[0]));
			} else {
				MySrvC *mysrvc=(MySrvC *)ptr;
				// carefully increase the 2nd index by 1 for every new column added
				if (atoi(r->fields[3])!=atoi(r->fields[11])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing weight for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[3] , mysrvc->weight , atoi(r->fields[11]));
					mysrvc->weight=atoi(r->fields[11]);
				}
				if (atoi(r->fields[4])!=atoi(r->fields[12])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing status for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[4] , mysrvc->status , atoi(r->fields[12]));
					mysrvc->status=(MySerStatus)atoi(r->fields[12]);
					if (mysrvc->status==MYSQL_SERVER_STATUS_SHUNNED) {
						mysrvc->shunned_automatic=false;
					}
				}
				if (atoi(r->fields[5])!=atoi(r->fields[13])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing compression for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[5] , mysrvc->compression , atoi(r->fields[13]));
					mysrvc->compression=atoi(r->fields[13]);
				}
				if (atoi(r->fields[6])!=atoi(r->fields[14])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing max_connections for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[6] , mysrvc->max_connections , atoi(r->fields[14]));
					mysrvc->max_connections=atoi(r->fields[14]);
				}
				if (atoi(r->fields[7])!=atoi(r->fields[15])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing max_replication_lag for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[7] , mysrvc->max_replication_lag , atoi(r->fields[15]));
					mysrvc->max_replication_lag=atoi(r->fields[15]);
				}
				if (atoi(r->fields[8])!=atoi(r->fields[16])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing use_ssl for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[8] , mysrvc->use_ssl , atoi(r->fields[16]));
					mysrvc->use_ssl=atoi(r->fields[16]);
				}
				if (atoi(r->fields[9])!=atoi(r->fields[17])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing max_latency_ms for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[9] , mysrvc->max_latency_ms , atoi(r->fields[17]));
					mysrvc->max_latency_us=1000*atoi(r->fields[17]);
				}
			}
		}
	}
	if (resultset) { delete resultset; resultset=NULL; }
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_servers_incoming\n");
	mydb->execute("DELETE FROM mysql_servers_incoming");	

	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_servers\n");
	mydb->execute("DELETE FROM mysql_servers");

	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_replication_hostgroups\n");
	mydb->execute("DELETE FROM mysql_replication_hostgroups");

	generate_mysql_servers_table();
	generate_mysql_replication_hostgroups_table();

	__sync_fetch_and_add(&status.servers_table_version,1);
	wrunlock();
	if (GloMTH) {
		GloMTH->signal_all_threads(1);
	}
	return true;
}


void MySQL_HostGroups_Manager::purge_mysql_servers_table() {
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		MySrvC *mysrvc=NULL;
		for (unsigned int j=0; j<myhgc->mysrvs->servers->len; j++) {
			mysrvc=myhgc->mysrvs->idx(j);
			if (mysrvc->status==MYSQL_SERVER_STATUS_OFFLINE_HARD) {
				if (mysrvc->ConnectionsUsed->conns->len==0 && mysrvc->ConnectionsFree->conns->len==0) {
					// no more connections for OFFLINE_HARD server, removing it
					mysrvc=(MySrvC *)myhgc->mysrvs->servers->remove_index_fast(j);
					delete mysrvc;
				}
			}
		}
	}
}

void MySQL_HostGroups_Manager::generate_mysql_servers_table() {
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		MySrvC *mysrvc=NULL;
		for (unsigned int j=0; j<myhgc->mysrvs->servers->len; j++) {
			mysrvc=myhgc->mysrvs->idx(j);
			uintptr_t ptr=(uintptr_t)mysrvc;
			char *q=(char *)"INSERT INTO mysql_servers VALUES(%d,\"%s\",%d,%d,%d,%u,%u,%u,%u,%u,%llu)";
			char *query=(char *)malloc(strlen(q)+8+strlen(mysrvc->address)+8+8+8+8+8+16+8+16+32);
			sprintf(query, q, mysrvc->myhgc->hid, mysrvc->address, mysrvc->port, mysrvc->weight, mysrvc->status, mysrvc->compression, mysrvc->max_connections, mysrvc->max_replication_lag, mysrvc->use_ssl, mysrvc->max_latency_us/1000,  ptr);
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
			fprintf(stderr,"HID: %d , address: %s , port: %d , weight: %d , status: %s , max_connections: %u , max_replication_lag: %u , use_ssl: %u , max_latency_ms: %u\n", mysrvc->myhgc->hid, mysrvc->address, mysrvc->port, mysrvc->weight, st, mysrvc->max_connections, mysrvc->max_replication_lag, mysrvc->use_ssl, mysrvc->max_latency_us*1000);
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
			//fprintf(stderr,"%s\n",query);
			mydb->execute(query);
			free(query);
		}
	}
}

void MySQL_HostGroups_Manager::generate_mysql_replication_hostgroups_table() {
	if (incoming_replication_hostgroups==NULL)
		return;
	proxy_info("New mysql_replication_hostgroups table\n");
	for (std::vector<SQLite3_row *>::iterator it = incoming_replication_hostgroups->rows.begin() ; it != incoming_replication_hostgroups->rows.end(); ++it) {
		SQLite3_row *r=*it;
		char query[256];
		sprintf(query,"INSERT INTO mysql_replication_hostgroups VALUES(%s,%s)",r->fields[0],r->fields[1]);
		mydb->execute(query);
		fprintf(stderr,"writer_hostgroup: %s , reader_hostgroup: %s\n", r->fields[0],r->fields[1]);
	}
	incoming_replication_hostgroups=NULL;
}

SQLite3_result * MySQL_HostGroups_Manager::dump_table_mysql_servers() {
	wrlock();

	// purge table
	purge_mysql_servers_table();

	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_servers\n");
	mydb->execute("DELETE FROM mysql_servers");
	generate_mysql_servers_table();

	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT hostgroup_id, hostname, port, weight, CASE status WHEN 0 THEN \"ONLINE\" WHEN 1 THEN \"SHUNNED\" WHEN 2 THEN \"OFFLINE_SOFT\" WHEN 3 THEN \"OFFLINE_HARD\" END, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms FROM mysql_servers";
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
	mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	wrunlock();
	return resultset;
}

SQLite3_result * MySQL_HostGroups_Manager::dump_table_mysql_replication_hostgroups() {
	wrlock();
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT writer_hostgroup, reader_hostgroup FROM mysql_replication_hostgroups";
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
			c->optimize();
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
	unsigned int TotalUsedConn=0;
	unsigned int l=mysrvs->cnt();
	if (l) {
		//int j=0;
		for (j=0; j<l; j++) {
			mysrvc=mysrvs->idx(j);
			if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) { // consider this server only if ONLINE
				if (mysrvc->ConnectionsUsed->conns->len < mysrvc->max_connections) { // consider this server only if didn't reach max_connections
					if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : mysql_thread___default_max_latency_ms*1000 ) ) { // consider the host only if not too far
						sum+=mysrvc->weight;
						TotalUsedConn+=mysrvc->ConnectionsUsed->conns->len;
					}
				}
			} else {
				if (mysrvc->status==MYSQL_SERVER_STATUS_SHUNNED) {
					// try to recover shunned servers
					if (mysrvc->shunned_automatic && mysql_thread___shun_recovery_time_sec) {
						time_t t;
						t=time(NULL);
						// we do all these changes without locking . We assume the server is not used from long
						// even if the server is still in used and any of the follow command fails it is not critical
						// because this is only an attempt to recover a server that is probably dead anyway

						// the next few lines of code try to solve issue #530
						int max_wait_sec = ( mysql_thread___shun_recovery_time_sec * 1000 >= mysql_thread___connect_timeout_server_max ? mysql_thread___connect_timeout_server_max/1000 - 1 : mysql_thread___shun_recovery_time_sec );
						if (max_wait_sec < 1) { // min wait time should be at least 1 second
							max_wait_sec = 1;
						}
						if ((t - mysrvc->time_last_detected_error) > max_wait_sec) {
							if (
								(mysrvc->shunned_and_kill_all_connections==false) // it is safe to bring it back online
								||
								(mysrvc->shunned_and_kill_all_connections==true && mysrvc->ConnectionsUsed->conns->len==0 && mysrvc->ConnectionsFree->conns->len==0) // if shunned_and_kill_all_connections is set, ensure all connections are already dropped
							) {
								mysrvc->status=MYSQL_SERVER_STATUS_ONLINE;
								mysrvc->shunned_automatic=false;
								mysrvc->shunned_and_kill_all_connections=false;
								mysrvc->connect_ERR_at_time_last_detected_error=0;
								mysrvc->time_last_detected_error=0;
								// if a server is taken back online, consider it immediately
								if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : mysql_thread___default_max_latency_ms*1000 ) ) { // consider the host only if not too far
									sum+=mysrvc->weight;
									TotalUsedConn+=mysrvc->ConnectionsUsed->conns->len;
								}
							}
						}
					}
				}
			}
		}
		if (sum==0) {
			// per issue #531 , we try a desperate attempt to bring back online any shunned server
			// we do this lowering the maximum wait time to 10%
			// most of the follow code is copied from few lines above
			time_t t;
			t=time(NULL);
			int max_wait_sec = ( mysql_thread___shun_recovery_time_sec * 1000 >= mysql_thread___connect_timeout_server_max ? mysql_thread___connect_timeout_server_max/100 - 1 : mysql_thread___shun_recovery_time_sec/10 );
			if (max_wait_sec < 1) { // min wait time should be at least 1 second
				max_wait_sec = 1;
			}
			if ((t - mysrvc->time_last_detected_error) > max_wait_sec) {
				mysrvc->status=MYSQL_SERVER_STATUS_ONLINE;
				mysrvc->shunned_automatic=false;
				mysrvc->connect_ERR_at_time_last_detected_error=0;
				mysrvc->time_last_detected_error=0;
				// if a server is taken back online, consider it immediately
				if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : mysql_thread___default_max_latency_ms*1000 ) ) { // consider the host only if not too far
					sum+=mysrvc->weight;
					TotalUsedConn+=mysrvc->ConnectionsUsed->conns->len;
				}
			}
		}
		if (sum==0) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC NULL because no backend ONLINE or with weight\n");
			return NULL; // if we reach here, we couldn't find any target
		}

		unsigned int New_sum=0;
		unsigned int New_TotalUsedConn=0;

		// we will now scan again to ignore overloaded server
		for (j=0; j<l; j++) {
			mysrvc=mysrvs->idx(j);
			if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) { // consider this server only if ONLINE
				unsigned int len=mysrvc->ConnectionsUsed->conns->len;
				if (len < mysrvc->max_connections) { // consider this server only if didn't reach max_connections
					if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : mysql_thread___default_max_latency_ms*1000 ) ) { // consider the host only if not too far
						if ((len * sum) <= (TotalUsedConn * mysrvc->weight * 1.5 + 1)) {
							New_sum+=mysrvc->weight;
							New_TotalUsedConn+=len;
						}
					}
				}
			}
		}

		if (New_sum==0) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC NULL because no backend ONLINE or with weight\n");
			return NULL; // if we reach here, we couldn't find any target
		}

		unsigned int k=rand()%New_sum;
  	k++;
		New_sum=0;

		for (j=0; j<l; j++) {
			mysrvc=mysrvs->idx(j);
			if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) { // consider this server only if ONLINE
				unsigned int len=mysrvc->ConnectionsUsed->conns->len;
				if (len < mysrvc->max_connections) { // consider this server only if didn't reach max_connections
					if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : mysql_thread___default_max_latency_ms*1000 ) ) { // consider the host only if not too far
						if ((len * sum) <= (TotalUsedConn * mysrvc->weight * 1.5 + 1)) {
							New_sum+=mysrvc->weight;
							if (k<=New_sum) {
								proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC %p, server %s:%d\n", mysrvc, mysrvc->address, mysrvc->port);
								return mysrvc;
							}
						}
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
		// deprecating this . #363
		//conn->options.server_capabilities=0;
		//if (mysql_thread___have_compress==true && mysrvc->compression) {
		//	conn->options.server_capabilities|=CLIENT_COMPRESS;
		//	conn->options.compression_min_length=mysrvc->compression;
		//}
		__sync_fetch_and_add(&MyHGM->status.server_connections_created, 1);
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
	status.myconnpoll_destroy++;
	//status.server_connections_connected--;
	wrunlock();
	delete c;
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
//						(current_replication_lag==-1 )
//						||
						(current_replication_lag>=0 && ((unsigned int)current_replication_lag > mysrvc->max_replication_lag))
					) {
						proxy_info("Shunning server %s:%d with replication lag of %d second\n", address, port, current_replication_lag);
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

void MySQL_HostGroups_Manager::drop_all_idle_connections() {
	// NOTE: the caller should hold wrlock
	int i, j;
	for (i=0; i<(int)MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
			MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
			if (mysrvc->status!=MYSQL_SERVER_STATUS_ONLINE) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d is not online\n", mysrvc->address, mysrvc->port);
				//__sync_fetch_and_sub(&status.server_connections_connected, mysrvc->ConnectionsFree->conns->len);
				mysrvc->ConnectionsFree->drop_all_connections();
			}

			// Drop idle connections if beyond max_connection
			while (mysrvc->ConnectionsFree->conns->len && mysrvc->ConnectionsUsed->conns->len+mysrvc->ConnectionsFree->conns->len > mysrvc->max_connections) {
				MySQL_Connection *conn=(MySQL_Connection *)mysrvc->ConnectionsFree->conns->remove_index_fast(0);
				delete conn;
				//__sync_fetch_and_sub(&status.server_connections_connected, 1);
			}

			PtrArray *pa=mysrvc->ConnectionsFree->conns;
			while (pa->len > mysql_thread___free_connections_pct*mysrvc->max_connections/100) {
				MySQL_Connection *mc=(MySQL_Connection *)pa->remove_index_fast(0);
				delete mc;
				//__sync_fetch_and_sub(&status.server_connections_connected, 1);
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
	int i,j, k;
	for (i=0; i<(int)MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		if (_hid >= 0 && _hid!=(int)myhgc->hid) continue;
		for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
			MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
			PtrArray *pa=mysrvc->ConnectionsFree->conns;
			for (k=0; k<(int)pa->len; k++) {
				MySQL_Connection *mc=(MySQL_Connection *)pa->index(k);
				// If the connection is idle ...
				if (mc->last_time_used < _max_last_time_used) {
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

void MySQL_HostGroups_Manager::set_incoming_replication_hostgroups(SQLite3_result *s) {
	incoming_replication_hostgroups=s;
}

SQLite3_result * MySQL_HostGroups_Manager::SQL3_Connection_Pool() {
  const int colnum=12;
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
  result->add_column_definition(SQLITE_TEXT,"Latency_us");
	wrlock();
	int i,j, k;
	for (i=0; i<(int)MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
			MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
			if (mysrvc->status!=MYSQL_SERVER_STATUS_ONLINE) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d is not online\n", mysrvc->address, mysrvc->port);
				//__sync_fetch_and_sub(&status.server_connections_connected, mysrvc->ConnectionsFree->conns->len);
				mysrvc->ConnectionsFree->drop_all_connections();
			}
			// drop idle connections if beyond max_connection
			while (mysrvc->ConnectionsFree->conns->len && mysrvc->ConnectionsUsed->conns->len+mysrvc->ConnectionsFree->conns->len > mysrvc->max_connections) {
				MySQL_Connection *conn=(MySQL_Connection *)mysrvc->ConnectionsFree->conns->remove_index_fast(0);
				delete conn;
				//__sync_fetch_and_sub(&status.server_connections_connected, 1);
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
			sprintf(buf,"%llu", mysrvc->current_latency_us);
			pta[11]=strdup(buf);
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
	const char *Q1=(char *)"SELECT hostgroup_id FROM mysql_servers join mysql_replication_hostgroups ON hostgroup_id=writer_hostgroup WHERE hostname='%s' AND port=%d AND status=0";
	const char *Q2=(char *)"UPDATE OR IGNORE mysql_servers SET hostgroup_id=(SELECT writer_hostgroup FROM mysql_replication_hostgroups WHERE reader_hostgroup=mysql_servers.hostgroup_id) WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT reader_hostgroup FROM mysql_replication_hostgroups WHERE reader_hostgroup=mysql_servers.hostgroup_id)";
	const char *Q3A=(char *)"INSERT OR IGNORE INTO mysql_servers(hostgroup_id, hostname, port, status, weight, max_connections, max_replication_lag, use_ssl, max_latency_ms) SELECT reader_hostgroup, hostname, port, status, weight, max_connections, max_replication_lag, use_ssl, max_latency_ms FROM mysql_servers JOIN mysql_replication_hostgroups ON mysql_servers.hostgroup_id=mysql_replication_hostgroups.writer_hostgroup WHERE hostname='%s' AND port=%d";
	const char *Q3B=(char *)"DELETE FROM mysql_servers WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT reader_hostgroup FROM mysql_replication_hostgroups WHERE reader_hostgroup=mysql_servers.hostgroup_id)";
	const char *Q4=(char *)"UPDATE OR IGNORE mysql_servers SET hostgroup_id=(SELECT reader_hostgroup FROM mysql_replication_hostgroups WHERE writer_hostgroup=mysql_servers.hostgroup_id) WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT writer_hostgroup FROM mysql_replication_hostgroups WHERE writer_hostgroup=mysql_servers.hostgroup_id)";
	const char *Q5=(char *)"DELETE FROM mysql_servers WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT writer_hostgroup FROM mysql_replication_hostgroups WHERE writer_hostgroup=mysql_servers.hostgroup_id)";
	// define a buffer that will be used for all queries
	char *query=(char *)malloc(strlen(hostname)+strlen(Q3A)+32);
	sprintf(query,Q1,hostname,port);

	int cols=0;
	char *error=NULL;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	wrlock();
	mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	wrunlock();
	int num_rows=0;
	if (resultset) {
		num_rows=resultset->rows_count;
		delete resultset;
	}

	if (GloAdmin==NULL) {
		// quick exit
		free(query);
		return;
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
				GloAdmin->save_mysql_servers_runtime_to_database(false); // SAVE MYSQL SERVERS FROM RUNTIME
				sprintf(query,Q2,hostname,port);
				admindb->execute(query);
				if (mysql_thread___monitor_writer_is_also_reader) {
					sprintf(query,Q3A,hostname,port);
				} else {
					sprintf(query,Q3B,hostname,port);
				}
				admindb->execute(query);
				GloAdmin->load_mysql_servers_to_runtime(); // LOAD MYSQL SERVERS TO RUNTIME
				GloAdmin->mysql_servers_wrunlock();
			}
			break;
		case 1:
			if (num_rows) {
				// the server has read_only=1 , but we find it as writer, so we perform a swap
				GloAdmin->mysql_servers_wrlock();
				GloAdmin->save_mysql_servers_runtime_to_database(false); // SAVE MYSQL SERVERS FROM RUNTIME
				sprintf(query,Q4,hostname,port);
				admindb->execute(query);
				sprintf(query,Q5,hostname,port);
				admindb->execute(query);
				GloAdmin->load_mysql_servers_to_runtime(); // LOAD MYSQL SERVERS TO RUNTIME
				GloAdmin->mysql_servers_wrunlock();
			}
			break;
		default:
			assert(0);
			break;
	}

	free(query);
}


// shun_and_killall
// this function is called only from MySQL_Monitor::monitor_ping()
// it temporary disables a host that is not responding to pings, and mark the host in a way that when used the connection will be dropped
void MySQL_HostGroups_Manager::shun_and_killall(char *hostname, int port) {
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
					switch (mysrvc->status) {
						case MYSQL_SERVER_STATUS_SHUNNED:
							if (mysrvc->shunned_automatic==false) {
								break;
							}
						case MYSQL_SERVER_STATUS_ONLINE:
						case MYSQL_SERVER_STATUS_OFFLINE_SOFT:
							mysrvc->status=MYSQL_SERVER_STATUS_SHUNNED;
							mysrvc->shunned_automatic=true;
							mysrvc->shunned_and_kill_all_connections=true;
							mysrvc->ConnectionsFree->drop_all_connections();
							break;
						default:
							break;
					}
				}
			}
		}
	}
	wrunlock();
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
