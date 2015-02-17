#include "proxysql.h"
#include "cpp.h"

#define char_malloc (char *)malloc
#define itostr(__s, __i)  { __s=char_malloc(32); sprintf(__s, "%lld", __i); }


//#define MYHGM_MYSQL_SERVERS "CREATE TABLE mysql_servers ( hostgroup_id INT NOT NULL DEFAULT 0, hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306, weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , status INT CHECK (status IN (0, 1, 2, 3)) NOT NULL DEFAULT 0, PRIMARY KEY (hostgroup_id, hostname, port) )"






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

MySrvC::MySrvC(char *add, uint16_t p, unsigned int _weight, enum MySerStatus _status) {
	address=strdup(add);
	port=p;
	weight=_weight;
	status=_status;
	myhgc=NULL;
	ConnectionsUsed=new MySrvConnList(this);
	ConnectionsFree=new MySrvConnList(this);
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
bool MySQL_HostGroups_Manager::server_add(unsigned int hid, char *add, uint16_t p, unsigned int _weight, enum MySerStatus status) {
	bool ret;
	char *q=(char *)"INSERT INTO mysql_servers_incoming VALUES (%u, \"%s\", %u, %u, %u)";
	char *query=(char *)malloc(strlen(q)+strlen(add)+100);
	sprintf(query,q,hid,add,p,_weight,status);
	ret=mydb->execute(query);
	free(query);
	return ret;
}


bool MySQL_HostGroups_Manager::commit() {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
  char *query=NULL;
	wrlock();
	query=(char *)"SELECT mem_pointer FROM mysql_servers t1 LEFT OUTER JOIN mysql_servers_incoming t2 ON (t1.hostgroup_id=t2.hostgroup_id AND t1.hostname=t2.hostname AND t1.port=t2.port) WHERE t2.hostgroup_id IS NULL";
  mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			long long ptr=atoll(r->fields[0]);
			fprintf(stderr,"%lld\n", ptr);
		}
	}
	if (resultset) { delete resultset; resultset=NULL; }

	mydb->execute("INSERT OR IGNORE INTO mysql_servers(hostgroup_id, hostname, port, weight, status) SELECT hostgroup_id, hostname, port, weight, status FROM mysql_servers_incoming");	

	query=(char *)"SELECT t1.*, t2.weight, t2.status FROM mysql_servers t1 JOIN mysql_servers_incoming t2 ON (t1.hostgroup_id=t2.hostgroup_id AND t1.hostname=t2.hostname AND t1.port=t2.port) WHERE mem_pointer=0 OR t1.weight<>t2.weight OR t1.status<>t2.status";
  mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			long long ptr=atoll(r->fields[5]);
			fprintf(stderr,"%lld\n", ptr);
			if (ptr==0) {
				MySrvC *mysrvc=new MySrvC(r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), (MySerStatus) atoi(r->fields[4]));
				add(mysrvc,atoi(r->fields[0]));
			}
	
		}
	}
	if (resultset) { delete resultset; resultset=NULL; }

	mydb->execute("DELETE FROM mysql_servers_incoming");	


	wrunlock();
	return true;
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
	mysrvc=(MySrvC *)c->parent;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL_Connection %p, server %s:%d\n", c, mysrvc->address, mysrvc->port);
  mysrvc->ConnectionsUsed->remove(c);
	mysrvc->ConnectionsFree->add(c);
	wrunlock();
}



MySrvC *MyHGC::get_random_MySrvC() {
	MySrvC *mysrvc=NULL;
	unsigned int i;
	unsigned int l=mysrvs->cnt();
	if (l) {
		i=rand()%l;
		mysrvc=mysrvs->idx(i);
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC %p, server %s:%d\n", mysrvc, mysrvc->address, mysrvc->port);
		return mysrvc;
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
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
		return  conn;
	}
	return NULL; // never reach here
}

MySQL_Connection * MySQL_HostGroups_Manager::get_MyConn_from_pool(unsigned int _hid) {
	MySQL_Connection * conn=NULL;
	wrlock();
	MyHGC *myhgc=MyHGC_lookup(_hid);
	MySrvC *mysrvc=myhgc->get_random_MySrvC();
	if (mysrvc) { // a MySrvC exists. If not, we return NULL = no targets
		//conn=mysrvc->ConnectionsUsed->get_random_MyConn();
		//mysrvc->ConnectionsFree->add(conn);
		conn=mysrvc->ConnectionsFree->get_random_MyConn();
		mysrvc->ConnectionsUsed->add(conn);
	}
//	conn->parent=mysrvc;
	wrunlock();
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
	return conn;
}

void MySQL_HostGroups_Manager::destroy_MyConn_from_pool(MySQL_Connection *c) {
	wrlock();
	MySrvC *mysrvc=(MySrvC *)c->parent;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d\n", c, mysrvc->address, mysrvc->port);
	mysrvc->ConnectionsUsed->remove(c);
	delete c;
	wrunlock();
}



void MySQL_HostGroups_Manager::add(MySrvC *mysrvc, unsigned int _hid) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Adding MySrvC %p (%s:%d) for hostgroup %d\n", mysrvc, mysrvc->address, mysrvc->port, _hid);
	MyHGC *myhgc=MyHGC_lookup(_hid);
	myhgc->mysrvs->add(mysrvc);
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
			PtrArray *pa=mysrvc->ConnectionsFree->conns;
			for (k=0; k<(int)pa->len; k++) {
				MySQL_Connection *mc=(MySQL_Connection *)pa->index(k);
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
	wrunlock();
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning %d idle connections\n", num_conn_current);
	return num_conn_current;
}

