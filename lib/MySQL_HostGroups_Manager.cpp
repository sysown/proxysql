#include "proxysql.h"
#include "cpp.h"
#include "SpookyV2.h"

#define char_malloc (char *)malloc
#define itostr(__s, __i)  { __s=char_malloc(32); sprintf(__s, "%lld", __i); }

#include "thread.h"
#include "wqueue.h"

#define SAFE_SQLITE3_STEP(_stmt) do {\
  do {\
    rc=sqlite3_step(_stmt);\
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

static void * HGCU_thread_run() {
	PtrArray *conn_array=new PtrArray();
	while(1) {
		MySQL_Connection *myconn=(MySQL_Connection *)MyHGM->queue.remove();
		if (myconn==NULL) {
			// intentionally exit immediately
			return NULL;
		}
		conn_array->add(myconn);
		while (MyHGM->queue.size()) {
			myconn=(MySQL_Connection *)MyHGM->queue.remove();
			if (myconn==NULL) return NULL;
			conn_array->add(myconn);
		}
		unsigned int l=conn_array->len;
		int *errs=(int *)malloc(sizeof(int)*l);
		int *statuses=(int *)malloc(sizeof(int)*l);
		my_bool *ret=(my_bool *)malloc(sizeof(my_bool)*l);
		int i;
		for (i=0;i<(int)l;i++) {
			myconn=(MySQL_Connection *)conn_array->index(i);
			if (myconn->mysql->net.vio && myconn->mysql->net.fd && myconn->mysql->net.buff) {
				statuses[i]=mysql_change_user_start(&ret[i], myconn->mysql, myconn->userinfo->username, myconn->userinfo->password, myconn->userinfo->schemaname);
				if (myconn->mysql->net.vio==NULL || myconn->mysql->net.fd==0 || myconn->mysql->net.buff==NULL) {
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
		unsigned long long now=monotonic_time();
		while (conn_array->len && ((monotonic_time() - now) < 1000000)) {
			usleep(50);
			for (i=0;i<(int)conn_array->len;i++) {
				myconn=(MySQL_Connection *)conn_array->index(i);
				if (myconn->mysql->net.vio && myconn->mysql->net.fd && myconn->mysql->net.buff) {
					statuses[i]=wait_for_mysql(myconn->mysql, statuses[i]);
					if (myconn->mysql->net.vio && myconn->mysql->net.fd && myconn->mysql->net.buff) {
						if ((statuses[i] & MYSQL_WAIT_TIMEOUT) == 0) {
							statuses[i]=mysql_change_user_cont(&ret[i], myconn->mysql, statuses[i]);
							if (myconn->mysql->net.vio==NULL || myconn->mysql->net.fd==0 || myconn->mysql->net.buff==NULL ) {
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
	}
}


MySQL_Connection *MySrvConnList::index(unsigned int _k) {
	return (MySQL_Connection *)conns->index(_k);
}

MySQL_Connection * MySrvConnList::remove(int _k) {
	return (MySQL_Connection *)conns->remove_index_fast(_k);
}

unsigned int MySrvConnList::conns_length() {
	return conns->len;
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

void MySrvList::remove(MySrvC *s) {
	int i=find_idx(s);
	assert(i>=0);
	servers->remove_index_fast((unsigned int)i);
}

void MySrvConnList::drop_all_connections() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Dropping all connections (%lu total) on MySrvConnList %p for server %s:%d , hostgroup=%d , status=%d\n", conns_length(), this, mysrvc->address, mysrvc->port, mysrvc->myhgc->hid, mysrvc->status);
	while (conns_length()) {
		MySQL_Connection *conn=(MySQL_Connection *)conns->remove_index_fast(0);
		delete conn;
	}
}


MySrvC::MySrvC(char *add, uint16_t p, unsigned int _weight, enum MySerStatus _status, unsigned int _compression /*, uint8_t _charset */, unsigned int _max_connections, unsigned int _max_replication_lag, unsigned int _use_ssl, unsigned int _max_latency_ms, char *_comment) {
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
	comment=strdup(_comment);
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
		case 1203: // User %s already has more than 'max_user_connections' active connections
		case 1226: // User '%s' has exceeded the '%s' resource (current value: %ld)
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
			bool _shu=false;
			MyHGM->wrlock(); // to prevent race conditions, lock here. See #627
			if (status==MYSQL_SERVER_STATUS_ONLINE) {
				status=MYSQL_SERVER_STATUS_SHUNNED;
				shunned_automatic=true;
				_shu=true;
			} else {
				_shu=false;
			}
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

MySQL_HostGroups_Manager::MySQL_HostGroups_Manager() {
	status.client_connections=0;
	status.client_connections_aborted=0;
	status.client_connections_created=0;
	status.server_connections_connected=0;
	status.server_connections_aborted=0;
	status.server_connections_created=0;
	status.servers_table_version=0;
	pthread_mutex_init(&status.servers_table_version_lock, NULL);
	pthread_cond_init(&status.servers_table_version_cond, NULL);
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
	status.backend_change_user=0;
	status.backend_init_db=0;
	status.backend_set_names=0;
	status.frontend_init_db=0;
	status.frontend_set_names=0;
	status.frontend_use_db=0;
	pthread_mutex_init(&readonly_mutex, NULL);
	pthread_mutex_init(&Group_Replication_Info_mutex, NULL);
#ifdef MHM_PTHREAD_MUTEX
	pthread_mutex_init(&lock, NULL);
#else
	spinlock_rwlock_init(&rwlock);
#endif
	admindb=NULL;	// initialized only if needed
	mydb=new SQLite3DB();
#ifdef DEBUG
	mydb->open((char *)"file:mem_mydb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
#else
	mydb->open((char *)"file:mem_mydb?mode=memory", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
#endif /* DEBUG */
	mydb->execute(MYHGM_MYSQL_SERVERS);
	mydb->execute(MYHGM_MYSQL_SERVERS_INCOMING);
	mydb->execute(MYHGM_MYSQL_REPLICATION_HOSTGROUPS);
	mydb->execute(MYHGM_MYSQL_GROUP_REPLICATION_HOSTGROUPS);
	MyHostGroups=new PtrArray();
	incoming_replication_hostgroups=NULL;
	incoming_group_replication_hostgroups=NULL;
	HGCU_thread = new std::thread(&HGCU_thread_run);
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
	queue.add(NULL);
	HGCU_thread->join();
#ifdef MHM_PTHREAD_MUTEX
	pthread_mutex_destroy(&lock);
#endif
}

// wrlock() is only required during commit()
void MySQL_HostGroups_Manager::wrlock() {
#ifdef MHM_PTHREAD_MUTEX
	pthread_mutex_lock(&lock);
#else
	spin_wrlock(&rwlock);
#endif
}

void MySQL_HostGroups_Manager::wrunlock() {
#ifdef MHM_PTHREAD_MUTEX
	pthread_mutex_unlock(&lock);
#else
	spin_wrunlock(&rwlock);
#endif
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

// add a new row in mysql_servers_incoming
// we always assume that the calling thread has acquired a rdlock()
bool MySQL_HostGroups_Manager::server_add(unsigned int hid, char *add, uint16_t p, unsigned int _weight, enum MySerStatus status, unsigned int _comp /*, uint8_t _charset */, unsigned int _max_connections, unsigned int _max_replication_lag, unsigned int _use_ssl, unsigned int _max_latency_ms , char *comment) {
	bool ret=true;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Adding in mysql_servers_incoming server %s:%d in hostgroup %u with weight %u , status %u, %s compression, max_connections %d, max_replication_lag %u, use_ssl=%u, max_latency_ms=%u\n", add,p,hid,_weight,status, (_comp ? "with" : "without") /*, _charset */ , _max_connections, _max_replication_lag, _use_ssl, _max_latency_ms);
	int rc;
	sqlite3_stmt *statement=NULL;
	sqlite3 *mydb3=mydb->get_db();
	char *query=(char *)"INSERT INTO mysql_servers_incoming VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
	rc=sqlite3_prepare_v2(mydb3, query, -1, &statement, 0);
	assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 1, hid); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement, 2, add, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 3, p); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 4, _weight); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 5, status); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 6, _comp); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 7, _max_connections); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 8, _max_replication_lag); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 9, _use_ssl); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 10, _max_latency_ms); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement, 11, comment, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);

	SAFE_SQLITE3_STEP(statement);
	rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
	rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
	sqlite3_finalize(statement);

	return ret;
}

int MySQL_HostGroups_Manager::servers_add(SQLite3_result *resultset) {
	if (resultset==NULL) {
		return 0;
	}
	int rc;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	sqlite3 *mydb3=mydb->get_db();
	char *query1=(char *)"INSERT INTO mysql_servers_incoming VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
	char *query32=(char *)"INSERT INTO mysql_servers_incoming VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11), (?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22), (?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33), (?34, ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44), (?45, ?46, ?47, ?48, ?49, ?50, ?51, ?52, ?53, ?54, ?55),(?56, ?57, ?58, ?59, ?60, ?61, ?62, ?63, ?64, ?65, ?66),(?67, ?68, ?69, ?70, ?71, ?72, ?73, ?74, ?75, ?76, ?77),(?78, ?79, ?80, ?81, ?82, ?83, ?84, ?85, ?86, ?87, ?88),(?89, ?90, ?91, ?92, ?93, ?94, ?95, ?96, ?97, ?98, ?99), (?100, ?101, ?102, ?103, ?104, ?105, ?106, ?107, ?108, ?109, ?110), (?111, ?112, ?113, ?114, ?115, ?116, ?117, ?118, ?119, ?120, ?121), (?122, ?123, ?124, ?125, ?126, ?127, ?128, ?129, ?130, ?131, ?132), (?133, ?134, ?135, ?136, ?137, ?138, ?139, ?140, ?141, ?142, ?143), (?144, ?145, ?146, ?147, ?148, ?149, ?150, ?151, ?152, ?153, ?154), (?155, ?156, ?157, ?158, ?159, ?160, ?161, ?162, ?163, ?164, ?165), (?166, ?167, ?168, ?169, ?170, ?171, ?172, ?173, ?174, ?175, ?176), (?177, ?178, ?179, ?180, ?181, ?182, ?183, ?184, ?185, ?186, ?187), (?188, ?189, ?190, ?191, ?192, ?193, ?194, ?195, ?196, ?197, ?198), (?199, ?200, ?201, ?202, ?203, ?204, ?205, ?206, ?207, ?208, ?209), (?210, ?211, ?212, ?213, ?214, ?215, ?216, ?217, ?218, ?219, ?220), (?221, ?222, ?223, ?224, ?225, ?226, ?227, ?228, ?229, ?230, ?231), (?232, ?233, ?234, ?235, ?236, ?237, ?238, ?239, ?240, ?241, ?242), (?243, ?244, ?245, ?246, ?247, ?248, ?249, ?250, ?251, ?252, ?253), (?254, ?255, ?256, ?257, ?258, ?259, ?260, ?261, ?262, ?263, ?264), (?265, ?266, ?267, ?268, ?269, ?270, ?271, ?272, ?273, ?274, ?275), (?276, ?277, ?278, ?279, ?280, ?281, ?282, ?283, ?284, ?285, ?286), (?287, ?288, ?289, ?290, ?291, ?292, ?293, ?294, ?295, ?296, ?297), (?298, ?299, ?300, ?301, ?302, ?303, ?304, ?305, ?306, ?307, ?308), (?309, ?310, ?311, ?312, ?313, ?314, ?315, ?316, ?317, ?318, ?319), (?320, ?321, ?322, ?323, ?324, ?325, ?326, ?327, ?328, ?329, ?330), (?331, ?332, ?333, ?334, ?335, ?336, ?337, ?338, ?339, ?340, ?341), (?342, ?343, ?344, ?345, ?346, ?347, ?348, ?349, ?350, ?351, ?352)";
	rc=sqlite3_prepare_v2(mydb3, query1, -1, &statement1, 0);
	assert(rc==SQLITE_OK);
	rc=sqlite3_prepare_v2(mydb3, query32, -1, &statement32, 0);
	assert(rc==SQLITE_OK);
	MySerStatus status1=MYSQL_SERVER_STATUS_ONLINE;
	int row_idx=0;
	int max_bulk_row_idx=resultset->rows_count/32;
	max_bulk_row_idx=max_bulk_row_idx*32;
	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r1=*it;
		status1=MYSQL_SERVER_STATUS_ONLINE;
		if (strcasecmp(r1->fields[3],"ONLINE")) {
			if (!strcasecmp(r1->fields[3],"SHUNNED")) {
				status1=MYSQL_SERVER_STATUS_SHUNNED;
			} else {
				if (!strcasecmp(r1->fields[3],"OFFLINE_SOFT")) {
					status1=MYSQL_SERVER_STATUS_OFFLINE_SOFT;
				} else {
					if (!strcasecmp(r1->fields[3],"OFFLINE_HARD")) {
						status1=MYSQL_SERVER_STATUS_OFFLINE_HARD;
					}
				}
			}
		}
		int idx=row_idx%32;
		if (row_idx<max_bulk_row_idx) { // bulk
			rc=sqlite3_bind_int64(statement32, (idx*11)+1, atoi(r1->fields[0])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement32, (idx*11)+2, r1->fields[1], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement32, (idx*11)+3, atoi(r1->fields[2])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement32, (idx*11)+4, atoi(r1->fields[4])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement32, (idx*11)+5, status1); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement32, (idx*11)+6, atoi(r1->fields[5])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement32, (idx*11)+7, atoi(r1->fields[6])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement32, (idx*11)+8, atoi(r1->fields[7])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement32, (idx*11)+9, atoi(r1->fields[8])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement32, (idx*11)+10, atoi(r1->fields[9])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement32, (idx*11)+11, r1->fields[10], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			if (idx==31) {
				SAFE_SQLITE3_STEP(statement32);
				rc=sqlite3_clear_bindings(statement32); assert(rc==SQLITE_OK);
				rc=sqlite3_reset(statement32); assert(rc==SQLITE_OK);
			}
		} else { // single row
			rc=sqlite3_bind_int64(statement1, 1, atoi(r1->fields[0])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 3, atoi(r1->fields[2])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 4, atoi(r1->fields[4])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 5, status1); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 6, atoi(r1->fields[5])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 7, atoi(r1->fields[6])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 8, atoi(r1->fields[7])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 9, atoi(r1->fields[8])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement1, 10, atoi(r1->fields[9])); assert(rc==SQLITE_OK);
			rc=sqlite3_bind_text(statement1, 11, r1->fields[10], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
			SAFE_SQLITE3_STEP(statement1);
			rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
			rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
		}
		row_idx++;
	}
	sqlite3_finalize(statement1);
	sqlite3_finalize(statement32);
	return 0;
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
  char *query=NULL;
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

// INSERT OR IGNORE INTO mysql_servers SELECT ... FROM mysql_servers_incoming
//	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "INSERT OR IGNORE INTO mysql_servers(hostgroup_id, hostname, port, weight, status, compression, max_connections) SELECT hostgroup_id, hostname, port, weight, status, compression, max_connections FROM mysql_servers_incoming\n");
	mydb->execute("INSERT OR IGNORE INTO mysql_servers(hostgroup_id, hostname, port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) SELECT hostgroup_id, hostname, port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers_incoming");


	// SELECT FROM mysql_servers whatever is not identical in mysql_servers_incoming, or where mem_pointer=0 (where there is no pointer yet)
	query=(char *)"SELECT t1.*, t2.weight, t2.status, t2.compression, t2.max_connections, t2.max_replication_lag, t2.use_ssl, t2.max_latency_ms, t2.comment FROM mysql_servers t1 JOIN mysql_servers_incoming t2 ON (t1.hostgroup_id=t2.hostgroup_id AND t1.hostname=t2.hostname AND t1.port=t2.port) WHERE mem_pointer=0 OR t1.weight<>t2.weight OR t1.status<>t2.status OR t1.compression<>t2.compression OR t1.max_connections<>t2.max_connections OR t1.max_replication_lag<>t2.max_replication_lag OR t1.use_ssl<>t2.use_ssl OR t1.max_latency_ms<>t2.max_latency_ms or t1.comment<>t2.comment";
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
  mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {

		// optimization #829
		int rc;
		sqlite3_stmt *statement1=NULL;
		sqlite3_stmt *statement2=NULL;
		sqlite3 *mydb3=mydb->get_db();
		char *query1=(char *)"UPDATE mysql_servers SET mem_pointer = ?1 WHERE hostgroup_id = ?2 AND hostname = ?3 AND port = ?4";
		rc=sqlite3_prepare_v2(mydb3, query1, -1, &statement1, 0);
		assert(rc==SQLITE_OK);
		char *query2=(char *)"UPDATE mysql_servers SET weight = ?1 , status = ?2 , compression = ?3 , max_connections = ?4 , max_replication_lag = ?5 , use_ssl = ?6 , max_latency_ms = ?7 , comment = ?8 WHERE hostgroup_id = ?9 AND hostname = ?10 AND port = ?11";
		rc=sqlite3_prepare_v2(mydb3, query2, -1, &statement2, 0);
		assert(rc==SQLITE_OK);

		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			long long ptr=atoll(r->fields[11]); // increase this index every time a new column is added
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d , weight=%d, status=%d, mem_pointer=%llu, hostgroup=%d, compression=%d\n", r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), (MySerStatus) atoi(r->fields[4]), ptr, atoi(r->fields[0]), atoi(r->fields[5]));
			//fprintf(stderr,"%lld\n", ptr);
			if (ptr==0) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Creating new server %s:%d , weight=%d, status=%d, compression=%d\n", r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), (MySerStatus) atoi(r->fields[4]), atoi(r->fields[5]) );
				MySrvC *mysrvc=new MySrvC(r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), (MySerStatus) atoi(r->fields[4]), atoi(r->fields[5]), atoi(r->fields[6]), atoi(r->fields[7]), atoi(r->fields[8]), atoi(r->fields[9]), r->fields[10]); // add new fields here if adding more columns in mysql_servers
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Adding new server %s:%d , weight=%d, status=%d, mem_ptr=%p into hostgroup=%d\n", r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), (MySerStatus) atoi(r->fields[4]), mysrvc, atoi(r->fields[0]));
				add(mysrvc,atoi(r->fields[0]));
				ptr=(uintptr_t)mysrvc;
				rc=sqlite3_bind_int64(statement1, 1, ptr); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 2, atoi(r->fields[0])); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 3,  r->fields[1], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 4, atoi(r->fields[2])); assert(rc==SQLITE_OK);
				SAFE_SQLITE3_STEP(statement1);
				rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
				rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
			} else {
				bool run_update=false;
				MySrvC *mysrvc=(MySrvC *)ptr;
				// carefully increase the 2nd index by 1 for every new column added
				if (atoi(r->fields[3])!=atoi(r->fields[12])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing weight for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[3] , mysrvc->weight , atoi(r->fields[12]));
					mysrvc->weight=atoi(r->fields[12]);
				}
				if (atoi(r->fields[4])!=atoi(r->fields[13])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing status for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[4] , mysrvc->status , atoi(r->fields[13]));
					mysrvc->status=(MySerStatus)atoi(r->fields[13]);
					if (mysrvc->status==MYSQL_SERVER_STATUS_SHUNNED) {
						mysrvc->shunned_automatic=false;
					}
				}
				if (atoi(r->fields[5])!=atoi(r->fields[14])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing compression for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[5] , mysrvc->compression , atoi(r->fields[14]));
					mysrvc->compression=atoi(r->fields[14]);
				}
				if (atoi(r->fields[6])!=atoi(r->fields[15])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing max_connections for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[6] , mysrvc->max_connections , atoi(r->fields[15]));
					mysrvc->max_connections=atoi(r->fields[15]);
				}
				if (atoi(r->fields[7])!=atoi(r->fields[16])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing max_replication_lag for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[7] , mysrvc->max_replication_lag , atoi(r->fields[16]));
					mysrvc->max_replication_lag=atoi(r->fields[16]);
				}
				if (atoi(r->fields[8])!=atoi(r->fields[17])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing use_ssl for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[8] , mysrvc->use_ssl , atoi(r->fields[17]));
					mysrvc->use_ssl=atoi(r->fields[17]);
				}
				if (atoi(r->fields[9])!=atoi(r->fields[18])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing max_latency_ms for server %s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[9] , mysrvc->max_latency_us , atoi(r->fields[18]));
					mysrvc->max_latency_us=1000*atoi(r->fields[18]);
				}
				if (strcmp(r->fields[10],r->fields[19])) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing comment for server %s:%d (%s:%d) from '%s' to '%s'\n" , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), r->fields[10], r->fields[19]);
					free(mysrvc->comment);
					mysrvc->comment=strdup(r->fields[19]);
				}
				if (run_update) {
					rc=sqlite3_bind_int64(statement2, 1, mysrvc->weight); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement2, 2, mysrvc->status); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement2, 3, mysrvc->compression); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement2, 4, mysrvc->max_connections); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement2, 5, mysrvc->max_replication_lag); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement2, 6, mysrvc->use_ssl); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement2, 7, mysrvc->max_latency_us/1000); assert(rc==SQLITE_OK);

					rc=sqlite3_bind_text(statement2, 8,  mysrvc->comment, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement2, 9, mysrvc->myhgc->hid); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_text(statement2, 10,  mysrvc->address, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement2, 11, mysrvc->port); assert(rc==SQLITE_OK);
					SAFE_SQLITE3_STEP(statement2);
					rc=sqlite3_clear_bindings(statement2); assert(rc==SQLITE_OK);
					rc=sqlite3_reset(statement2); assert(rc==SQLITE_OK);
				}
			}
		}
		sqlite3_finalize(statement1);
		sqlite3_finalize(statement2);
	}
	if (resultset) { delete resultset; resultset=NULL; }
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_servers_incoming\n");
	mydb->execute("DELETE FROM mysql_servers_incoming");	

	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_replication_hostgroups\n");
	mydb->execute("DELETE FROM mysql_replication_hostgroups");

	generate_mysql_replication_hostgroups_table();


	// group replication
	if (incoming_group_replication_hostgroups) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM mysql_group_replication_hostgroups\n");
		mydb->execute("DELETE FROM mysql_group_replication_hostgroups");
		generate_mysql_group_replication_hostgroups_table();
	}


	if ( GloAdmin && GloAdmin->checksum_variables.checksum_mysql_servers ) {
		uint64_t hash1=0, hash2=0;
		SpookyHash myhash;
		char buf[80];
		bool init = false;
/* removing all this code, because we need them ordered
		MySrvC *mysrvc=NULL;
		for (unsigned int i=0; i<MyHostGroups->len; i++) {
			MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
			for (unsigned int j=0; j<myhgc->mysrvs->servers->len; j++) {
				if (init == false) {
					init = true;
					myhash.Init(19,3);
				}
				mysrvc=myhgc->mysrvs->idx(j);
				// hostgroup
				sprintf(buf,"%u",mysrvc->myhgc->hid);
				myhash.Update(buf,strlen(buf));
				// hoatname
				if (mysrvc->address) {
					myhash.Update(mysrvc->address,strlen(mysrvc->address));
				} else { myhash.Update("",0); }
				// port
				sprintf(buf,"%u",mysrvc->port);
				myhash.Update(buf,strlen(buf));
				// status
				sprintf(buf,"%u",mysrvc->status);
				myhash.Update(buf,strlen(buf));
				// weight
				sprintf(buf,"%u",mysrvc->weight);
				myhash.Update(buf,strlen(buf));
				// compression
				sprintf(buf,"%u",mysrvc->compression);
				myhash.Update(buf,strlen(buf));
				// max_connections
				sprintf(buf,"%u",mysrvc->max_connections);
				myhash.Update(buf,strlen(buf));
				// max_replication_lag
				sprintf(buf,"%u",mysrvc->max_replication_lag);
				myhash.Update(buf,strlen(buf));
				// use_ssl
				sprintf(buf,"%u",mysrvc->use_ssl);
				myhash.Update(buf,strlen(buf));
				// max_latency_ms
				sprintf(buf,"%u",mysrvc->max_latency_us);
				myhash.Update(buf,strlen(buf));
				if (mysrvc->comment) {
					myhash.Update(mysrvc->comment,strlen(mysrvc->comment));
				} else { myhash.Update("",0); }
			}
		}
*/
		{
			mydb->execute("DELETE FROM mysql_servers");
			generate_mysql_servers_table();
			char *error=NULL;
			int cols=0;
			int affected_rows=0;
			SQLite3_result *resultset=NULL;
			char *query=(char *)"SELECT hostgroup_id, hostname, port, CASE status WHEN 0 OR 1 OR 4 THEN 0 ELSE status END status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers WHERE status<>3 ORDER BY hostgroup_id, hostname, port";
			mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
			if (resultset) {
				if (resultset->rows_count) {
					if (init == false) {
						init = true;
						myhash.Init(19,3);
					}
					uint64_t hash1_ = resultset->raw_checksum();
					myhash.Update(&hash1_, sizeof(hash1_));
				}
				delete resultset;
			}
		}
		{
			char *error=NULL;
			int cols=0;
			int affected_rows=0;
			SQLite3_result *resultset=NULL;
			char *query=(char *)"SELECT * FROM mysql_replication_hostgroups ORDER BY writer_hostgroup";
			mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
			if (resultset) {
				if (resultset->rows_count) {
					if (init == false) {
						init = true;
						myhash.Init(19,3);
					}
					uint64_t hash1_ = resultset->raw_checksum();
					myhash.Update(&hash1_, sizeof(hash1_));
				}
				delete resultset;
			}
		}
		{
			char *error=NULL;
			int cols=0;
			int affected_rows=0;
			SQLite3_result *resultset=NULL;
			char *query=(char *)"SELECT * FROM mysql_group_replication_hostgroups ORDER BY writer_hostgroup";
			mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
			if (resultset) {
				if (resultset->rows_count) {
					if (init == false) {
						init = true;
						myhash.Init(19,3);
					}
					uint64_t hash1_ = resultset->raw_checksum();
					myhash.Update(&hash1_, sizeof(hash1_));
				}
				delete resultset;
			}
		}
		if (init == true) {
			myhash.Final(&hash1, &hash2);
		}
		uint32_t d32[2];
		memcpy(&d32,&hash1,sizeof(hash1));
		sprintf(buf,"0x%0X%0X", d32[0], d32[1]);
		pthread_mutex_lock(&GloVars.checksum_mutex);
		GloVars.checksums_values.mysql_servers.set_checksum(buf);
		GloVars.checksums_values.mysql_servers.version++;
		//struct timespec ts;
		//clock_gettime(CLOCK_REALTIME, &ts);
		time_t t = time(NULL);
		GloVars.checksums_values.mysql_servers.epoch = t;
		GloVars.checksums_values.updates_cnt++;
		GloVars.generate_global_checksum();
		GloVars.epoch_version = t;
		pthread_mutex_unlock(&GloVars.checksum_mutex);
	}

	__sync_fetch_and_add(&status.servers_table_version,1);
	pthread_cond_broadcast(&status.servers_table_version_cond);
	pthread_mutex_unlock(&status.servers_table_version_lock);
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
				if (mysrvc->ConnectionsUsed->conns_length()==0 && mysrvc->ConnectionsFree->conns_length()==0) {
					// no more connections for OFFLINE_HARD server, removing it
					mysrvc=(MySrvC *)myhgc->mysrvs->servers->remove_index_fast(j);
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
	sqlite3 *mydb3=mydb->get_db();
	char *query1=(char *)"INSERT INTO mysql_servers VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
	rc=sqlite3_prepare_v2(mydb3, query1, -1, &statement1, 0);
	assert(rc==SQLITE_OK);
	char *query32=(char *)"INSERT INTO mysql_servers VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12), (?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24), (?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36), (?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44, ?45, ?46, ?47, ?48), (?49, ?50, ?51, ?52, ?53, ?54, ?55, ?56, ?57, ?58, ?59, ?60), (?61, ?62, ?63, ?64, ?65, ?66, ?67, ?68, ?69, ?70, ?71, ?72), (?73, ?74, ?75, ?76, ?77, ?78, ?79, ?80, ?81, ?82, ?83, ?84), (?85, ?86, ?87, ?88, ?89, ?90, ?91, ?92, ?93, ?94, ?95, ?96), (?97, ?98, ?99, ?100, ?101, ?102, ?103, ?104, ?105, ?106, ?107, ?108), (?109, ?110, ?111, ?112, ?113, ?114, ?115, ?116, ?117, ?118, ?119, ?120), (?121, ?122, ?123, ?124, ?125, ?126, ?127, ?128, ?129, ?130, ?131, ?132), (?133, ?134, ?135, ?136, ?137, ?138, ?139, ?140, ?141, ?142, ?143, ?144), (?145, ?146, ?147, ?148, ?149, ?150, ?151, ?152, ?153, ?154, ?155, ?156), (?157, ?158, ?159, ?160, ?161, ?162, ?163, ?164, ?165, ?166, ?167, ?168), (?169, ?170, ?171, ?172, ?173, ?174, ?175, ?176, ?177, ?178, ?179, ?180), (?181, ?182, ?183, ?184, ?185, ?186, ?187, ?188, ?189, ?190, ?191, ?192), (?193, ?194, ?195, ?196, ?197, ?198, ?199, ?200, ?201, ?202, ?203, ?204), (?205, ?206, ?207, ?208, ?209, ?210, ?211, ?212, ?213, ?214, ?215, ?216), (?217, ?218, ?219, ?220, ?221, ?222, ?223, ?224, ?225, ?226, ?227, ?228), (?229, ?230, ?231, ?232, ?233, ?234, ?235, ?236, ?237, ?238, ?239, ?240), (?241, ?242, ?243, ?244, ?245, ?246, ?247, ?248, ?249, ?250, ?251, ?252), (?253, ?254, ?255, ?256, ?257, ?258, ?259, ?260, ?261, ?262, ?263, ?264), (?265, ?266, ?267, ?268, ?269, ?270, ?271, ?272, ?273, ?274, ?275, ?276), (?277, ?278, ?279, ?280, ?281, ?282, ?283, ?284, ?285, ?286, ?287, ?288), (?289, ?290, ?291, ?292, ?293, ?294, ?295, ?296, ?297, ?298, ?299, ?300), (?301, ?302, ?303, ?304, ?305, ?306, ?307, ?308, ?309, ?310, ?311, ?312), (?313, ?314, ?315, ?316, ?317, ?318, ?319, ?320, ?321, ?322, ?323, ?324), (?325, ?326, ?327, ?328, ?329, ?330, ?331, ?332, ?333, ?334, ?335, ?336), (?337, ?338, ?339, ?340, ?341, ?342, ?343, ?344, ?345, ?346, ?347, ?348), (?349, ?350, ?351, ?352, ?353, ?354, ?355, ?356, ?357, ?358, ?359, ?360), (?361, ?362, ?363, ?364, ?365, ?366, ?367, ?368, ?369, ?370, ?371, ?372), (?373, ?374, ?375, ?376, ?377, ?378, ?379, ?380, ?381, ?382, ?383, ?384)";
	rc=sqlite3_prepare_v2(mydb3, query32, -1, &statement32, 0);
	assert(rc==SQLITE_OK);

	if (GloMTH->variables.hostgroup_manager_verbose) {
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
			if (GloMTH->variables.hostgroup_manager_verbose) {
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
					case 4:
						st=(char *)"SHUNNED";
						break;
				}
				fprintf(stderr,"HID: %d , address: %s , port: %d , weight: %d , status: %s , max_connections: %u , max_replication_lag: %u , use_ssl: %u , max_latency_ms: %u , comment: %s\n", mysrvc->myhgc->hid, mysrvc->address, mysrvc->port, mysrvc->weight, st, mysrvc->max_connections, mysrvc->max_replication_lag, mysrvc->use_ssl, mysrvc->max_latency_us*1000, mysrvc->comment);
			}
			lst->add(mysrvc);
			if (lst->len==32) {
				while (lst->len) {
					int i=lst->len;
					i--;
					MySrvC *mysrvc=(MySrvC *)lst->remove_index_fast(0);
					uintptr_t ptr=(uintptr_t)mysrvc;
					rc=sqlite3_bind_int64(statement32, (i*12)+1, mysrvc->myhgc->hid); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_text(statement32, (i*12)+2, mysrvc->address, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement32, (i*12)+3, mysrvc->port); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement32, (i*12)+4, mysrvc->weight); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement32, (i*12)+5, mysrvc->status); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement32, (i*12)+6, mysrvc->compression); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement32, (i*12)+7, mysrvc->max_connections); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement32, (i*12)+8, mysrvc->max_replication_lag); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement32, (i*12)+9, mysrvc->use_ssl); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement32, (i*12)+10, mysrvc->max_latency_us/1000); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_text(statement32, (i*12)+11, mysrvc->comment, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement32, (i*12)+12, ptr); assert(rc==SQLITE_OK);
				}
				SAFE_SQLITE3_STEP(statement32);
				rc=sqlite3_clear_bindings(statement32); assert(rc==SQLITE_OK);
				rc=sqlite3_reset(statement32); assert(rc==SQLITE_OK);
			}
		}
	}
	while (lst->len) {
		MySrvC *mysrvc=(MySrvC *)lst->remove_index_fast(0);
		uintptr_t ptr=(uintptr_t)mysrvc;
		rc=sqlite3_bind_int64(statement1, 1, mysrvc->myhgc->hid); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_text(statement1, 2, mysrvc->address, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement1, 3, mysrvc->port); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement1, 4, mysrvc->weight); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement1, 5, mysrvc->status); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement1, 6, mysrvc->compression); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement1, 7, mysrvc->max_connections); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement1, 8, mysrvc->max_replication_lag); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement1, 9, mysrvc->use_ssl); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement1, 10, mysrvc->max_latency_us/1000); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_text(statement1, 11, mysrvc->comment, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement1, 12, ptr); assert(rc==SQLITE_OK);

		SAFE_SQLITE3_STEP(statement1);
		rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
		rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
	}
	sqlite3_finalize(statement1);
	sqlite3_finalize(statement32);
}

void MySQL_HostGroups_Manager::generate_mysql_replication_hostgroups_table() {
	if (incoming_replication_hostgroups==NULL)
		return;
	proxy_info("New mysql_replication_hostgroups table\n");
	for (std::vector<SQLite3_row *>::iterator it = incoming_replication_hostgroups->rows.begin() ; it != incoming_replication_hostgroups->rows.end(); ++it) {
		SQLite3_row *r=*it;
		char *o=NULL;
		int comment_length=0;	// #issue #643
		if (r->fields[2]) { // comment is not null
			o=escape_string_single_quotes(r->fields[2],false);
			comment_length=strlen(o);
		}
		char *query=(char *)malloc(256+comment_length);
		if (r->fields[2]) { // comment is not null
			sprintf(query,"INSERT INTO mysql_replication_hostgroups VALUES(%s,%s,'%s')",r->fields[0], r->fields[1], o);
			if (o!=r->fields[2]) { // there was a copy
				free(o);
			}
		} else {
			sprintf(query,"INSERT INTO mysql_replication_hostgroups VALUES(%s,%s,NULL)",r->fields[0],r->fields[1]);
		}
		mydb->execute(query);
		fprintf(stderr,"writer_hostgroup: %s , reader_hostgroup: %s, %s\n", r->fields[0],r->fields[1], r->fields[2]);
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
	sqlite3 *mydb3=mydb->get_db();
	char *query=(char *)"INSERT INTO mysql_group_replication_hostgroups(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
	rc=sqlite3_prepare_v2(mydb3, query, -1, &statement, 0);
	assert(rc==SQLITE_OK);
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
		rc=sqlite3_bind_int64(statement, 1, writer_hostgroup); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement, 2, backup_writer_hostgroup); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement, 3, reader_hostgroup); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement, 4, offline_hostgroup); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement, 5, active); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement, 6, max_writers); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement, 7, writer_is_also_reader); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement, 8, max_transactions_behind); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_text(statement, 9, r->fields[8], -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);

		SAFE_SQLITE3_STEP(statement);
		rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
		rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
		std::map<int , Group_Replication_Info *>::iterator it2;
		it2 = Group_Replication_Info_Map.find(writer_hostgroup);
		Group_Replication_Info *info=NULL;
		if (it2!=Group_Replication_Info_Map.end()) {
			info=it2->second;
			bool changed=false;
			changed=info->update(backup_writer_hostgroup,reader_hostgroup,offline_hostgroup, max_writers, max_transactions_behind,  (bool)active, (bool)writer_is_also_reader, r->fields[8]);
			if (changed) {
				//info->need_converge=true;
			}
		} else {
			info=new Group_Replication_Info(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup, max_writers, max_transactions_behind,  (bool)active, (bool)writer_is_also_reader, r->fields[8]);
			//info->need_converge=true;
			Group_Replication_Info_Map.insert(Group_Replication_Info_Map.begin(), std::pair<int, Group_Replication_Info *>(writer_hostgroup,info));
		}
	}
	sqlite3_finalize(statement);
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
	pthread_mutex_lock(&GloMyMon->group_replication_mutex);
	{
		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		char *query=(char *)"SELECT writer_hostgroup, hostname, port, MAX(use_ssl) use_ssl , writer_is_also_reader , max_transactions_behind FROM mysql_servers JOIN mysql_group_replication_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=backup_writer_hostgroup OR hostgroup_id=reader_hostgroup OR hostgroup_id=offline_hostgroup WHERE status NOT IN (2,3) GROUP BY hostname, port";
		mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		if (resultset) {
			if (GloMyMon->Group_Replication_Hosts_resultset) {
				delete GloMyMon->Group_Replication_Hosts_resultset;
			}
			GloMyMon->Group_Replication_Hosts_resultset=resultset;
		}
	}
	pthread_mutex_unlock(&GloMyMon->group_replication_mutex);

	pthread_mutex_unlock(&Group_Replication_Info_mutex);
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
	char *query=(char *)"SELECT hostgroup_id, hostname, port, weight, CASE status WHEN 0 THEN \"ONLINE\" WHEN 1 THEN \"SHUNNED\" WHEN 2 THEN \"OFFLINE_SOFT\" WHEN 3 THEN \"OFFLINE_HARD\" WHEN 4 THEN \"SHUNNED\" END, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers";
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
	char *query=(char *)"SELECT writer_hostgroup, reader_hostgroup, comment FROM mysql_replication_hostgroups";
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
	mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	wrunlock();
	return resultset;
}

SQLite3_result * MySQL_HostGroups_Manager::dump_table_mysql_group_replication_hostgroups() {
	wrlock();
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment FROM mysql_group_replication_hostgroups";
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

void MySQL_HostGroups_Manager::push_MyConn_to_pool(MySQL_Connection *c, bool _lock) {
	assert(c->parent);
	MySrvC *mysrvc=NULL;
	if (_lock)
		wrlock();
	status.myconnpoll_push++;
	mysrvc=(MySrvC *)c->parent;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL_Connection %p, server %s:%d with status %d\n", c, mysrvc->address, mysrvc->port, mysrvc->status);
	mysrvc->ConnectionsUsed->remove(c);
	if (c->largest_query_length > (unsigned int)GloMTH->variables.threshold_query_length) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d with status %d . largest_query_length = %lu\n", c, mysrvc->address, mysrvc->port, mysrvc->status, c->largest_query_length);
		delete c;
		goto __exit_push_MyConn_to_pool;
	}
	if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) {
		if (c->async_state_machine==ASYNC_IDLE) {
#ifndef PROXYSQL_STMT_V14
			if (c->local_stmts->get_num_entries() > (unsigned int)GloMTH->variables.max_stmts_per_connection) {
#else
			if (c->local_stmts->get_num_backend_stmts() > (unsigned int)GloMTH->variables.max_stmts_per_connection) {
#endif
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d with status %d because has too many prepared statements\n", c, mysrvc->address, mysrvc->port, mysrvc->status);
				delete c;
			} else {
				c->optimize();
				mysrvc->ConnectionsFree->add(c);
			}
		} else {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d with status %d\n", c, mysrvc->address, mysrvc->port, mysrvc->status);
			delete c;
		}
	} else {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d with status %d\n", c, mysrvc->address, mysrvc->port, mysrvc->status);
		delete c;
	}
__exit_push_MyConn_to_pool:
	if (_lock)
		wrunlock();
}

void MySQL_HostGroups_Manager::push_MyConn_to_pool_array(MySQL_Connection **ca) {
	unsigned int i=0;
	MySQL_Connection *c=NULL;
	c=ca[i];
	wrlock();
	while (c) {
		push_MyConn_to_pool(c,false);
		i++;
		c=ca[i];
	}
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
				if (mysrvc->ConnectionsUsed->conns_length() < mysrvc->max_connections) { // consider this server only if didn't reach max_connections
					if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : mysql_thread___default_max_latency_ms*1000 ) ) { // consider the host only if not too far
						sum+=mysrvc->weight;
						TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
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
								(mysrvc->shunned_and_kill_all_connections==true && mysrvc->ConnectionsUsed->conns_length()==0 && mysrvc->ConnectionsFree->conns_length()==0) // if shunned_and_kill_all_connections is set, ensure all connections are already dropped
							) {
								mysrvc->status=MYSQL_SERVER_STATUS_ONLINE;
								mysrvc->shunned_automatic=false;
								mysrvc->shunned_and_kill_all_connections=false;
								mysrvc->connect_ERR_at_time_last_detected_error=0;
								mysrvc->time_last_detected_error=0;
								// if a server is taken back online, consider it immediately
								if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : mysql_thread___default_max_latency_ms*1000 ) ) { // consider the host only if not too far
									sum+=mysrvc->weight;
									TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
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
			for (j=0; j<l; j++) {
				mysrvc=mysrvs->idx(j);
				if (mysrvc->status==MYSQL_SERVER_STATUS_SHUNNED && mysrvc->shunned_automatic==true) {
					if ((t - mysrvc->time_last_detected_error) > max_wait_sec) {
						mysrvc->status=MYSQL_SERVER_STATUS_ONLINE;
						mysrvc->shunned_automatic=false;
						mysrvc->connect_ERR_at_time_last_detected_error=0;
						mysrvc->time_last_detected_error=0;
						// if a server is taken back online, consider it immediately
						if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : mysql_thread___default_max_latency_ms*1000 ) ) { // consider the host only if not too far
							sum+=mysrvc->weight;
							TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
						}
					}
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
				unsigned int len=mysrvc->ConnectionsUsed->conns_length();
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

		unsigned int k;
		if (New_sum > 32768) {
			k=rand()%New_sum;
		} else {
			k=fastrand()%New_sum;
		}
  	k++;
		New_sum=0;

		for (j=0; j<l; j++) {
			mysrvc=mysrvs->idx(j);
			if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) { // consider this server only if ONLINE
				unsigned int len=mysrvc->ConnectionsUsed->conns_length();
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
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC NULL\n");
	return NULL; // if we reach here, we couldn't find any target
}

unsigned int MySrvList::cnt() {
	return servers->len;
}

MySrvC * MySrvList::idx(unsigned int i) { return (MySrvC *)servers->index(i); }

MySQL_Connection * MySrvConnList::get_random_MyConn(bool ff) {
	MySQL_Connection * conn=NULL;
	unsigned int i;
	unsigned int l=conns_length();
	if (l && ff==false) {
		if (l>32768) {
			i=rand()%l;
		} else {
			i=fastrand()%l;
		}
		conn=(MySQL_Connection *)conns->remove_index_fast(i);
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
		return conn;
	} else {
		conn = new MySQL_Connection();
		conn->parent=mysrvc;
		__sync_fetch_and_add(&MyHGM->status.server_connections_created, 1);
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
		return  conn;
	}
	return NULL; // never reach here
}

MySQL_Connection * MySQL_HostGroups_Manager::get_MyConn_from_pool(unsigned int _hid, bool ff) {
	MySQL_Connection * conn=NULL;
	wrlock();
	status.myconnpoll_get++;
	MyHGC *myhgc=MyHGC_lookup(_hid);
	MySrvC *mysrvc=myhgc->get_random_MySrvC();
	if (mysrvc) { // a MySrvC exists. If not, we return NULL = no targets
		conn=mysrvc->ConnectionsFree->get_random_MyConn(ff);
		mysrvc->ConnectionsUsed->add(conn);
		status.myconnpoll_get_ok++;
	}
	wrunlock();
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, (conn ? conn->parent->address : "") , (conn ? conn->parent->port : 0 ));
	return conn;
}

void MySQL_HostGroups_Manager::destroy_MyConn_from_pool(MySQL_Connection *c) {
	bool to_del=true; // the default, legacy behavior
	MySrvC *mysrvc=(MySrvC *)c->parent;
	if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE && c->send_quit && queue.size() < 100) {
		// overall, the backend seems healthy and so it is the connection. Try to reset it
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Trying to reset MySQL_Connection %p, server %s:%d\n", c, mysrvc->address, mysrvc->port);
		to_del=false;
		c->userinfo->set(mysql_thread___monitor_username,mysql_thread___monitor_password,mysql_thread___default_schema,NULL);
		queue.add(c);
	} else {
		// we lock only this part of the code because we need to remove the connection from ConnectionsUsed
		wrlock();
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d\n", c, mysrvc->address, mysrvc->port);
		mysrvc->ConnectionsUsed->remove(c);
		status.myconnpoll_destroy++;
		wrunlock();
	}
	if (to_del) {
		delete c;
	}
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
						proxy_warning("Shunning server %s:%d with replication lag of %d second\n", address, port, current_replication_lag);
						mysrvc->status=MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG;
					}
				} else {
					if (mysrvc->status==MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) {
						if (
							(current_replication_lag>=0 && ((unsigned int)current_replication_lag <= mysrvc->max_replication_lag))
							||
							(current_replication_lag==-2) // see issue 959
						) {
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
			while (mysrvc->ConnectionsFree->conns_length() && mysrvc->ConnectionsUsed->conns_length()+mysrvc->ConnectionsFree->conns_length() > mysrvc->max_connections) {
				MySQL_Connection *conn=mysrvc->ConnectionsFree->remove(0);
				delete conn;
			}

			//PtrArray *pa=mysrvc->ConnectionsFree->conns;
			MySrvConnList *mscl=mysrvc->ConnectionsFree;
			while (mscl->conns_length() > mysql_thread___free_connections_pct*mysrvc->max_connections/100) {
				MySQL_Connection *mc=mscl->remove(0);
				delete mc;
			}

			// drop all connections with life exceeding mysql-connection_max_age
			if (mysql_thread___connection_max_age_ms) {
				unsigned long long curtime=monotonic_time();
				int i=0;
				for (i=0; i<(int)mscl->conns_length() ; i++) {
					MySQL_Connection *mc=mscl->index(i);
					if (curtime > mc->creation_time + mysql_thread___connection_max_age_ms * 1000) {
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
	int i,j, k;
	for (i=0; i<(int)MyHostGroups->len; i++) {
		MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		if (_hid >= 0 && _hid!=(int)myhgc->hid) continue;
		for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
			MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
			//PtrArray *pa=mysrvc->ConnectionsFree->conns;
			MySrvConnList *mscl=mysrvc->ConnectionsFree;
			for (k=0; k<(int)mscl->conns_length(); k++) {
				MySQL_Connection *mc=mscl->index(k);
				// If the connection is idle ...
				if (mc->last_time_used < _max_last_time_used) {
					//mc=(MySQL_Connection *)pa->remove_index_fast(k);
					mc=mscl->remove(k);
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

void MySQL_HostGroups_Manager::set_incoming_group_replication_hostgroups(SQLite3_result *s) {
	incoming_group_replication_hostgroups=s;
}

SQLite3_result * MySQL_HostGroups_Manager::SQL3_Connection_Pool(bool _reset) {
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
			while (mysrvc->ConnectionsFree->conns_length() && mysrvc->ConnectionsUsed->conns_length()+mysrvc->ConnectionsFree->conns_length() > mysrvc->max_connections) {
				//MySQL_Connection *conn=(MySQL_Connection *)mysrvc->ConnectionsFree->conns->remove_index_fast(0);
				MySQL_Connection *conn=mysrvc->ConnectionsFree->remove(0);
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
			sprintf(buf,"%llu", mysrvc->queries_sent);
			pta[8]=strdup(buf);
			if (_reset) {
				mysrvc->queries_sent=0;
			}
			sprintf(buf,"%llu", mysrvc->bytes_sent);
			pta[9]=strdup(buf);
			if (_reset) {
				mysrvc->bytes_sent=0;
			}
			sprintf(buf,"%llu", mysrvc->bytes_recv);
			pta[10]=strdup(buf);
			if (_reset) {
				mysrvc->bytes_recv=0;
			}
			sprintf(buf,"%u", mysrvc->current_latency_us);
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
	const char *Q1=(char *)"SELECT hostgroup_id,status FROM mysql_replication_hostgroups JOIN mysql_servers ON hostgroup_id=writer_hostgroup AND hostname='%s' AND port=%d AND status<>3";
	const char *Q1B=(char *)"SELECT hostgroup_id,status FROM ( SELECT DISTINCT writer_hostgroup FROM mysql_replication_hostgroups JOIN mysql_servers WHERE (hostgroup_id=writer_hostgroup OR reader_hostgroup=hostgroup_id) AND hostname='%s' AND port=%d ) LEFT JOIN mysql_servers ON hostgroup_id=writer_hostgroup AND hostname='%s' AND port=%d";
	const char *Q2A=(char *)"DELETE FROM mysql_servers WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT writer_hostgroup FROM mysql_replication_hostgroups WHERE writer_hostgroup=mysql_servers.hostgroup_id) AND status='OFFLINE_HARD'";
	const char *Q2B=(char *)"UPDATE OR IGNORE mysql_servers SET hostgroup_id=(SELECT writer_hostgroup FROM mysql_replication_hostgroups WHERE reader_hostgroup=mysql_servers.hostgroup_id) WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT reader_hostgroup FROM mysql_replication_hostgroups WHERE reader_hostgroup=mysql_servers.hostgroup_id)";
	const char *Q3A=(char *)"INSERT OR IGNORE INTO mysql_servers(hostgroup_id, hostname, port, status, weight, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) SELECT reader_hostgroup, hostname, port, status, weight, max_connections, max_replication_lag, use_ssl, max_latency_ms, mysql_servers.comment FROM mysql_servers JOIN mysql_replication_hostgroups ON mysql_servers.hostgroup_id=mysql_replication_hostgroups.writer_hostgroup WHERE hostname='%s' AND port=%d";
	const char *Q3B=(char *)"DELETE FROM mysql_servers WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT reader_hostgroup FROM mysql_replication_hostgroups WHERE reader_hostgroup=mysql_servers.hostgroup_id)";
	const char *Q4=(char *)"UPDATE OR IGNORE mysql_servers SET hostgroup_id=(SELECT reader_hostgroup FROM mysql_replication_hostgroups WHERE writer_hostgroup=mysql_servers.hostgroup_id) WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT writer_hostgroup FROM mysql_replication_hostgroups WHERE writer_hostgroup=mysql_servers.hostgroup_id)";
	const char *Q5=(char *)"DELETE FROM mysql_servers WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT writer_hostgroup FROM mysql_replication_hostgroups WHERE writer_hostgroup=mysql_servers.hostgroup_id)";
	if (GloAdmin==NULL) {
		return;
	}

	pthread_mutex_lock(&readonly_mutex);

	// define a buffer that will be used for all queries
	char *query=(char *)malloc(strlen(hostname)*2+strlen(Q3A)+64);
	sprintf(query,Q1,hostname,port);

	int cols=0;
	char *error=NULL;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	wrlock();
	mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	wrunlock();
	int num_rows=0;
	if (resultset==NULL) {
		goto __exit_read_only_action;
	}
	num_rows=resultset->rows_count;

	delete resultset;
	resultset=NULL;
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
				sprintf(query,Q2B,hostname,port);
				admindb->execute(query);
				if (mysql_thread___monitor_writer_is_also_reader) {
					sprintf(query,Q3A,hostname,port);
				} else {
					sprintf(query,Q3B,hostname,port);
				}
				admindb->execute(query);
				GloAdmin->load_mysql_servers_to_runtime(); // LOAD MYSQL SERVERS TO RUNTIME
				GloAdmin->mysql_servers_wrunlock();
			} else {
				// there is a server in writer hostgroup, let check the status of present and not present hosts
				// this is the same query as Q1, but with a LEFT JOIN
				sprintf(query,Q1B,hostname,port,hostname,port);
				wrlock();
				mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
				wrunlock();
				bool act=false;
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
				if (act==true) {	// there are servers either missing, or with stats=OFFLINE_HARD
					GloAdmin->mysql_servers_wrlock();
					GloAdmin->save_mysql_servers_runtime_to_database(false); // SAVE MYSQL SERVERS FROM RUNTIME
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
					GloAdmin->load_mysql_servers_to_runtime(); // LOAD MYSQL SERVERS TO RUNTIME
					GloAdmin->mysql_servers_wrunlock();
				}
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

__exit_read_only_action:
	pthread_mutex_unlock(&readonly_mutex);
	if (resultset) {
		delete resultset;
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
							mysrvc->status=MYSQL_SERVER_STATUS_SHUNNED;
						case MYSQL_SERVER_STATUS_OFFLINE_SOFT:
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

unsigned long long MySQL_HostGroups_Manager::Get_Memory_Stats() {
	unsigned long long intsize=0;
	wrlock();
	MySrvC *mysrvc=NULL;
  for (unsigned int i=0; i<MyHostGroups->len; i++) {
		intsize+=sizeof(MyHGC);
    MyHGC *myhgc=(MyHGC *)MyHostGroups->index(i);
		unsigned int j,k;
		unsigned int l=myhgc->mysrvs->cnt();
		if (l) {
			for (j=0; j<l; j++) {
				intsize+=sizeof(MySrvC);
				mysrvc=myhgc->mysrvs->idx(j);
				intsize+=((mysrvc->ConnectionsUsed->conns_length())*sizeof(MySQL_Connection *));
				for (k=0; k<mysrvc->ConnectionsFree->conns_length(); k++) {
					//MySQL_Connection *myconn=(MySQL_Connection *)mysrvc->ConnectionsFree->conns->index(k);
					MySQL_Connection *myconn=mysrvc->ConnectionsFree->index(k);
					intsize+=sizeof(MySQL_Connection)+sizeof(MYSQL);
					intsize+=myconn->mysql->net.max_packet;
					intsize+=(4096*15); // ASYNC_CONTEXT_DEFAULT_STACK_SIZE
					if (myconn->MyRS) {
						intsize+=myconn->MyRS->current_size();
					}
				}
				intsize+=((mysrvc->ConnectionsUsed->conns_length())*sizeof(MySQL_Connection *));
			}
		}
	}
	wrunlock();
	return intsize;
}


Group_Replication_Info::Group_Replication_Info(int w, int b, int r, int o, int mw, int mtb, bool _a, bool _w, char *c) {
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

bool Group_Replication_Info::update(int b, int r, int o, int mw, int mtb, bool _a, bool _w, char *c) {
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
			mydb->execute("INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers");
			q=(char *)"UPDATE OR IGNORE mysql_servers_incoming SET hostgroup_id=(SELECT offline_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d) WHERE hostname='%s' AND port=%d AND hostgroup_id<>(SELECT offline_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d)";
			query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_writer_hostgroup,_hostname,_port,_writer_hostgroup);
			mydb->execute(query);
			//free(query);
			q=(char *)"DELETE FROM mysql_servers_incoming WHERE hostname='%s' AND port=%d AND hostgroup_id<>(SELECT offline_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d)";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_hostname,_port,_writer_hostgroup);
			mydb->execute(query);
			//free(query);
			q=(char *)"UPDATE mysql_servers_incoming SET status=0 WHERE hostname='%s' AND port=%d AND hostgroup_id=(SELECT offline_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d)";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_hostname,_port,_writer_hostgroup);
			mydb->execute(query);
			//free(query);
			converge_group_replication_config(_writer_hostgroup);
			commit();
			wrlock();
			SQLite3_result *resultset2=NULL;
			q=(char *)"SELECT writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_port,_writer_hostgroup);
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
						sprintf(query,q,_port,_writer_hostgroup);
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
			mydb->execute("INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers");
			q=(char *)"UPDATE OR IGNORE mysql_servers_incoming SET hostgroup_id=(SELECT reader_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d) WHERE hostname='%s' AND port=%d AND hostgroup_id<>(SELECT reader_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d)";
			query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_writer_hostgroup,_hostname,_port,_writer_hostgroup);
			mydb->execute(query);
			//free(query);
			q=(char *)"DELETE FROM mysql_servers_incoming WHERE hostname='%s' AND port=%d AND hostgroup_id<>(SELECT reader_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d)";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_hostname,_port,_writer_hostgroup);
			mydb->execute(query);
			//free(query);
			q=(char *)"UPDATE mysql_servers_incoming SET status=0 WHERE hostname='%s' AND port=%d AND hostgroup_id=(SELECT reader_hostgroup FROM mysql_group_replication_hostgroups WHERE writer_hostgroup=%d)";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_hostname,_port,_writer_hostgroup);
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

void MySQL_HostGroups_Manager::update_group_replication_set_writer(char *_hostname, int _port, int _writer_hostgroup) {
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=NULL;
	char *q=NULL;
	char *error=NULL;
	q=(char *)"SELECT hostgroup_id FROM mysql_servers JOIN mysql_group_replication_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup OR hostgroup_id=backup_writer_hostgroup OR hostgroup_id=offline_hostgroup WHERE hostname='%s' AND port=%d AND status<>3";
	query=(char *)malloc(strlen(q)+strlen(_hostname)+32);
	sprintf(query,q,_hostname,_port);
  mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset);
	if (error) {
		free(error);
		error=NULL;
	}
	free(query);

	bool writer_is_also_reader=false;
	bool found_writer=false;
	bool found_reader=false;
	int read_HG=-1;
	bool need_converge=false;
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
			need_converge=info->need_converge;
			info->need_converge=false;
		}
		pthread_mutex_unlock(&Group_Replication_Info_mutex);

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
		if (need_converge==false) {
			if (found_writer) { // maybe no-op
				if (writer_is_also_reader==found_reader) { // either both true or both false
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
			mydb->execute("INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers");
			q=(char *)"UPDATE OR IGNORE mysql_servers_incoming SET hostgroup_id=%d WHERE hostname='%s' AND port=%d AND hostgroup_id<>%d";
			query=(char *)malloc(strlen(q)+strlen(_hostname)+256);
			sprintf(query,q,_writer_hostgroup,_hostname,_port,_writer_hostgroup);
			mydb->execute(query);
			//free(query);
			q=(char *)"DELETE FROM mysql_servers_incoming WHERE hostname='%s' AND port=%d AND hostgroup_id<>%d";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_hostname,_port,_writer_hostgroup);
			mydb->execute(query);
			//free(query);
			q=(char *)"UPDATE mysql_servers_incoming SET status=0 WHERE hostname='%s' AND port=%d AND hostgroup_id=%d";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query,q,_hostname,_port,_writer_hostgroup);
			mydb->execute(query);
			//free(query);
			if (writer_is_also_reader && read_HG>=0) {
				q=(char *)"INSERT OR IGNORE INTO mysql_servers_incoming (hostgroup_id,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) SELECT %d,hostname,port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers_incoming WHERE hostgroup_id=%d AND hostname='%s' AND port=%d";
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

// this function completes the tuning of mysql_servers_incoming
// it assumes that before calling converge_group_replication_config()
// * GloAdmin->mysql_servers_wrlock() was already called
// * mysql_servers_incoming has already entries copied from mysql_servers and ready to be loaded
// at this moment, it is only used to check if there are more than one writer
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
		q=(char *)"SELECT hostgroup_id,hostname,port FROM mysql_servers_incoming WHERE status=0 AND hostgroup_id IN (%d, %d, %d, %d) ORDER BY weight DESC, hostname DESC";
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
					proxy_info("Group replication: max_writers=%d , moving %d nodes from writer HG %d to backup HG %d\n", info->max_writers, to_move, info->writer_hostgroup, info->backup_writer_hostgroup);
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
						proxy_info("Group replication: max_writers=%d , moving %d nodes from backup HG %d to writer HG %d\n", info->max_writers, to_move, info->backup_writer_hostgroup, info->writer_hostgroup);
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
	} else {
		// we couldn't find the cluster, exits
	}
	pthread_mutex_unlock(&Group_Replication_Info_mutex);
}
