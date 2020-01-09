#include "proxysql.h"
#include "cpp.h"
#include "SpookyV2.h"

#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"

#define char_malloc (char *)malloc
#define itostr(__s, __i)  { __s=char_malloc(32); sprintf(__s, "%lld", __i); }

#include "thread.h"
#include "wqueue.h"

#include "ev.h"

#include <mutex>

#define USE_MYSRVC_ARRAY

#ifdef USE_MYSRVC_ARRAY
static unsigned long long array_mysrvc_total = 0;
static unsigned long long array_mysrvc_cands = 0;
#endif // USE_MYSRVC_ARRAY

#define SAFE_SQLITE3_STEP(_stmt) do {\
  do {\
    rc=sqlite3_step(_stmt);\
    if (rc!=SQLITE_DONE) {\
      assert(rc==SQLITE_LOCKED);\
      usleep(100);\
    }\
  } while (rc!=SQLITE_DONE);\
} while (0)

#define SAFE_SQLITE3_STEP2(_stmt) do {\
	do {\
		rc=sqlite3_step(_stmt);\
		if (rc==SQLITE_LOCKED || rc==SQLITE_BUSY) {\
			usleep(100);\
		}\
	} while (rc==SQLITE_LOCKED || rc==SQLITE_BUSY);\
} while (0)

extern ProxySQL_Admin *GloAdmin;

extern MySQL_Threads_Handler *GloMTH;

extern MySQL_Monitor *GloMyMon;

class MySrvConnList;
class MySrvC;
class MySrvList;
class MyHGC;

/*
class HGM_query_errors_stats {
	public:
	int hid;
	char *hostname;
	int port;
	char *username;
	char *schemaname;
	int error_no;
	unsigned int count_star;
	time_t first_seen;
	time_t last_seen;
	char *last_error;
	HGM_query_errors_stats(int _h, char *_hn, int _p, char *u, char *s, int e, char *le) {
		hid=_h;
		hostname=strdup(_hn);
		port=_p;
		username=strdup(u);
		schemaname=strdup(s);
		error_no=e;
		last_error=strdup(le);
		count_star=0;
		first_seen=0;
		last_seen=0;
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
	~HGM_query_errors_stats() {
		if (hostname) {
			free(hostname);
			hostname=NULL;
		}
		if (username) {
			free(username);
			username=NULL;
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
		char **pta=(char **)malloc(sizeof(char *)*10);
		sprintf(buf,"%d",hid);
		pta[0]=strdup(buf);
		assert(hostname);
		pta[1]=strdup(hostname);
		sprintf(buf,"%d",port);
		pta[2]=strdup(buf);
		assert(username);
		pta[3]=strdup(username);
		assert(schemaname);
		pta[4]=strdup(schemaname);
		sprintf(buf,"%d",error_no);
		pta[5]=strdup(buf);

		sprintf(buf,"%u",count_star);
		pta[6]=strdup(buf);

		time_t __now;
		time(&__now);
		unsigned long long curtime=monotonic_time();
		time_t seen_time;

		seen_time= __now - curtime/1000000 + first_seen/1000000;
		sprintf(buf,"%ld", seen_time);
		pta[7]=strdup(buf);

		seen_time= __now - curtime/1000000 + last_seen/1000000;
		sprintf(buf,"%ld", seen_time);
		pta[8]=strdup(buf);

		assert(last_error);
		pta[9]=strdup(last_error);
		return pta;
	}
	void free_row(char **pta) {
		int i;
		for (i=0;i<10;i++) {
			assert(pta[i]);
			free(pta[i]);
		}
		free(pta);
	}
};

*/

//static struct ev_async * gtid_ev_async;

static pthread_mutex_t ev_loop_mutex;

//static std::unordered_map <string, Gtid_Server_Info *> gtid_map;

static void gtid_async_cb(struct ev_loop *loop, struct ev_async *watcher, int revents) {
	if (glovars.shutdown) {
		ev_break(loop);
	}
	pthread_mutex_lock(&ev_loop_mutex);
	MyHGM->gtid_missing_nodes = false;
	MyHGM->generate_mysql_gtid_executed_tables();
	pthread_mutex_unlock(&ev_loop_mutex);
	return;
}

static void gtid_timer_cb (struct ev_loop *loop, struct ev_timer *timer, int revents) {
	ev_timer_stop(loop, timer);
	ev_timer_set(timer, __sync_add_and_fetch(&GloMTH->variables.binlog_reader_connect_retry_msec,0)/1000, 0);
	if (glovars.shutdown) {
		ev_break(loop);
	}
	if (MyHGM->gtid_missing_nodes) {
		pthread_mutex_lock(&ev_loop_mutex);
		MyHGM->gtid_missing_nodes = false;
		MyHGM->generate_mysql_gtid_executed_tables();
		pthread_mutex_unlock(&ev_loop_mutex);
	}
	ev_timer_start(loop, timer);
	return;
}

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

void reader_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
	pthread_mutex_lock(&ev_loop_mutex);
	if (revents & EV_READ) {
		GTID_Server_Data *sd = (GTID_Server_Data *)w->data;
		bool rc = true;
		rc = sd->readall();
		if (rc == false) {
			//delete sd;
			std::string s1 = sd->address;
			s1.append(":");
			s1.append(std::to_string(sd->mysql_port));
			MyHGM->gtid_missing_nodes = true;
			proxy_warning("GTID: failed to connect to ProxySQL binlog reader on port %d for server %s:%d\n", sd->port, sd->address, sd->mysql_port);
			std::unordered_map <string, GTID_Server_Data *>::iterator it2;
			it2 = MyHGM->gtid_map.find(s1);
			if (it2 != MyHGM->gtid_map.end()) {
				//MyHGM->gtid_map.erase(it2);
				it2->second = NULL;
				delete sd;
			}
			ev_io_stop(MyHGM->gtid_ev_loop, w);
			free(w);
		} else {
			sd->dump();
		}
	}
	pthread_mutex_unlock(&ev_loop_mutex);
}

void connect_cb(EV_P_ ev_io *w, int revents) {
	pthread_mutex_lock(&ev_loop_mutex);
	struct ev_io * c = w;
	if (revents & EV_WRITE) {
		int optval = 0;
		socklen_t optlen = sizeof(optval);
		if ((getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) ||
			(optval != 0)) {
			/* Connection failed; try the next address in the list. */
			//int errnum = optval ? optval : errno;
			ev_io_stop(MyHGM->gtid_ev_loop, w);
			close(w->fd);
			MyHGM->gtid_missing_nodes = true;
			GTID_Server_Data * custom_data = (GTID_Server_Data *)w->data;
			GTID_Server_Data *sd = custom_data;
			std::string s1 = sd->address;
			s1.append(":");
			s1.append(std::to_string(sd->mysql_port));
			proxy_warning("GTID: failed to connect to ProxySQL binlog reader on port %d for server %s:%d\n", sd->port, sd->address, sd->mysql_port);
			std::unordered_map <string, GTID_Server_Data *>::iterator it2;
			it2 = MyHGM->gtid_map.find(s1);
			if (it2 != MyHGM->gtid_map.end()) {
				//MyHGM->gtid_map.erase(it2);
				it2->second = NULL;
				delete sd;
			}
			//delete custom_data;
			free(c);
		} else {
			ev_io_stop(MyHGM->gtid_ev_loop, w);
			int fd=w->fd;
			struct ev_io * new_w = (struct ev_io*) malloc(sizeof(struct ev_io));
			new_w->data = w->data;
			GTID_Server_Data * custom_data = (GTID_Server_Data *)new_w->data;
			custom_data->w = new_w;
			free(w);
			ev_io_init(new_w, reader_cb, fd, EV_READ);
			ev_io_start(MyHGM->gtid_ev_loop, new_w);
		}
	}
	pthread_mutex_unlock(&ev_loop_mutex);
}

struct ev_io * new_connector(char *address, uint16_t gtid_port, uint16_t mysql_port) {
	//struct sockaddr_in a;
	int s;

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		close(s);
		return NULL;
	}
/*
	memset(&a, 0, sizeof(a));
	a.sin_port = htons(gtid_port);
	a.sin_family = AF_INET;
	if (!inet_aton(address, (struct in_addr *) &a.sin_addr.s_addr)) {
		perror("bad IP address format");
		close(s);
		return NULL;
	}
*/
	ioctl_FIONBIO(s,1);

	struct addrinfo hints;
	struct addrinfo *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_protocol= IPPROTO_TCP;
	hints.ai_family= AF_UNSPEC;
	hints.ai_socktype= SOCK_STREAM;

	char str_port[NI_MAXSERV+1];
	sprintf(str_port,"%d", gtid_port);
	int gai_rc = getaddrinfo(address, str_port, &hints, &res);
	if (gai_rc) {
		freeaddrinfo(res);
		//exit here
		return NULL;
	}

	//int status = connect(s, (struct sockaddr *) &a, sizeof(a));
	int status = connect(s, res->ai_addr, res->ai_addrlen);
	if ((status == 0) || ((status == -1) && (errno == EINPROGRESS))) {
		struct ev_io *c = (struct ev_io *)malloc(sizeof(struct ev_io));
		if (c) {
			ev_io_init(c, connect_cb, s, EV_WRITE);
			GTID_Server_Data * custom_data = new GTID_Server_Data(c, address, gtid_port, mysql_port);
			c->data = (void *)custom_data;
			return c;
		}
		/* else error */
	}
	return NULL;
}



GTID_Server_Data::GTID_Server_Data(struct ev_io *_w, char *_address, uint16_t _port, uint16_t _mysql_port) {
	active = true;
	w = _w;
	size = 1024; // 1KB buffer
	data = (char *)malloc(size);
	uuid_server[0] = 0;
	pos = 0;
	len = 0;
	address = strdup(_address);
	port = _port;
	mysql_port = _mysql_port;
	events_read = 0;
}

void GTID_Server_Data::resize(size_t _s) {
	char *data_ = (char *)malloc(_s);
	memcpy(data_, data, (_s > size ? size : _s));
	size = _s;
	free(data);
	data = data_;
}

GTID_Server_Data::~GTID_Server_Data() {
	free(address);
	free(data);
}

bool GTID_Server_Data::readall() {
	bool ret = true;
	if (size == len) {
		// buffer is full, expand
		resize(len*2);
	}
	int rc = 0;
	rc = read(w->fd,data+len,size-len);
	if (rc > 0) {
		len += rc;
	} else {
		int myerr = errno;
		proxy_error("Read returned %d bytes, error %d\n", rc, myerr);
		if (
			(rc == 0) ||
			(rc==-1 && myerr != EINTR && myerr != EAGAIN)
		) {
			ret = false;
		}
	}
	return ret;
}


bool GTID_Server_Data::gtid_exists(char *gtid_uuid, uint64_t gtid_trxid) {
	std::string s = gtid_uuid;
	auto it = gtid_executed.find(s);
//	fprintf(stderr,"Checking if server %s:%d has GTID %s:%lu ... ", address, port, gtid_uuid, gtid_trxid);
	if (it == gtid_executed.end()) {
//		fprintf(stderr,"NO\n");
		return false;
	}
	for (auto itr = it->second.begin(); itr != it->second.end(); ++itr) {
		if ((int64_t)gtid_trxid >= itr->first && (int64_t)gtid_trxid <= itr->second) {
//			fprintf(stderr,"YES\n");
			return true;
		}
	}
//	fprintf(stderr,"NO\n");
	return false;
}

void GTID_Server_Data::read_all_gtids() {
		while (read_next_gtid()) {
		}
	}

void GTID_Server_Data::dump() {
	if (len==0) {
		return;
	}
	read_all_gtids();
	//int rc = write(1,data+pos,len-pos);
	fflush(stdout);
	///pos += rc;
	if (pos >= len/2) {
		memmove(data,data+pos,len-pos);
		len = len-pos;
		pos = 0;
	}
}

bool GTID_Server_Data::writeout() {
	bool ret = true;
	if (len==0) {
		return ret;
	}
	int rc = 0;
	rc = write(w->fd,data+pos,len-pos);
	if (rc > 0) {
		pos += rc;
		if (pos >= len/2) {
			memmove(data,data+pos,len-pos);
			len = len-pos;
			pos = 0;
		}
	}
	return ret;
}

bool GTID_Server_Data::read_next_gtid() {
	if (len==0) {
		return false;
	}
	void *nlp = NULL;
	nlp = memchr(data+pos,'\n',len-pos);
	if (nlp == NULL) {
		return false;
	}
	int l = (char *)nlp - (data+pos);
	char rec_msg[80];
	if (strncmp(data+pos,(char *)"ST=",3)==0) {
		// we are reading the bootstrap
		char *bs = (char *)malloc(l+1-3); // length + 1 (null byte) - 3 (header)
		memcpy(bs,data+pos+3,l+1-3);
		char *saveptr1=NULL;
		char *saveptr2=NULL;
		//char *saveptr3=NULL;
		char *token = NULL;
		char *subtoken = NULL;
		//char *subtoken2 = NULL;
		char *str1 = NULL;
		char *str2 = NULL;
		//char *str3 = NULL;
		for (str1 = bs; ; str1 = NULL) {
			token = strtok_r(str1, ",", &saveptr1);
			if (token == NULL) {
				break;
			}
			int j = 0;
			for (str2 = token; ; str2 = NULL) {
				subtoken = strtok_r(str2, ":", &saveptr2);
				if (subtoken == NULL) {
					break;
					}
				j++;
				if (j%2 == 1) { // we are reading the uuid
					char *p = uuid_server;
					for (unsigned int k=0; k<strlen(subtoken); k++) {
						if (subtoken[k]!='-') {
							*p = subtoken[k];
							p++;
						}
					}
					//fprintf(stdout,"BS from %s\n", uuid_server);
				} else { // we are reading the trxids
					uint64_t trx_from;
					uint64_t trx_to;
					sscanf(subtoken,"%lu-%lu",&trx_from,&trx_to);
					//fprintf(stdout,"BS from %s:%lu-%lu\n", uuid_server, trx_from, trx_to);
					std::string s = uuid_server;
					gtid_executed[s].emplace_back(trx_from, trx_to);
			   }
			}
		}
		pos += l+1;
		free(bs);
		//return true;
	} else {
		strncpy(rec_msg,data+pos,l);
		pos += l+1;
		rec_msg[l]=0;
		//int rc = write(1,data+pos,l+1);
		//fprintf(stdout,"%s\n", rec_msg);
		if (rec_msg[0]=='I') {
			//char rec_uuid[80];
			uint64_t rec_trxid;
			char *a = NULL;
			int ul = 0;
			switch (rec_msg[1]) {
				case '1':
					//sscanf(rec_msg+3,"%s\:%lu",uuid_server,&rec_trxid);
					a = strchr(rec_msg+3,':');
					ul = a-rec_msg-3;
					strncpy(uuid_server,rec_msg+3,ul);
					uuid_server[ul] = 0;
					rec_trxid=atoll(a+1);
					break;
				case '2':
					//sscanf(rec_msg+3,"%lu",&rec_trxid);
					rec_trxid=atoll(rec_msg+3);
					break;
				default:
					break;
			}
			//fprintf(stdout,"%s:%lu\n", uuid_server, rec_trxid);
			std::string s = uuid_server;
			gtid_t new_gtid = std::make_pair(s,rec_trxid);
			addGtid(new_gtid,gtid_executed);
			events_read++;
			//return true;
		}
	}
	//std::cout << "current pos " << gtid_executed_to_string(gtid_executed) << std::endl << std::endl;
	return true;
}

std::string gtid_executed_to_string(gtid_set_t& gtid_executed) {
	std::string gtid_set;
	for (auto it=gtid_executed.begin(); it!=gtid_executed.end(); ++it) {
		std::string s = it->first;
		s.insert(8,"-");
		s.insert(13,"-");
		s.insert(18,"-");
		s.insert(23,"-");
		s = s + ":";
		for (auto itr = it->second.begin(); itr != it->second.end(); ++itr) {
			std::string s2 = s;
			s2 = s2 + std::to_string(itr->first);
			s2 = s2 + "-";
			s2 = s2 + std::to_string(itr->second);
			s2 = s2 + ",";
			gtid_set = gtid_set + s2;
		}
	}
	gtid_set.pop_back();
	return gtid_set;
}



void addGtid(const gtid_t& gtid, gtid_set_t& gtid_executed) {
	auto it = gtid_executed.find(gtid.first);
	if (it == gtid_executed.end())
	{
		gtid_executed[gtid.first].emplace_back(gtid.second, gtid.second);
		return;
	}

	bool flag = true;
	for (auto itr = it->second.begin(); itr != it->second.end(); ++itr)
	{
		if (gtid.second >= itr->first && gtid.second <= itr->second)
			return;
		if (gtid.second + 1 == itr->first)
		{
			--itr->first;
			flag = false;
			break;
		}
		else if (gtid.second == itr->second + 1)
		{
			++itr->second;
			flag = false;
			break;
		}
		else if (gtid.second < itr->first)
		{
			it->second.emplace(itr, gtid.second, gtid.second);
			return;
		}
	}

	if (flag)
		it->second.emplace_back(gtid.second, gtid.second);

	for (auto itr = it->second.begin(); itr != it->second.end(); ++itr)
	{
		auto next_itr = std::next(itr);
		if (next_itr != it->second.end() && itr->second + 1 == next_itr->first)
		{
			itr->second = next_itr->second;
			it->second.erase(next_itr);
			break;
		}
	}
}

static void * GTID_syncer_run() {
	//struct ev_loop * gtid_ev_loop;
	//gtid_ev_loop = NULL;
	MyHGM->gtid_ev_loop = ev_loop_new (EVBACKEND_POLL | EVFLAG_NOENV);
	if (MyHGM->gtid_ev_loop == NULL) {
		proxy_error("could not initialise GTID sync loop\n");
		exit(EXIT_FAILURE);
	}
	//ev_async_init(gtid_ev_async, gtid_async_cb);
	//ev_async_start(gtid_ev_loop, gtid_ev_async);
	MyHGM->gtid_ev_timer = (struct ev_timer *)malloc(sizeof(struct ev_timer));
	ev_async_init(MyHGM->gtid_ev_async, gtid_async_cb);
	ev_async_start(MyHGM->gtid_ev_loop, MyHGM->gtid_ev_async);
	//ev_timer_init(MyHGM->gtid_ev_timer, gtid_timer_cb, __sync_add_and_fetch(&GloMTH->variables.binlog_reader_connect_retry_msec,0)/1000, 0);
	ev_timer_init(MyHGM->gtid_ev_timer, gtid_timer_cb, 3, 0);
	ev_timer_start(MyHGM->gtid_ev_loop, MyHGM->gtid_ev_timer);
	//ev_ref(gtid_ev_loop);
	ev_run(MyHGM->gtid_ev_loop, 0);
	//sleep(1000);
	return NULL;
}

//static void * HGCU_thread_run() {
static void * HGCU_thread_run() {
	PtrArray *conn_array=new PtrArray();
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


MySQL_Connection *MySrvConnList::index(unsigned int _k) {
	return (MySQL_Connection *)conns->index(_k);
}

MySQL_Connection * MySrvConnList::remove(int _k) {
	return (MySQL_Connection *)conns->remove_index_fast(_k);
}

/*
unsigned int MySrvConnList::conns_length() {
	return conns->len;
}
*/

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


MySrvC::MySrvC(char *add, uint16_t p, uint16_t gp, unsigned int _weight, enum MySerStatus _status, unsigned int _compression /*, uint8_t _charset */, unsigned int _max_connections, unsigned int _max_replication_lag, unsigned int _use_ssl, unsigned int _max_latency_ms, char *_comment) {
	address=strdup(add);
	port=p;
	gtid_port=gp;
	weight=_weight;
	status=_status;
	compression=_compression;
	max_connections=_max_connections;
	max_replication_lag=_max_replication_lag;
	use_ssl=_use_ssl;
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

void MySrvC::connect_error(int err_num) {
	// NOTE: this function operates without any mutex
	// although, it is not extremely important if any counter is lost
	// as a single connection failure won't make a significant difference
	__sync_fetch_and_add(&connect_ERR,1);
	__sync_fetch_and_add(&MyHGM->status.server_connections_aborted,1);
	if (err_num >= 1048 && err_num <= 1052)
		return;
	if (err_num >= 1054 && err_num <= 1075)
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
		case 1203: // User %s already has more than 'max_user_connections' active connections
		case 1226: // User '%s' has exceeded the '%s' resource (current value: %ld)
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
	current_time_now = 0;
	new_connections_now = 0;
}


MyHGC::~MyHGC() {
	delete mysrvs;
}

MySQL_HostGroups_Manager::MySQL_HostGroups_Manager() {
	pthread_mutex_init(&ev_loop_mutex, NULL);
	status.client_connections=0;
	status.client_connections_aborted=0;
	status.client_connections_created=0;
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
	pthread_mutex_init(&readonly_mutex, NULL);
	pthread_mutex_init(&Group_Replication_Info_mutex, NULL);
	pthread_mutex_init(&Galera_Info_mutex, NULL);
	pthread_mutex_init(&AWS_Aurora_Info_mutex, NULL);
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
	mydb->execute(MYHGM_MYSQL_GALERA_HOSTGROUPS);
	mydb->execute(MYHGM_MYSQL_AWS_AURORA_HOSTGROUPS);
	MyHostGroups=new PtrArray();
	incoming_replication_hostgroups=NULL;
	incoming_group_replication_hostgroups=NULL;
	incoming_galera_hostgroups=NULL;
	incoming_aws_aurora_hostgroups = NULL;
	pthread_rwlock_init(&gtid_rwlock, NULL);
	gtid_missing_nodes = false;
	gtid_ev_loop=NULL;
	gtid_ev_timer=NULL;
	gtid_ev_async = (struct ev_async *)malloc(sizeof(struct ev_async));

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
bool MySQL_HostGroups_Manager::server_add(unsigned int hid, char *add, uint16_t p, uint16_t gp, unsigned int _weight, enum MySerStatus status, unsigned int _comp /*, uint8_t _charset */, unsigned int _max_connections, unsigned int _max_replication_lag, unsigned int _use_ssl, unsigned int _max_latency_ms , char *comment) {
	bool ret=true;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Adding in mysql_servers_incoming server %s:%d in hostgroup %u with weight %u , status %u, %s compression, max_connections %d, max_replication_lag %u, use_ssl=%u, max_latency_ms=%u\n", add,p,hid,_weight,status, (_comp ? "with" : "without") /*, _charset */ , _max_connections, _max_replication_lag, _use_ssl, _max_latency_ms);
	int rc;
	sqlite3_stmt *statement=NULL;
	//sqlite3 *mydb3=mydb->get_db();
	char *query=(char *)"INSERT INTO mysql_servers_incoming VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
	//rc=sqlite3_prepare_v2(mydb3, query, -1, &statement, 0);
	rc = mydb->prepare_v2(query, &statement);
	ASSERT_SQLITE_OK(rc, mydb);
	rc=sqlite3_bind_int64(statement, 1, hid); ASSERT_SQLITE_OK(rc, mydb);
	rc=sqlite3_bind_text(statement, 2, add, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
	rc=sqlite3_bind_int64(statement, 3, p); ASSERT_SQLITE_OK(rc, mydb);
	rc=sqlite3_bind_int64(statement, 4, gp); ASSERT_SQLITE_OK(rc, mydb);
	rc=sqlite3_bind_int64(statement, 5, _weight); ASSERT_SQLITE_OK(rc, mydb);
	rc=sqlite3_bind_int64(statement, 6, status); ASSERT_SQLITE_OK(rc, mydb);
	rc=sqlite3_bind_int64(statement, 7, _comp); ASSERT_SQLITE_OK(rc, mydb);
	rc=sqlite3_bind_int64(statement, 8, _max_connections); ASSERT_SQLITE_OK(rc, mydb);
	rc=sqlite3_bind_int64(statement, 9, _max_replication_lag); ASSERT_SQLITE_OK(rc, mydb);
	rc=sqlite3_bind_int64(statement, 10, _use_ssl); ASSERT_SQLITE_OK(rc, mydb);
	rc=sqlite3_bind_int64(statement, 11, _max_latency_ms); ASSERT_SQLITE_OK(rc, mydb);
	rc=sqlite3_bind_text(statement, 12, comment, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);

	SAFE_SQLITE3_STEP2(statement);
	rc=sqlite3_clear_bindings(statement); ASSERT_SQLITE_OK(rc, mydb);
	rc=sqlite3_reset(statement); ASSERT_SQLITE_OK(rc, mydb);
	sqlite3_finalize(statement);

	return ret;
}

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
	char *query32=(char *)"INSERT INTO mysql_servers_incoming VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12), (?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24), (?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36), (?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44, ?45, ?46, ?47, ?48), (?49, ?50, ?51, ?52, ?53, ?54, ?55, ?56, ?57, ?58, ?59, ?60), (?61, ?62, ?63, ?64, ?65, ?66, ?67, ?68, ?69, ?70, ?71, ?72), (?73, ?74, ?75, ?76, ?77, ?78, ?79, ?80, ?81, ?82, ?83, ?84), (?85, ?86, ?87, ?88, ?89, ?90, ?91, ?92, ?93, ?94, ?95, ?96), (?97, ?98, ?99, ?100, ?101, ?102, ?103, ?104, ?105, ?106, ?107, ?108), (?109, ?110, ?111, ?112, ?113, ?114, ?115, ?116, ?117, ?118, ?119, ?120), (?121, ?122, ?123, ?124, ?125, ?126, ?127, ?128, ?129, ?130, ?131, ?132), (?133, ?134, ?135, ?136, ?137, ?138, ?139, ?140, ?141, ?142, ?143, ?144), (?145, ?146, ?147, ?148, ?149, ?150, ?151, ?152, ?153, ?154, ?155, ?156), (?157, ?158, ?159, ?160, ?161, ?162, ?163, ?164, ?165, ?166, ?167, ?168), (?169, ?170, ?171, ?172, ?173, ?174, ?175, ?176, ?177, ?178, ?179, ?180), (?181, ?182, ?183, ?184, ?185, ?186, ?187, ?188, ?189, ?190, ?191, ?192), (?193, ?194, ?195, ?196, ?197, ?198, ?199, ?200, ?201, ?202, ?203, ?204), (?205, ?206, ?207, ?208, ?209, ?210, ?211, ?212, ?213, ?214, ?215, ?216), (?217, ?218, ?219, ?220, ?221, ?222, ?223, ?224, ?225, ?226, ?227, ?228), (?229, ?230, ?231, ?232, ?233, ?234, ?235, ?236, ?237, ?238, ?239, ?240), (?241, ?242, ?243, ?244, ?245, ?246, ?247, ?248, ?249, ?250, ?251, ?252), (?253, ?254, ?255, ?256, ?257, ?258, ?259, ?260, ?261, ?262, ?263, ?264), (?265, ?266, ?267, ?268, ?269, ?270, ?271, ?272, ?273, ?274, ?275, ?276), (?277, ?278, ?279, ?280, ?281, ?282, ?283, ?284, ?285, ?286, ?287, ?288), (?289, ?290, ?291, ?292, ?293, ?294, ?295, ?296, ?297, ?298, ?299, ?300), (?301, ?302, ?303, ?304, ?305, ?306, ?307, ?308, ?309, ?310, ?311, ?312), (?313, ?314, ?315, ?316, ?317, ?318, ?319, ?320, ?321, ?322, ?323, ?324), (?325, ?326, ?327, ?328, ?329, ?330, ?331, ?332, ?333, ?334, ?335, ?336), (?337, ?338, ?339, ?340, ?341, ?342, ?343, ?344, ?345, ?346, ?347, ?348), (?349, ?350, ?351, ?352, ?353, ?354, ?355, ?356, ?357, ?358, ?359, ?360), (?361, ?362, ?363, ?364, ?365, ?366, ?367, ?368, ?369, ?370, ?371, ?372), (?373, ?374, ?375, ?376, ?377, ?378, ?379, ?380, ?381, ?382, ?383, ?384)";
	//rc=sqlite3_prepare_v2(mydb3, query1, -1, &statement1, 0);
	rc = mydb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, mydb);
	//rc=sqlite3_prepare_v2(mydb3, query32, -1, &statement32, 0);
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
			rc=sqlite3_bind_int64(statement32, (idx*12)+1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_text(statement32, (idx*12)+2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement32, (idx*12)+3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement32, (idx*12)+4, atoi(r1->fields[3])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement32, (idx*12)+5, atoi(r1->fields[5])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement32, (idx*12)+6, status1); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement32, (idx*12)+7, atoi(r1->fields[6])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement32, (idx*12)+8, atoi(r1->fields[7])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement32, (idx*12)+9, atoi(r1->fields[8])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement32, (idx*12)+10, atoi(r1->fields[9])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement32, (idx*12)+11, atoi(r1->fields[10])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_text(statement32, (idx*12)+12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
			if (idx==31) {
				SAFE_SQLITE3_STEP2(statement32);
				rc=sqlite3_clear_bindings(statement32); ASSERT_SQLITE_OK(rc, mydb);
				rc=sqlite3_reset(statement32); ASSERT_SQLITE_OK(rc, mydb);
			}
		} else { // single row
			rc=sqlite3_bind_int64(statement1, 1, atoi(r1->fields[0])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_text(statement1, 2, r1->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement1, 3, atoi(r1->fields[2])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement1, 4, atoi(r1->fields[3])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement1, 5, atoi(r1->fields[5])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement1, 6, status1); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement1, 7, atoi(r1->fields[6])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement1, 8, atoi(r1->fields[7])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement1, 9, atoi(r1->fields[8])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement1, 10, atoi(r1->fields[9])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_int64(statement1, 11, atoi(r1->fields[10])); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_bind_text(statement1, 12, r1->fields[11], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
			SAFE_SQLITE3_STEP2(statement1);
			rc=sqlite3_clear_bindings(statement1); ASSERT_SQLITE_OK(rc, mydb);
			rc=sqlite3_reset(statement1); ASSERT_SQLITE_OK(rc, mydb);
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

	unsigned long long curtime1=monotonic_time();
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
		//rc=sqlite3_prepare_v2(mydb3, query1, -1, &statement1, 0);
		rc = mydb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, mydb);
		char *query2=(char *)"UPDATE mysql_servers SET weight = ?1 , status = ?2 , compression = ?3 , max_connections = ?4 , max_replication_lag = ?5 , use_ssl = ?6 , max_latency_ms = ?7 , comment = ?8 , gtid_port = ?9 WHERE hostgroup_id = ?10 AND hostname = ?11 AND port = ?12";
		//rc=sqlite3_prepare_v2(mydb3, query2, -1, &statement2, 0);
		rc = mydb->prepare_v2(query2, &statement2);
		ASSERT_SQLITE_OK(rc, mydb);

		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			long long ptr=atoll(r->fields[12]); // increase this index every time a new column is added
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d , weight=%d, status=%d, mem_pointer=%llu, hostgroup=%d, compression=%d\n", r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), (MySerStatus) atoi(r->fields[4]), ptr, atoi(r->fields[0]), atoi(r->fields[5]));
			//fprintf(stderr,"%lld\n", ptr);
			if (ptr==0) {
				if (GloMTH->variables.hostgroup_manager_verbose) {
					proxy_info("Creating new server in HG %d : %s:%d , gtid_port=%d, weight=%d, status=%d\n", atoi(r->fields[0]), r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), atoi(r->fields[4]), (MySerStatus) atoi(r->fields[5]));
				}
				MySrvC *mysrvc=new MySrvC(r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), atoi(r->fields[4]), (MySerStatus) atoi(r->fields[5]), atoi(r->fields[6]), atoi(r->fields[7]), atoi(r->fields[8]), atoi(r->fields[9]), atoi(r->fields[10]), r->fields[11]); // add new fields here if adding more columns in mysql_servers
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Adding new server %s:%d , weight=%d, status=%d, mem_ptr=%p into hostgroup=%d\n", r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), (MySerStatus) atoi(r->fields[4]), mysrvc, atoi(r->fields[0]));
				add(mysrvc,atoi(r->fields[0]));
				ptr=(uintptr_t)mysrvc;
				rc=sqlite3_bind_int64(statement1, 1, ptr); ASSERT_SQLITE_OK(rc, mydb);
				rc=sqlite3_bind_int64(statement1, 2, atoi(r->fields[0])); ASSERT_SQLITE_OK(rc, mydb);
				rc=sqlite3_bind_text(statement1, 3,  r->fields[1], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
				rc=sqlite3_bind_int64(statement1, 4, atoi(r->fields[2])); ASSERT_SQLITE_OK(rc, mydb);
				SAFE_SQLITE3_STEP2(statement1);
				rc=sqlite3_clear_bindings(statement1); ASSERT_SQLITE_OK(rc, mydb);
				rc=sqlite3_reset(statement1); ASSERT_SQLITE_OK(rc, mydb);
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
						proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Changing weight for server %d:%s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->myhgc->hid , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), atoi(r->fields[4]) , mysrvc->weight , atoi(r->fields[14]));
					mysrvc->weight=atoi(r->fields[14]);
				}
				if (atoi(r->fields[5])!=atoi(r->fields[15])) {
					if (GloMTH->variables.hostgroup_manager_verbose)
						proxy_info("Changing status for server %d:%s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->myhgc->hid , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), atoi(r->fields[5]) , mysrvc->status , atoi(r->fields[15]));
					mysrvc->status=(MySerStatus)atoi(r->fields[15]);
					if (mysrvc->status==MYSQL_SERVER_STATUS_SHUNNED) {
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
					proxy_info("Changing max_connections for server %d:%s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->myhgc->hid , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), atoi(r->fields[7]) , mysrvc->max_connections , atoi(r->fields[17]));
					mysrvc->max_connections=atoi(r->fields[17]);
				}
				if (atoi(r->fields[8])!=atoi(r->fields[18])) {
					if (GloMTH->variables.hostgroup_manager_verbose)
						proxy_info("Changing max_replication_lag for server %u:%s:%d (%s:%d) from %d (%d) to %d\n" , mysrvc->myhgc->hid , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), atoi(r->fields[8]) , mysrvc->max_replication_lag , atoi(r->fields[18]));
					mysrvc->max_replication_lag=atoi(r->fields[18]);
					if (mysrvc->max_replication_lag == 0) { // we just changed it to 0
						if (mysrvc->status == MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) {
							// the server is currently shunned due to replication lag
							// but we reset max_replication_lag to 0
							// therefore we immediately reset the status too
							mysrvc->status = MYSQL_SERVER_STATUS_ONLINE;
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
					rc=sqlite3_bind_int64(statement2, 1, mysrvc->weight); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement2, 2, mysrvc->status); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement2, 3, mysrvc->compression); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement2, 4, mysrvc->max_connections); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement2, 5, mysrvc->max_replication_lag); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement2, 6, mysrvc->use_ssl); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement2, 7, mysrvc->max_latency_us/1000); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_text(statement2, 8,  mysrvc->comment, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement2, 9, mysrvc->gtid_port); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement2, 10, mysrvc->myhgc->hid); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_text(statement2, 11,  mysrvc->address, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement2, 12, mysrvc->port); ASSERT_SQLITE_OK(rc, mydb);
					SAFE_SQLITE3_STEP2(statement2);
					rc=sqlite3_clear_bindings(statement2); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_reset(statement2); ASSERT_SQLITE_OK(rc, mydb);
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
			char *query=(char *)"SELECT hostgroup_id, hostname, port, gtid_port, CASE status WHEN 0 OR 1 OR 4 THEN 0 ELSE status END status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers WHERE status<>3 ORDER BY hostgroup_id, hostname, port";
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
		{
			char *error=NULL;
			int cols=0;
			int affected_rows=0;
			SQLite3_result *resultset=NULL;
			char *query=(char *)"SELECT * FROM mysql_galera_hostgroups ORDER BY writer_hostgroup";
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
			char *query=(char *)"SELECT * FROM mysql_aws_aurora_hostgroups ORDER BY writer_hostgroup";
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

	ev_async_send(gtid_ev_loop, gtid_ev_async);

	__sync_fetch_and_add(&status.servers_table_version,1);
	pthread_cond_broadcast(&status.servers_table_version_cond);
	pthread_mutex_unlock(&status.servers_table_version_lock);
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
				} else {
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
	std::vector<string> to_remove;
	it = gtid_map.begin();
	while(it != gtid_map.end()) {
		GTID_Server_Data * gtid_si = it->second;
		if (gtid_si->active == false) {
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
	//sqlite3 *mydb3=mydb->get_db();
	char *query1=(char *)"INSERT INTO mysql_servers VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";
	//rc=sqlite3_prepare_v2(mydb3, query1, -1, &statement1, 0);
	rc = mydb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, mydb);
	char *query32=(char *)"INSERT INTO mysql_servers VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13), (?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26), (?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38, ?39), (?40, ?41, ?42, ?43, ?44, ?45, ?46, ?47, ?48, ?49, ?50, ?51, ?52), (?53, ?54, ?55, ?56, ?57, ?58, ?59, ?60, ?61, ?62, ?63, ?64, ?65), (?66, ?67, ?68, ?69, ?70, ?71, ?72, ?73, ?74, ?75, ?76, ?77, ?78), (?79, ?80, ?81, ?82, ?83, ?84, ?85, ?86, ?87, ?88, ?89, ?90, ?91), (?92, ?93, ?94, ?95, ?96, ?97, ?98, ?99, ?100, ?101, ?102, ?103, ?104), (?105, ?106, ?107, ?108, ?109, ?110, ?111, ?112, ?113, ?114, ?115, ?116, ?117), (?118, ?119, ?120, ?121, ?122, ?123, ?124, ?125, ?126, ?127, ?128, ?129, ?130), (?131, ?132, ?133, ?134, ?135, ?136, ?137, ?138, ?139, ?140, ?141, ?142, ?143), (?144, ?145, ?146, ?147, ?148, ?149, ?150, ?151, ?152, ?153, ?154, ?155, ?156), (?157, ?158, ?159, ?160, ?161, ?162, ?163, ?164, ?165, ?166, ?167, ?168, ?169), (?170, ?171, ?172, ?173, ?174, ?175, ?176, ?177, ?178, ?179, ?180, ?181, ?182), (?183, ?184, ?185, ?186, ?187, ?188, ?189, ?190, ?191, ?192, ?193, ?194, ?195), (?196, ?197, ?198, ?199, ?200, ?201, ?202, ?203, ?204, ?205, ?206, ?207, ?208), (?209, ?210, ?211, ?212, ?213, ?214, ?215, ?216, ?217, ?218, ?219, ?220, ?221), (?222, ?223, ?224, ?225, ?226, ?227, ?228, ?229, ?230, ?231, ?232, ?233, ?234), (?235, ?236, ?237, ?238, ?239, ?240, ?241, ?242, ?243, ?244, ?245, ?246, ?247), (?248, ?249, ?250, ?251, ?252, ?253, ?254, ?255, ?256, ?257, ?258, ?259, ?260), (?261, ?262, ?263, ?264, ?265, ?266, ?267, ?268, ?269, ?270, ?271, ?272, ?273), (?274, ?275, ?276, ?277, ?278, ?279, ?280, ?281, ?282, ?283, ?284, ?285, ?286), (?287, ?288, ?289, ?290, ?291, ?292, ?293, ?294, ?295, ?296, ?297, ?298, ?299), (?300, ?301, ?302, ?303, ?304, ?305, ?306, ?307, ?308, ?309, ?310, ?311, ?312), (?313, ?314, ?315, ?316, ?317, ?318, ?319, ?320, ?321, ?322, ?323, ?324, ?325), (?326, ?327, ?328, ?329, ?330, ?331, ?332, ?333, ?334, ?335, ?336, ?337, ?338), (?339, ?340, ?341, ?342, ?343, ?344, ?345, ?346, ?347, ?348, ?349, ?350, ?351), (?352, ?353, ?354, ?355, ?356, ?357, ?358, ?359, ?360, ?361, ?362, ?363, ?364), (?365, ?366, ?367, ?368, ?369, ?370, ?371, ?372, ?373, ?374, ?375, ?376, ?377), (?378, ?379, ?380, ?381, ?382, ?383, ?384, ?385, ?386, ?387, ?388, ?389, ?390), (?391, ?392, ?393, ?394, ?395, ?396, ?397, ?398, ?399, ?400, ?401, ?402, ?403), (?404, ?405, ?406, ?407, ?408, ?409, ?410, ?411, ?412, ?413, ?414, ?415, ?416)";
	//rc=sqlite3_prepare_v2(mydb3, query32, -1, &statement32, 0);
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
				fprintf(stderr,"HID: %d , address: %s , port: %d , gtid_port: %d , weight: %d , status: %s , max_connections: %u , max_replication_lag: %u , use_ssl: %u , max_latency_ms: %u , comment: %s\n", mysrvc->myhgc->hid, mysrvc->address, mysrvc->port, mysrvc->gtid_port, mysrvc->weight, st, mysrvc->max_connections, mysrvc->max_replication_lag, mysrvc->use_ssl, mysrvc->max_latency_us*1000, mysrvc->comment);
			}
			lst->add(mysrvc);
			if (lst->len==32) {
				while (lst->len) {
					int i=lst->len;
					i--;
					MySrvC *mysrvc=(MySrvC *)lst->remove_index_fast(0);
					uintptr_t ptr=(uintptr_t)mysrvc;
					rc=sqlite3_bind_int64(statement32, (i*13)+1, mysrvc->myhgc->hid); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_text(statement32, (i*13)+2, mysrvc->address, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement32, (i*13)+3, mysrvc->port); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement32, (i*13)+4, mysrvc->gtid_port); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement32, (i*13)+5, mysrvc->weight); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement32, (i*13)+6, mysrvc->status); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement32, (i*13)+7, mysrvc->compression); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement32, (i*13)+8, mysrvc->max_connections); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement32, (i*13)+9, mysrvc->max_replication_lag); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement32, (i*13)+10, mysrvc->use_ssl); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement32, (i*13)+11, mysrvc->max_latency_us/1000); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_text(statement32, (i*13)+12, mysrvc->comment, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
					rc=sqlite3_bind_int64(statement32, (i*13)+13, ptr); ASSERT_SQLITE_OK(rc, mydb);
				}
				SAFE_SQLITE3_STEP2(statement32);
				rc=sqlite3_clear_bindings(statement32); ASSERT_SQLITE_OK(rc, mydb);
				rc=sqlite3_reset(statement32); ASSERT_SQLITE_OK(rc, mydb);
			}
		}
	}
	while (lst->len) {
		MySrvC *mysrvc=(MySrvC *)lst->remove_index_fast(0);
		uintptr_t ptr=(uintptr_t)mysrvc;
		rc=sqlite3_bind_int64(statement1, 1, mysrvc->myhgc->hid); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_text(statement1, 2, mysrvc->address, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement1, 3, mysrvc->port); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement1, 4, mysrvc->gtid_port); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement1, 5, mysrvc->weight); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement1, 6, mysrvc->status); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement1, 7, mysrvc->compression); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement1, 8, mysrvc->max_connections); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement1, 9, mysrvc->max_replication_lag); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement1, 10, mysrvc->use_ssl); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement1, 11, mysrvc->max_latency_us/1000); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_text(statement1, 12, mysrvc->comment, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement1, 13, ptr); ASSERT_SQLITE_OK(rc, mydb);

		SAFE_SQLITE3_STEP2(statement1);
		rc=sqlite3_clear_bindings(statement1); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_reset(statement1); ASSERT_SQLITE_OK(rc, mydb);
	}
	sqlite3_finalize(statement1);
	sqlite3_finalize(statement32);
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
	//rc=sqlite3_prepare_v2(mydb3, query, -1, &statement, 0);
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
		rc=sqlite3_bind_int64(statement, 1, writer_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 2, backup_writer_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 3, reader_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 4, offline_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 5, active); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 6, max_writers); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 7, writer_is_also_reader); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 8, max_transactions_behind); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_text(statement, 9, r->fields[8], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);

		SAFE_SQLITE3_STEP2(statement);
		rc=sqlite3_clear_bindings(statement); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_reset(statement); ASSERT_SQLITE_OK(rc, mydb);
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
	sqlite3_finalize(statement);
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

	pthread_mutex_unlock(&Group_Replication_Info_mutex);
}

void MySQL_HostGroups_Manager::generate_mysql_galera_hostgroups_table() {
	if (incoming_galera_hostgroups==NULL) {
		return;
	}
	int rc;
	sqlite3_stmt *statement=NULL;
	//sqlite3 *mydb3=mydb->get_db();
	char *query=(char *)"INSERT INTO mysql_galera_hostgroups(writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
	//rc=sqlite3_prepare_v2(mydb3, query, -1, &statement, 0);
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
		rc=sqlite3_bind_int64(statement, 1, writer_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 2, backup_writer_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 3, reader_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 4, offline_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 5, active); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 6, max_writers); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 7, writer_is_also_reader); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 8, max_transactions_behind); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_text(statement, 9, r->fields[8], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);

		SAFE_SQLITE3_STEP2(statement);
		rc=sqlite3_clear_bindings(statement); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_reset(statement); ASSERT_SQLITE_OK(rc, mydb);
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
	sqlite3_finalize(statement);
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
			" hostgroup_id=reader_hostgroup OR hostgroup_id=offline_hostgroup WHERE active=1 GROUP BY hostgroup_id, hostname, port";
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
	char *query=(char *)"SELECT hostgroup_id, hostname, port, gtid_port, weight, CASE status WHEN 0 THEN \"ONLINE\" WHEN 1 THEN \"SHUNNED\" WHEN 2 THEN \"OFFLINE_SOFT\" WHEN 3 THEN \"OFFLINE_HARD\" WHEN 4 THEN \"SHUNNED\" END, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers";
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
	char *query=(char *)"SELECT writer_hostgroup, reader_hostgroup, check_type, comment FROM mysql_replication_hostgroups";
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

SQLite3_result * MySQL_HostGroups_Manager::dump_table_mysql_galera_hostgroups() {
	wrlock();
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,max_writers,writer_is_also_reader,max_transactions_behind,comment FROM mysql_galera_hostgroups";
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
	mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	wrunlock();
	return resultset;
}

SQLite3_result * MySQL_HostGroups_Manager::dump_table_mysql_aws_aurora_hostgroups() {
	wrlock();
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT writer_hostgroup,reader_hostgroup,active,aurora_port,domain_name,max_lag_ms,"
					    "check_interval_ms,check_timeout_ms,writer_is_also_reader,new_reader_weight,add_lag_ms,min_lag_ms,lag_num_checks,comment FROM mysql_aws_aurora_hostgroups";
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

void MySQL_HostGroups_Manager::increase_reset_counter() {
	wrlock();
	status.myconnpoll_reset++;
	wrunlock();
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
			if (c->local_stmts->get_num_backend_stmts() > (unsigned int)GloMTH->variables.max_stmts_per_connection) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying MySQL_Connection %p, server %s:%d with status %d because has too many prepared statements\n", c, mysrvc->address, mysrvc->port, mysrvc->status);
//				delete c;
				mysrvc->ConnectionsUsed->add(c);
				destroy_MyConn_from_pool(c, false);
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

void MySQL_HostGroups_Manager::push_MyConn_to_pool_array(MySQL_Connection **ca, unsigned int cnt) {
	unsigned int i=0;
	MySQL_Connection *c=NULL;
	c=ca[i];
	wrlock();
	while (i<cnt) {
		push_MyConn_to_pool(c,false);
		i++;
		if (i<cnt)
			c=ca[i];
	}
	wrunlock();
}

MySrvC *MyHGC::get_random_MySrvC(char * gtid_uuid, uint64_t gtid_trxid, int max_lag_ms, MySQL_Session *sess) {
	MySrvC *mysrvc=NULL;
	unsigned int j;
	unsigned int sum=0;
	unsigned int TotalUsedConn=0;
	unsigned int l=mysrvs->cnt();
#ifdef USE_MYSRVC_ARRAY
#ifdef TEST_AURORA
	unsigned long long a1 = array_mysrvc_total/10000;
	array_mysrvc_total += l;
	unsigned long long a2 = array_mysrvc_total/10000;
	if (a2 > a1) {
		fprintf(stderr, "Total: %llu, Candidates: %llu\n", array_mysrvc_total-l, array_mysrvc_cands);
	}
#endif // TEST_AURORA
	MySrvC *mysrvcCandidates_static[32];
	MySrvC **mysrvcCandidates = mysrvcCandidates_static;
	unsigned int num_candidates = 0;
	if (l>32) {
		mysrvcCandidates = (MySrvC **)malloc(sizeof(MySrvC *)*l);
	}
#endif // USE_MYSRVC_ARRAY
	if (l) {
		//int j=0;
		for (j=0; j<l; j++) {
			mysrvc=mysrvs->idx(j);
			if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) { // consider this server only if ONLINE
				if (mysrvc->ConnectionsUsed->conns_length() < mysrvc->max_connections) { // consider this server only if didn't reach max_connections
					if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : mysql_thread___default_max_latency_ms*1000 ) ) { // consider the host only if not too far
						if (gtid_trxid) {
							if (MyHGM->gtid_exists(mysrvc, gtid_uuid, gtid_trxid)) {
								sum+=mysrvc->weight;
								TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
#ifdef USE_MYSRVC_ARRAY
								mysrvcCandidates[num_candidates]=mysrvc;
								num_candidates++;
#endif // USE_MYSRVC_ARRAY
							}
						} else {
							if (max_lag_ms >= 0) {
								if (max_lag_ms >= mysrvc->aws_aurora_current_lag_us/1000) {
									sum+=mysrvc->weight;
									TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
#ifdef USE_MYSRVC_ARRAY
									mysrvcCandidates[num_candidates]=mysrvc;
									num_candidates++;
#endif // USE_MYSRVC_ARRAY
								} else {
									sess->thread->status_variables.aws_aurora_replicas_skipped_during_query++;
								}
							} else {
								sum+=mysrvc->weight;
								TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
#ifdef USE_MYSRVC_ARRAY
								mysrvcCandidates[num_candidates]=mysrvc;
								num_candidates++;
#endif // USE_MYSRVC_ARRAY
							}
						}
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
						if (t > mysrvc->time_last_detected_error && (t - mysrvc->time_last_detected_error) > max_wait_sec) {
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
									if (gtid_trxid) {
										if (MyHGM->gtid_exists(mysrvc, gtid_uuid, gtid_trxid)) {
											sum+=mysrvc->weight;
											TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
#ifdef USE_MYSRVC_ARRAY
											mysrvcCandidates[num_candidates]=mysrvc;
											num_candidates++;
#endif // USE_MYSRVC_ARRAY
										}
									} else {
										if (max_lag_ms >= 0) {
											if (max_lag_ms >= mysrvc->aws_aurora_current_lag_us/1000) {
												sum+=mysrvc->weight;
												TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
#ifdef USE_MYSRVC_ARRAY
												mysrvcCandidates[num_candidates]=mysrvc;
												num_candidates++;
#endif // USE_MYSRVC_ARRAY
											}
										} else {
											sum+=mysrvc->weight;
											TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
#ifdef USE_MYSRVC_ARRAY
											mysrvcCandidates[num_candidates]=mysrvc;
											num_candidates++;
#endif // USE_MYSRVC_ARRAY
										}
									}
								}
							}
						}
					}
				}
			}
		}
#ifdef USE_MYSRVC_ARRAY
		if (max_lag_ms) { // we are using AWS Aurora, as this logic is implemented only here
			unsigned int min_num_replicas = sess->thread->variables.aurora_max_lag_ms_only_read_from_replicas;
			if (min_num_replicas) {
				if (num_candidates >= min_num_replicas) { // there are at least N replicas
					// we try to remove the writer
					unsigned int total_aws_aurora_current_lag_us=0;
					for (j=0; j<num_candidates; j++) {
						mysrvc = mysrvcCandidates[j];
						total_aws_aurora_current_lag_us += mysrvc->aws_aurora_current_lag_us;
					}
					if (total_aws_aurora_current_lag_us) { // we are just double checking that we don't have all servers with aws_aurora_current_lag_us==0
						for (j=0; j<num_candidates; j++) {
							mysrvc = mysrvcCandidates[j];
							if (mysrvc->aws_aurora_current_lag_us==0) {
								sum-=mysrvc->weight;
								TotalUsedConn-=mysrvc->ConnectionsUsed->conns_length();
								if (j < num_candidates-1) {
									mysrvcCandidates[j]=mysrvcCandidates[num_candidates-1];
								}
								num_candidates--;
							}
						}
					}
				}
			}
		}
#endif // USE_MYSRVC_ARRAY
		if (sum==0) {
			// per issue #531 , we try a desperate attempt to bring back online any shunned server
			// we do this lowering the maximum wait time to 10%
			// most of the follow code is copied from few lines above
			time_t t;
			t=time(NULL);
			int max_wait_sec = ( mysql_thread___shun_recovery_time_sec * 1000 >= mysql_thread___connect_timeout_server_max ? mysql_thread___connect_timeout_server_max/10000 - 1 : mysql_thread___shun_recovery_time_sec/10 );
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
							if (gtid_trxid) {
								if (MyHGM->gtid_exists(mysrvc, gtid_uuid, gtid_trxid)) {
									sum+=mysrvc->weight;
									TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
#ifdef USE_MYSRVC_ARRAY
									mysrvcCandidates[num_candidates]=mysrvc;
									num_candidates++;
#endif // USE_MYSRVC_ARRAY
								}
							} else {
								if (max_lag_ms >= 0) {
									if (max_lag_ms >= mysrvc->aws_aurora_current_lag_us/1000) {
										sum+=mysrvc->weight;
										TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
#ifdef USE_MYSRVC_ARRAY
										mysrvcCandidates[num_candidates]=mysrvc;
										num_candidates++;
#endif // USE_MYSRVC_ARRAY
									}
								} else {
									sum+=mysrvc->weight;
									TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
#ifdef USE_MYSRVC_ARRAY
									mysrvcCandidates[num_candidates]=mysrvc;
									num_candidates++;
#endif // USE_MYSRVC_ARRAY
								}
							}
						}
					}
				}
			}
		}
		if (sum==0) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC NULL because no backend ONLINE or with weight\n");
#ifdef USE_MYSRVC_ARRAY
			if (l>32) {
				free(mysrvcCandidates);
			}
			array_mysrvc_cands += num_candidates;
#endif // USE_MYSRVC_ARRAY
			return NULL; // if we reach here, we couldn't find any target
		}

		unsigned int New_sum=0;
		unsigned int New_TotalUsedConn=0;

		// we will now scan again to ignore overloaded servers
#ifdef USE_MYSRVC_ARRAY
		for (j=0; j<num_candidates; j++) {
			mysrvc = mysrvcCandidates[j];
#else
		for (j=0; j<l; j++) {
			mysrvc=mysrvs->idx(j);
			if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) { // consider this server only if ONLINE
#endif // USE_MYSRVC_ARRAY
				unsigned int len=mysrvc->ConnectionsUsed->conns_length();
#ifdef USE_MYSRVC_ARRAY
#else

				if (len < mysrvc->max_connections) { // consider this server only if didn't reach max_connections
					if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : mysql_thread___default_max_latency_ms*1000 ) ) { // consider the host only if not too far
#endif // USE_MYSRVC_ARRAY
						if ((len * sum) <= (TotalUsedConn * mysrvc->weight * 1.5 + 1)) {

#ifdef USE_MYSRVC_ARRAY
							New_sum+=mysrvc->weight;
							New_TotalUsedConn+=len;
#else
							if (gtid_trxid) {
								if (MyHGM->gtid_exists(mysrvc, gtid_uuid, gtid_trxid)) {
									New_sum+=mysrvc->weight;
									New_TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
								}
							} else {
								if (max_lag_ms >= 0) {
									if (max_lag_ms >= mysrvc->aws_aurora_current_lag_us/1000) {
										New_sum+=mysrvc->weight;
										New_TotalUsedConn+=len;
									}
								} else {
									New_sum+=mysrvc->weight;
									New_TotalUsedConn+=len;
								}
							}
#endif // USE_MYSRVC_ARRAY
#ifdef USE_MYSRVC_ARRAY
						} else {
							// remove the candidate
							if (j+1 < num_candidates) {
								mysrvcCandidates[j] = mysrvcCandidates[num_candidates-1];
							}
							j--;
							num_candidates--;
#endif // USE_MYSRVC_ARRAY
						}
#ifdef USE_MYSRVC_ARRAY
#else
					}
				}
			}
#endif // USE_MYSRVC_ARRAY
		}


		if (New_sum==0) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC NULL because no backend ONLINE or with weight\n");
#ifdef USE_MYSRVC_ARRAY
			if (l>32) {
				free(mysrvcCandidates);
			}
			array_mysrvc_cands += num_candidates;
#endif // USE_MYSRVC_ARRAY
			return NULL; // if we reach here, we couldn't find any target
		}

#ifdef USE_MYSRVC_ARRAY
		// latency awareness algorithm is enabled only when compiled with USE_MYSRVC_ARRAY
		if (sess->thread->variables.min_num_servers_lantency_awareness) {
			if (num_candidates >= sess->thread->variables.min_num_servers_lantency_awareness) {
				unsigned int servers_with_latency = 0;
				unsigned int total_latency_us = 0;
				// scan and verify that all servers have some latency
				for (j=0; j<num_candidates; j++) {
					mysrvc = mysrvcCandidates[j];
					if (mysrvc->current_latency_us) {
						servers_with_latency++;
						total_latency_us += mysrvc->current_latency_us;
					}
				}
				if (servers_with_latency == num_candidates) {
					// all servers have some latency.
					// That is good. If any server have no latency, something is wrong
					// and we will skip this algorithm
					sess->thread->status_variables.ConnPool_get_conn_latency_awareness++;
					unsigned int avg_latency_us = 0;
					avg_latency_us = total_latency_us/num_candidates;
					for (j=0; j<num_candidates; j++) {
						mysrvc = mysrvcCandidates[j];
						if (mysrvc->current_latency_us > avg_latency_us) {
							// remove the candidate
							if (j+1 < num_candidates) {
								mysrvcCandidates[j] = mysrvcCandidates[num_candidates-1];
							}
							j--;
							num_candidates--;
						}
					}
					// we scan again to adjust weight
					New_sum = 0;
					for (j=0; j<num_candidates; j++) {
						mysrvc = mysrvcCandidates[j];
						New_sum+=mysrvc->weight;
					}
				}
			}
		}
#endif // USE_MYSRVC_ARRAY


		unsigned int k;
		if (New_sum > 32768) {
			k=rand()%New_sum;
		} else {
			k=fastrand()%New_sum;
		}
		k++;
		New_sum=0;

#ifdef USE_MYSRVC_ARRAY
		for (j=0; j<num_candidates; j++) {
			mysrvc = mysrvcCandidates[j];
#else
		for (j=0; j<l; j++) {
			mysrvc=mysrvs->idx(j);
			if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) { // consider this server only if ONLINE
				unsigned int len=mysrvc->ConnectionsUsed->conns_length();
				if (len < mysrvc->max_connections) { // consider this server only if didn't reach max_connections
					if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : mysql_thread___default_max_latency_ms*1000 ) ) { // consider the host only if not too far
						if ((len * sum) <= (TotalUsedConn * mysrvc->weight * 1.5 + 1)) {
#endif // USE_MYSRVC_ARRAY
#ifdef USE_MYSRVC_ARRAY
							New_sum+=mysrvc->weight;
#else
							if (gtid_trxid) {
								if (MyHGM->gtid_exists(mysrvc, gtid_uuid, gtid_trxid)) {
									New_sum+=mysrvc->weight;
									//TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length(); // this line is a bug
								}
							} else {
								if (max_lag_ms >= 0) {
									if (max_lag_ms >= mysrvc->aws_aurora_current_lag_us/1000) {
										New_sum+=mysrvc->weight;
									}
								} else {
									New_sum+=mysrvc->weight;
								}
							}
#endif // USE_MYSRVC_ARRAY
							if (k<=New_sum) {
								proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC %p, server %s:%d\n", mysrvc, mysrvc->address, mysrvc->port);
#ifdef USE_MYSRVC_ARRAY
								if (l>32) {
									free(mysrvcCandidates);
								}
								array_mysrvc_cands += num_candidates;
#endif // USE_MYSRVC_ARRAY
								return mysrvc;
							}
#ifdef USE_MYSRVC_ARRAY
#else
						}
					}
				}
			}
#endif // USE_MYSRVC_ARRAY
		}
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySrvC NULL\n");
#ifdef USE_MYSRVC_ARRAY
	if (l>32) {
		free(mysrvcCandidates);
	}
	array_mysrvc_cands += num_candidates;
#endif // USE_MYSRVC_ARRAY
	return NULL; // if we reach here, we couldn't find any target
}

//unsigned int MySrvList::cnt() {
//	return servers->len;
//}

//MySrvC * MySrvList::idx(unsigned int i) { return (MySrvC *)servers->index(i); }

MySQL_Connection * MySrvConnList::get_random_MyConn(MySQL_Session *sess, bool ff) {
	MySQL_Connection * conn=NULL;
	unsigned int i;
	unsigned int l=conns_length();
	if (l && ff==false) {
		if (l>32768) {
			i=rand()%l;
		} else {
			i=fastrand()%l;
		}
		if (sess && sess->client_myds && sess->client_myds->myconn && sess->client_myds->myconn->userinfo) {
			// try to match schemaname AND username
			char *schema = sess->client_myds->myconn->userinfo->schemaname;
			char *username = sess->client_myds->myconn->userinfo->username;
			MySQL_Connection * client_conn = sess->client_myds->myconn;
			bool conn_found = false;
			unsigned int k;
			unsigned int options_matching_idx;
			bool options_matching_found = false;
			for (k = i; conn_found == false && k < l; k++) {
				conn = (MySQL_Connection *)conns->index(k);
				if (conn->match_tracked_options(client_conn)) {
					if (options_matching_found == false) {
						options_matching_found = true;
						options_matching_idx = k;
					}
					if (strcmp(conn->userinfo->schemaname,schema)==0 && strcmp(conn->userinfo->username,username)==0) {
						conn_found = true;
						i = k;
					}
				}
			}
			if (conn_found == false ) {
				for (k = 0; conn_found == false && k < i; k++) {
					conn = (MySQL_Connection *)conns->index(k);
					if (conn->match_tracked_options(client_conn)) {
						if (options_matching_found == false) {
							options_matching_found = true;
							options_matching_idx = k;
						}
						if (strcmp(conn->userinfo->schemaname,schema)==0 && strcmp(conn->userinfo->username,username)==0) {
							conn_found = true;
							i = k;
						}
					}
				}
			}
			if (conn_found == true) {
				conn=(MySQL_Connection *)conns->remove_index_fast(i);
			} else {
				if (options_matching_found == false) {
					// we must create a new connection
					conn = new MySQL_Connection();
					conn->parent=mysrvc;
					__sync_fetch_and_add(&MyHGM->status.server_connections_created, 1);
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
				} else {
					// we may consider creating a new connection
					unsigned int conns_free = mysrvc->ConnectionsFree->conns_length();
					unsigned int conns_used = mysrvc->ConnectionsUsed->conns_length();
					if ((conns_used > conns_free) && (mysrvc->max_connections > (conns_free/2 + conns_used/2)) ) {
						conn = new MySQL_Connection();
						conn->parent=mysrvc;
						__sync_fetch_and_add(&MyHGM->status.server_connections_created, 1);
						proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
					} else {
						conn=(MySQL_Connection *)conns->remove_index_fast(i);
					}
				}
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
		if (_myhgc->new_connections_now > (unsigned int) mysql_thread___throttle_connections_per_sec_to_hostgroup) {
			__sync_fetch_and_add(&MyHGM->status.server_connections_delayed, 1);
			return NULL;
		} else {
			conn = new MySQL_Connection();
			conn->parent=mysrvc;
			__sync_fetch_and_add(&MyHGM->status.server_connections_created, 1);
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
			return  conn;
		}
	}
	return NULL; // never reach here
}

MySQL_Connection * MySQL_HostGroups_Manager::get_MyConn_from_pool(unsigned int _hid, MySQL_Session *sess, bool ff, char * gtid_uuid, uint64_t gtid_trxid, int max_lag_ms) {
	MySQL_Connection * conn=NULL;
	wrlock();
	status.myconnpoll_get++;
	MyHGC *myhgc=MyHGC_lookup(_hid);
	MySrvC *mysrvc = NULL;
#ifdef TEST_AURORA
	for (int i=0; i<10; i++)
#endif // TEST_AURORA
	mysrvc = myhgc->get_random_MySrvC(gtid_uuid, gtid_trxid, max_lag_ms, sess);
	if (mysrvc) { // a MySrvC exists. If not, we return NULL = no targets
		conn=mysrvc->ConnectionsFree->get_random_MyConn(sess, ff);
		if (conn) {
			mysrvc->ConnectionsUsed->add(conn);
			status.myconnpoll_get_ok++;
			mysrvc->update_max_connections_used();
		}
	}
	wrunlock();
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, (conn ? conn->parent->address : "") , (conn ? conn->parent->port : 0 ));
	return conn;
}

void MySQL_HostGroups_Manager::destroy_MyConn_from_pool(MySQL_Connection *c, bool _lock) {
	bool to_del=true; // the default, legacy behavior
	MySrvC *mysrvc=(MySrvC *)c->parent;
	if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE && c->send_quit && queue.size() < __sync_fetch_and_add(&GloMTH->variables.connpoll_reset_queue_length,0)) {
		if (c->async_state_machine==ASYNC_IDLE) {
			// overall, the backend seems healthy and so it is the connection. Try to reset it
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Trying to reset MySQL_Connection %p, server %s:%d\n", c, mysrvc->address, mysrvc->port);
			to_del=false;
			//c->userinfo->set(mysql_thread___monitor_username,mysql_thread___monitor_password,mysql_thread___default_schema,NULL);
			queue.add(c);
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
						KillArgs *ka = new KillArgs(ui->username, auth_password, c->parent->address, c->parent->port, c->mysql->thread_id, KILL_CONNECTION, NULL);
						pthread_attr_t attr;
						pthread_attr_init(&attr);
						pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
						pthread_attr_setstacksize (&attr, 256*1024);
						pthread_t pt;
						if (pthread_create(&pt, &attr, &kill_query_thread, ka) != 0) {
							proxy_error("Thread creation\n");
							assert(0);
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

void MySQL_HostGroups_Manager::add(MySrvC *mysrvc, unsigned int _hid) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Adding MySrvC %p (%s:%d) for hostgroup %d\n", mysrvc, mysrvc->address, mysrvc->port, _hid);
	MyHGC *myhgc=MyHGC_lookup(_hid);
	myhgc->mysrvs->add(mysrvc);
}

void MySQL_HostGroups_Manager::replication_lag_action(int _hid, char *address, unsigned int port, int current_replication_lag) {
	GloAdmin->mysql_servers_wrlock();
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
						proxy_warning("Shunning server %s:%d from HG %u with replication lag of %d second\n", address, port, myhgc->hid, current_replication_lag);
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
							proxy_warning("Re-enabling server %s:%d from HG %u with replication lag of %d second\n", address, port, myhgc->hid, current_replication_lag);
						}
					}
				}
				goto __exit_replication_lag_action;
			}
		}
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
				if (mc->last_time_used && mc->last_time_used < _max_last_time_used) {
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
	if (incoming_group_replication_hostgroups) {
		delete incoming_group_replication_hostgroups;
		incoming_group_replication_hostgroups = NULL;
	}
	incoming_group_replication_hostgroups=s;
}

void MySQL_HostGroups_Manager::set_incoming_galera_hostgroups(SQLite3_result *s) {
	if (incoming_galera_hostgroups) {
		delete incoming_galera_hostgroups;
		incoming_galera_hostgroups = NULL;
	}
	incoming_galera_hostgroups=s;
}

void MySQL_HostGroups_Manager::set_incoming_aws_aurora_hostgroups(SQLite3_result *s) {
	if (incoming_aws_aurora_hostgroups) {
		delete incoming_aws_aurora_hostgroups;
		incoming_aws_aurora_hostgroups = NULL;
	}
	incoming_aws_aurora_hostgroups=s;
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
			if (mysrvc->status!=MYSQL_SERVER_STATUS_ONLINE) {
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
					j["options"]["charset_name"] = _my->options.charset_name;
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

SQLite3_result * MySQL_HostGroups_Manager::SQL3_Connection_Pool(bool _reset) {
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
	const char *Q1=(char *)"SELECT hostgroup_id,status FROM mysql_replication_hostgroups JOIN mysql_servers ON hostgroup_id=writer_hostgroup AND hostname='%s' AND port=%d AND status<>3";
	const char *Q1B=(char *)"SELECT hostgroup_id,status FROM ( SELECT DISTINCT writer_hostgroup FROM mysql_replication_hostgroups JOIN mysql_servers WHERE (hostgroup_id=writer_hostgroup OR reader_hostgroup=hostgroup_id) AND hostname='%s' AND port=%d ) LEFT JOIN mysql_servers ON hostgroup_id=writer_hostgroup AND hostname='%s' AND port=%d";
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
	char *query=(char *)malloc(strlen(hostname)*2+strlen(Q3A)+64);
	sprintf(query,Q1,hostname,port);

	int cols=0;
	char *error=NULL;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	wrlock();
	// we run this query holding the mutex
	// we minimum the time we hold the mutex, as connection pool is being locked
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
					switch (mysrvc->status) {
						case MYSQL_SERVER_STATUS_SHUNNED:
							if (mysrvc->shunned_automatic==false) {
								break;
							}
						case MYSQL_SERVER_STATUS_ONLINE:
							if (mysrvc->status == MYSQL_SERVER_STATUS_ONLINE) {
								ret = true;
							}
							mysrvc->status=MYSQL_SERVER_STATUS_SHUNNED;
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

	int writer_is_also_reader=0;
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
				q=(char *)"INSERT OR IGNORE INTO mysql_servers_incoming (hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) SELECT %d,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers_incoming WHERE hostgroup_id=%d AND hostname='%s' AND port=%d";
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

void MySQL_HostGroups_Manager::update_galera_set_offline(char *_hostname, int _port, int _writer_hostgroup, char *_error) {
	bool set_offline = false;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=NULL;
	char *q=NULL;
	char *error=NULL;
	q=(char *)"SELECT hostgroup_id FROM mysql_servers JOIN mysql_galera_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=backup_writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE hostname='%s' AND port=%d";
	query=(char *)malloc(strlen(q)+strlen(_hostname)+1024); // increased this buffer as it is used for other queries too
	sprintf(query,q,_hostname,_port);
	mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		free(error);
		error=NULL;
	}
	free(query);
	GloAdmin->mysql_servers_wrlock();
	if (resultset) { // we lock only if needed
		if (resultset->rows_count) {
			set_offline = true;
		} else { // the server is already offline, but we check if needs to be taken back online
			SQLite3_result *numw_result = NULL;
			q=(char *)"SELECT 1 FROM mysql_servers WHERE hostgroup_id=%d AND status=0";
			query=(char *)malloc(strlen(q) + (sizeof(_writer_hostgroup) * 8 + 1));
			sprintf(query,q,_writer_hostgroup);
			mydb->execute_statement(query, &error , &cols , &affected_rows , &numw_result);
			free(query);
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
			q=(char *)"UPDATE OR IGNORE mysql_servers_incoming SET hostgroup_id=%d WHERE hostname='%s' AND port=%d AND hostgroup_id in (%d, %d, %d)";
			query=(char *)malloc(strlen(q)+strlen(_hostname)+128);
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
				proxy_warning("Galera: setting host %s:%d offline because: %s\n", _hostname, _port, _error);
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
			}
			free(query);
		}
	}
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
			GloAdmin->mysql_servers_wrlock();
			mydb->execute("DELETE FROM mysql_servers_incoming");
			mydb->execute("INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers");
			q=(char *)"UPDATE OR IGNORE mysql_servers_incoming SET hostgroup_id=%d WHERE hostname='%s' AND port=%d AND hostgroup_id in (%d, %d, %d)";
			query=(char *)malloc(strlen(q)+strlen(_hostname)+512);
			sprintf(query, q, info->reader_hostgroup, _hostname, _port, info->writer_hostgroup, info->backup_writer_hostgroup, info->offline_hostgroup);
			mydb->execute(query);
			//free(query);
			q=(char *)"DELETE FROM mysql_servers_incoming WHERE hostname='%s' AND port=%d AND hostgroup_id in (%d, %d, %d) FROM mysql_galera_hostgroups WHERE writer_hostgroup=%d)";
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
	std::mutex local_mutex;
	std::lock_guard<std::mutex> lock(local_mutex);
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=NULL;
	char *q=NULL;
	char *error=NULL;
	q=(char *)"SELECT hostgroup_id FROM mysql_servers JOIN mysql_galera_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup OR hostgroup_id=backup_writer_hostgroup OR hostgroup_id=offline_hostgroup WHERE hostname='%s' AND port=%d";
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
					if (GloMTH->variables.hostgroup_manager_verbose > 1) {
						proxy_info("Galera: max_writers=%d , moving %d nodes from writer HG %d to backup HG %d\n", info->max_writers, to_move, info->writer_hostgroup, info->backup_writer_hostgroup);
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
							/*
							char * s0 = GloMyMon->galera_find_last_node(info->writer_hostgroup);
							if (s0) {
								std::string s = string(s0);
								std::size_t found=s.find_last_of(":");
								std::string host=s.substr(0,found);
								std::string port=s.substr(found+1);
								int port_n = atoi(port.c_str());
								proxy_info("Galera: trying to use server %s:%s as a writer for HG %d\n", host.c_str(), port.c_str(), info->writer_hostgroup);
								q=(char *)"UPDATE OR REPLACE mysql_servers_incoming SET status=0, hostgroup_id=%d WHERE hostgroup_id IN (%d, %d, %d, %d)  AND hostname='%s' AND port=%d";
								query=(char *)malloc(strlen(q) + s.length() + 512);
								sprintf(query,q,info->writer_hostgroup, info->writer_hostgroup, info->backup_writer_hostgroup, info->reader_hostgroup, info->offline_hostgroup, host.c_str(), port_n);
								mydb->execute(query);
								free(query);
								bool writer_is_also_reader = info->writer_is_also_reader;
								if (writer_is_also_reader) {
									int read_HG = info->reader_hostgroup;
									q=(char *)"INSERT OR IGNORE INTO mysql_servers_incoming (hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) SELECT %d,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers_incoming WHERE hostgroup_id=%d AND hostname='%s' AND port=%d";
									query=(char *)malloc(strlen(q) + s.length() + 128);
									sprintf(query,q,read_HG, info->writer_hostgroup, host.c_str(), port_n);
									mydb->execute(query);
									free(query);
								}
								free(s0);
							}
							*/
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
	pthread_mutex_unlock(&Galera_Info_mutex);
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
		char **pta=(char **)malloc(sizeof(char *)*11);
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

		time_t __now;
		time(&__now);
		unsigned long long curtime=monotonic_time();
		time_t seen_time;

		seen_time= __now - curtime/1000000 + first_seen/1000000;
		sprintf(buf,"%ld", seen_time);
		pta[8]=strdup(buf);

		seen_time= __now - curtime/1000000 + last_seen/1000000;
		sprintf(buf,"%ld", seen_time);
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
		for (i=0;i<11;i++) {
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
	SQLite3_result *result=new SQLite3_result(11);
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
	//rc=sqlite3_prepare_v2(mydb3, query, -1, &statement, 0);
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
		rc=sqlite3_bind_int64(statement, 1, writer_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 2, reader_hostgroup); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 3, active); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 4, aurora_port); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_text(statement, 5, r->fields[4], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 6, max_lag_ms); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 7, check_interval_ms); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 8, check_timeout_ms); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 9, writer_is_also_reader); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 10, new_reader_weight); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 11, add_lag_ms); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 12, min_lag_ms); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_int64(statement, 13, lag_num_checks); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_bind_text(statement, 14, r->fields[13], -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);

		SAFE_SQLITE3_STEP2(statement);
		rc=sqlite3_clear_bindings(statement); ASSERT_SQLITE_OK(rc, mydb);
		rc=sqlite3_reset(statement); ASSERT_SQLITE_OK(rc, mydb);
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
	sqlite3_finalize(statement);
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
	{
		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		char *query=(char *)"SELECT writer_hostgroup, reader_hostgroup, hostname, port, MAX(use_ssl) use_ssl , max_lag_ms , check_interval_ms , check_timeout_ms , "
					        "add_lag_ms , min_lag_ms , lag_num_checks  FROM mysql_servers JOIN mysql_aws_aurora_hostgroups ON hostgroup_id=writer_hostgroup OR "
					        "hostgroup_id=reader_hostgroup WHERE active=1 AND status NOT IN (2,3) GROUP BY writer_hostgroup, hostname, port";
		mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		if (resultset) {
			if (GloMyMon->AWS_Aurora_Hosts_resultset) {
				delete GloMyMon->AWS_Aurora_Hosts_resultset;
			}
			GloMyMon->AWS_Aurora_Hosts_resultset=resultset;
			GloMyMon->AWS_Aurora_Hosts_resultset_checksum=resultset->raw_checksum();
		}
	}
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
					if (mysrvc->status == MYSQL_SERVER_STATUS_ONLINE) {
						if (verbose) {
							proxy_warning("Shunning server %s:%d from HG %u with replication lag of %f microseconds\n", address, port, myhgc->hid, current_replication_lag_ms);
						}
						mysrvc->status = MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG;
					}
				} else {
					if (mysrvc->status == MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) {
						if (verbose) {
							proxy_warning("Re-enabling server %s:%d from HG %u with replication lag of %f microseconds\n", address, port, myhgc->hid, current_replication_lag_ms);
						}
						mysrvc->status = MYSQL_SERVER_STATUS_ONLINE;
					}
				}
				mysrvc->aws_aurora_current_lag_us = current_replication_lag_ms * 1000;
				if (mysrvc->status == MYSQL_SERVER_STATUS_ONLINE || mysrvc->status == MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) {
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
								if (mysrvc->status == MYSQL_SERVER_STATUS_OFFLINE_HARD) {
									mysrvc->status = MYSQL_SERVER_STATUS_ONLINE;
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
	//free(query);

	if (resultset) {
/*
		// let's get info about this cluster
		pthread_mutex_lock(&AWS_Aurora_Info_mutex);
		std::map<int , AWS_Aurora_Info *>::iterator it2;
		it2 = AWS_Aurora_Info_Map.find(_writer_hostgroup);
		AWS_Aurora_Info *info=NULL;
		if (it2!=AWS_Aurora_Info_Map.end()) {
			info=it2->second;
			writer_is_also_reader=info->writer_is_also_reader;
			new_reader_weight = info->new_reader_weight;
			read_HG = info->reader_hostgroup;
			//need_converge=info->need_converge;
			//info->need_converge=false;
			//max_writers = info->max_writers;
		}
		pthread_mutex_unlock(&AWS_Aurora_Info_mutex);
*/
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
/*
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
*/
//		if (need_converge==false) {
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
//		}
	}

	if (resultset) {
		// If we reach there, there is some action to perform.
		// This should be the case most of the time,
		// because the calling function knows if an action is required.
		if (resultset->rows_count) {
			//need_converge=false;

			GloAdmin->mysql_servers_wrlock();
			mydb->execute("DELETE FROM mysql_servers_incoming");
			q=(char *)"INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers WHERE hostgroup_id=%d";
			sprintf(query,q,_rhid);
			mydb->execute(query);
			q=(char *)"INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers WHERE hostgroup_id=%d AND hostname='%s%s' AND port=%d";
			sprintf(query, q, _writer_hostgroup, _server_id, domain_name, aurora_port);
			mydb->execute(query);
			q=(char *)"UPDATE OR IGNORE mysql_servers_incoming SET hostgroup_id=%d WHERE hostname='%s%s' AND port=%d AND hostgroup_id<>%d";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+1024); // increased this buffer as it is used for other queries too
			sprintf(query, q, _writer_hostgroup, _server_id, domain_name, aurora_port, _writer_hostgroup);
			mydb->execute(query);
			//free(query);
			q=(char *)"DELETE FROM mysql_servers_incoming WHERE hostname='%s%s' AND port=%d AND hostgroup_id<>%d";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query, q, _server_id, domain_name, aurora_port, _writer_hostgroup);
			mydb->execute(query);
			//free(query);
			q=(char *)"UPDATE mysql_servers_incoming SET status=0 WHERE hostname='%s%s' AND port=%d AND hostgroup_id=%d";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query, q, _server_id, domain_name, aurora_port, _writer_hostgroup);
			mydb->execute(query);

			// we need to move the old writer into the reader HG
			q=(char *)"DELETE FROM mysql_servers_incoming WHERE status=3 AND hostgroup_id=%d";
			sprintf(query,q,_rhid);
			mydb->execute(query);
			q=(char *)"INSERT OR IGNORE INTO mysql_servers_incoming SELECT %d, hostname, port, gtid_port, %d, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers WHERE hostgroup_id=%d AND status=0";
			sprintf(query,q,_rhid, new_reader_weight, _whid);
			mydb->execute(query);

			//free(query);
			if (writer_is_also_reader && read_HG>=0) {
				q=(char *)"INSERT OR IGNORE INTO mysql_servers_incoming (hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment) SELECT %d,hostname,port,gtid_port,status,weight,compression,max_connections,max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers_incoming WHERE hostgroup_id=%d AND hostname='%s%s' AND port=%d";
				sprintf(query, q, read_HG, _writer_hostgroup, _server_id, domain_name, aurora_port);
				mydb->execute(query);
				q = (char *)"UPDATE mysql_servers_incoming SET weight=%d WHERE hostgroup_id=%d AND hostname='%s%s' AND port=%d";
				sprintf(query, q, new_reader_weight, read_HG, _server_id, domain_name, aurora_port);
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
/*
				SQLite3_result *resultset2=NULL;
				q=(char *)"SELECT writer_hostgroup, reader_hostgroup FROM mysql_aws_aurora_hostgroups WHERE writer_hostgroup=%d";
				sprintf(query,q,_writer_hostgroup);
				mydb->execute_statement(query, &error, &cols , &affected_rows , &resultset2);
				if (resultset2) {
					if (resultset2->rows_count) {
						for (std::vector<SQLite3_row *>::iterator it = resultset2->rows.begin() ; it != resultset2->rows.end(); ++it) {
							SQLite3_row *r=*it;
							int writer_hostgroup=atoi(r->fields[0]);
							int reader_hostgroup=atoi(r->fields[1]);
*/
							q=(char *)"DELETE FROM mysql_servers WHERE hostgroup_id IN (%d , %d)";
							sprintf(query,q,_whid,_rhid);
							mydb->execute(query);
							generate_mysql_servers_table(&_whid);
							generate_mysql_servers_table(&_rhid);
/*
						}
					}
					delete resultset2;
					resultset2=NULL;
				}
*/
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
			GloAdmin->mysql_servers_wrlock();
			mydb->execute("DELETE FROM mysql_servers_incoming");
			q=(char *)"INSERT INTO mysql_servers_incoming SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers WHERE hostname<>'%s%s'";
			sprintf(query,q, _server_id, domain_name);
			mydb->execute(query);
			q=(char *)"INSERT INTO mysql_servers_incoming (hostgroup_id, hostname, port, weight) VALUES (%d, '%s%s', %d, %d)";
			sprintf(query,q, _writer_hostgroup, _server_id, domain_name, aurora_port, new_reader_weight);
			mydb->execute(query);
			if (writer_is_also_reader && read_HG>=0) {
				q=(char *)"INSERT INTO mysql_servers_incoming (hostgroup_id, hostname, port, weight) VALUES (%d, '%s%s', %d, %d)";
				sprintf(query, q, read_HG, _server_id, domain_name, aurora_port, new_reader_weight);
				mydb->execute(query);
			}
			proxy_info("AWS Aurora: setting new auto-discovered host %s%s:%d as writer\n", _server_id, domain_name, aurora_port);
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
			query = NULL;
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
	q=(char *)"SELECT hostgroup_id FROM mysql_servers JOIN mysql_aws_aurora_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE hostname='%s%s' AND port=%d AND status<>3";
	query=(char *)malloc(strlen(q)+strlen(_server_id)+strlen(domain_name)+32);
	sprintf(query, q, _server_id, domain_name, aurora_port);
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
			q=(char *)"UPDATE OR IGNORE mysql_servers_incoming SET hostgroup_id=%d WHERE hostname='%s%s' AND port=%d AND hostgroup_id<>%d";
			query=(char *)malloc(strlen(q)+strlen(_server_id)+strlen(domain_name)+512);
			sprintf(query, q, _rhid, _server_id, domain_name, aurora_port, _rhid);
			mydb->execute(query);
			//free(query);
			q=(char *)"DELETE FROM mysql_servers_incoming WHERE hostname='%s%s' AND port=%d AND hostgroup_id<>%d";
			//query=(char *)malloc(strlen(q)+strlen(_hostname)+64);
			sprintf(query, q, _server_id, domain_name, aurora_port, _rhid);
			mydb->execute(query);
			//free(query);
			q=(char *)"UPDATE mysql_servers_incoming SET status=0 WHERE hostname='%s%s' AND port=%d AND hostgroup_id=%d";
			sprintf(query, q, _server_id, domain_name, aurora_port, _rhid);
			mydb->execute(query);
			//free(query);
			//converge_galera_config(_writer_hostgroup);
			commit();
			wrlock();
/*
			SQLite3_result *resultset2=NULL;
			q=(char *)"SELECT writer_hostgroup, reader_hostgroup FROM mysql_galera_hostgroups WHERE writer_hostgroup=%d";
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
*/
						q=(char *)"DELETE FROM mysql_servers WHERE hostgroup_id IN (%d , %d)";
						sprintf(query,q,_whid,_rhid);
						mydb->execute(query);
						generate_mysql_servers_table(&_whid);
						generate_mysql_servers_table(&_rhid);
/*
						generate_mysql_servers_table(&writer_hostgroup);
						generate_mysql_servers_table(&backup_writer_hostgroup);
						generate_mysql_servers_table(&reader_hostgroup);
						generate_mysql_servers_table(&offline_hostgroup);
					}
				}
				delete resultset2;
				resultset2=NULL;
			}
*/
			wrunlock();
			GloAdmin->mysql_servers_wrunlock();
			free(query);
		} else {
			// we couldn't find the server
			// autodiscovery algorithm here
			char *full_hostname=(char *)malloc(strlen(_server_id)+strlen(domain_name)+1);
			sprintf(full_hostname, "%s%s", _server_id, domain_name);
			bool found = false;
			GloAdmin->mysql_servers_wrlock();
			unsigned int max_max_connections = 1000;
			unsigned int max_use_ssl = 0;
			wrlock();
			MyHGC *myhgc=MyHGC_lookup(_rhid);
			{
				for (int j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
					MySrvC *mysrvc=(MySrvC *)myhgc->mysrvs->servers->index(j);
					if (mysrvc->max_connections > max_max_connections) {
						max_max_connections = mysrvc->max_connections;
					}
					if (mysrvc->use_ssl > max_use_ssl) {
						max_use_ssl = mysrvc->use_ssl;
					}
					if (strcmp(mysrvc->address,full_hostname)==0 && mysrvc->port==aurora_port) {
						found = true;
						// we found the server, we just configure it online if it was offline
						if (mysrvc->status == MYSQL_SERVER_STATUS_OFFLINE_HARD) {
							mysrvc->status = MYSQL_SERVER_STATUS_ONLINE;
						}
					}
				}
				if (found == false) { // the server doesn't exist
					MySrvC *mysrvc=new MySrvC(full_hostname, aurora_port, 0, new_reader_weight, MYSQL_SERVER_STATUS_ONLINE, 0, max_max_connections, 0, max_use_ssl, 0, (char *)""); // add new fields here if adding more columns in mysql_servers
					proxy_info("Adding new discovered AWS Aurora node %s:%d with: hostgroup=%d, weight=%d, max_connections=%d\n" , full_hostname, aurora_port, _rhid , new_reader_weight, max_max_connections);
					add(mysrvc,_rhid);
				}
				q=(char *)"DELETE FROM mysql_servers WHERE hostgroup_id IN (%d , %d)";
				query = (char *)malloc(strlen(q)+64);
				sprintf(query,q,_whid,_rhid);
				mydb->execute(query);
				generate_mysql_servers_table(&_whid);
				generate_mysql_servers_table(&_rhid);
				free(query);
			}
			wrunlock();
			// it is now time to build a new structure in Monitor
			pthread_mutex_lock(&AWS_Aurora_Info_mutex);
			pthread_mutex_lock(&GloMyMon->aws_aurora_mutex);
			{
				char *error=NULL;
				int cols=0;
				int affected_rows=0;
				SQLite3_result *resultset=NULL;
				char *query=(char *)"SELECT writer_hostgroup, reader_hostgroup, hostname, port, MAX(use_ssl) use_ssl , max_lag_ms , check_interval_ms , check_timeout_ms, add_lag_ms, min_lag_ms, lag_num_checks FROM mysql_servers JOIN mysql_aws_aurora_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE active=1 AND status NOT IN (2,3) GROUP BY hostname, port";
				mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
				if (resultset) {
					if (GloMyMon->AWS_Aurora_Hosts_resultset) {
						delete GloMyMon->AWS_Aurora_Hosts_resultset;
					}
					GloMyMon->AWS_Aurora_Hosts_resultset=resultset;
					GloMyMon->AWS_Aurora_Hosts_resultset_checksum=resultset->raw_checksum();
				}
			}
			pthread_mutex_unlock(&GloMyMon->aws_aurora_mutex);
			pthread_mutex_unlock(&AWS_Aurora_Info_mutex);
			GloAdmin->mysql_servers_wrunlock();
			free(full_hostname);
		}
	}
	if (resultset) {
		delete resultset;
		resultset=NULL;
	}
	free(domain_name);
}


