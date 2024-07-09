#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "PgSQL_HostGroups_Manager.h"
#include "proxysql.h"
#include "cpp.h"

#include "MySQL_PreparedStatement.h"
#include "PgSQL_Data_Stream.h"

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

#ifdef TEST_AURORA
static unsigned long long array_mysrvc_total = 0;
static unsigned long long array_mysrvc_cands = 0;
#endif // TEST_AURORA

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

class PgSQL_SrvConnList;
class PgSQL_SrvC;
class PgSQL_SrvList;
class PgSQL_HGC;

//static struct ev_async * gtid_ev_async;

static pthread_mutex_t ev_loop_mutex;

//static std::unordered_map <string, Gtid_Server_Info *> gtid_map;

const int PgSQL_ERRORS_STATS_FIELD_NUM = 11;

#if 0
static std::string gtid_executed_to_string(gtid_set_t & gtid_executed);
static void addGtid(const gtid_t & gtid, gtid_set_t & gtid_executed);

static void gtid_async_cb(struct ev_loop *loop, struct ev_async *watcher, int revents) {
	if (glovars.shutdown) {
		ev_break(loop);
	}
	pthread_mutex_lock(&ev_loop_mutex);
	PgHGM->gtid_missing_nodes = false;
	PgHGM->generate_pgsql_gtid_executed_tables();
	pthread_mutex_unlock(&ev_loop_mutex);
	return;
}

static void gtid_timer_cb (struct ev_loop *loop, struct ev_timer *timer, int revents) {
	if (GloMTH == nullptr) { return; }
	ev_timer_stop(loop, timer);
	ev_timer_set(timer, __sync_add_and_fetch(&GloMTH->variables.binlog_reader_connect_retry_msec,0)/1000, 0);
	if (glovars.shutdown) {
		ev_break(loop);
	}
	if (PgHGM->gtid_missing_nodes) {
		pthread_mutex_lock(&ev_loop_mutex);
		PgHGM->gtid_missing_nodes = false;
		PgHGM->generate_pgsql_gtid_executed_tables();
		pthread_mutex_unlock(&ev_loop_mutex);
	}
	ev_timer_start(loop, timer);
	return;
}
#endif // 0

static int wait_for_pgsql(MYSQL *mysql, int status) {
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
 * @param hid Hostgroup for which the 'servers_defaults' is defined in 'pgsql_hostgroup_attributes'. Used for
 *  error logging.
 * @param key The key for the value to be extracted.
 * @param val_check A validation function, checks if the value is within a expected range.
 *
 * @return The value extracted from the supplied JSON. In case of error '-1', and error cause is logged.
 */
template <typename T, typename std::enable_if<std::is_integral<T>::value, bool>::type = true>
T PgSQL_j_get_srv_default_int_val(
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
					"Invalid value %ld supplied for 'pgsql_hostgroup_attributes.servers_defaults.%s' for hostgroup %d."
						" Value NOT UPDATED.\n",
					static_cast<int64_t>(val), key.c_str(), hid
				);
			}
		} else {
			proxy_error(
				"Invalid type '%s'(%hhu) supplied for 'pgsql_hostgroup_attributes.servers_defaults.%s' for hostgroup %d."
					" Value NOT UPDATED.\n",
				type_name, static_cast<std::uint8_t>(val_type), key.c_str(), hid
			);
		}
	}

	return static_cast<T>(-1);
}

#if 0
static void reader_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
	pthread_mutex_lock(&ev_loop_mutex);
	if (revents & EV_READ) {
		PgSQL_GTID_Server_Data *sd = (PgSQL_GTID_Server_Data *)w->data;
		bool rc = true;
		rc = sd->readall();
		if (rc == false) {
			//delete sd;
			std::string s1 = sd->address;
			s1.append(":");
			s1.append(std::to_string(sd->pgsql_port));
			PgHGM->gtid_missing_nodes = true;
			proxy_warning("GTID: failed to connect to ProxySQL binlog reader on port %d for server %s:%d\n", sd->port, sd->address, sd->pgsql_port);
			std::unordered_map <string, PgSQL_GTID_Server_Data *>::iterator it2;
			it2 = PgHGM->gtid_map.find(s1);
			if (it2 != PgHGM->gtid_map.end()) {
				//PgHGM->gtid_map.erase(it2);
				it2->second = NULL;
				delete sd;
			}
			ev_io_stop(PgHGM->gtid_ev_loop, w);
			free(w);
		} else {
			sd->dump();
		}
	}
	pthread_mutex_unlock(&ev_loop_mutex);
}

static void connect_cb(EV_P_ ev_io *w, int revents) {
	pthread_mutex_lock(&ev_loop_mutex);
	struct ev_io * c = w;
	if (revents & EV_WRITE) {
		int optval = 0;
		socklen_t optlen = sizeof(optval);
		if ((getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1) ||
			(optval != 0)) {
			/* Connection failed; try the next address in the list. */
			//int errnum = optval ? optval : errno;
			ev_io_stop(PgHGM->gtid_ev_loop, w);
			close(w->fd);
			PgHGM->gtid_missing_nodes = true;
			PgSQL_GTID_Server_Data * custom_data = (PgSQL_GTID_Server_Data *)w->data;
			PgSQL_GTID_Server_Data *sd = custom_data;
			std::string s1 = sd->address;
			s1.append(":");
			s1.append(std::to_string(sd->pgsql_port));
			proxy_warning("GTID: failed to connect to ProxySQL binlog reader on port %d for server %s:%d\n", sd->port, sd->address, sd->pgsql_port);
			std::unordered_map <string, PgSQL_GTID_Server_Data *>::iterator it2;
			it2 = PgHGM->gtid_map.find(s1);
			if (it2 != PgHGM->gtid_map.end()) {
				//PgHGM->gtid_map.erase(it2);
				it2->second = NULL;
				delete sd;
			}
			//delete custom_data;
			free(c);
		} else {
			ev_io_stop(PgHGM->gtid_ev_loop, w);
			int fd=w->fd;
			struct ev_io * new_w = (struct ev_io*) malloc(sizeof(struct ev_io));
			new_w->data = w->data;
			PgSQL_GTID_Server_Data * custom_data = (PgSQL_GTID_Server_Data *)new_w->data;
			custom_data->w = new_w;
			free(w);
			ev_io_init(new_w, reader_cb, fd, EV_READ);
			ev_io_start(PgHGM->gtid_ev_loop, new_w);
		}
	}
	pthread_mutex_unlock(&ev_loop_mutex);
}

static struct ev_io * new_connector(char *address, uint16_t gtid_port, uint16_t pgsql_port) {
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
			PgSQL_GTID_Server_Data * custom_data = new PgSQL_GTID_Server_Data(c, address, gtid_port, pgsql_port);
			c->data = (void *)custom_data;
			return c;
		}
		/* else error */
	}
	return NULL;
}



PgSQL_GTID_Server_Data::PgSQL_GTID_Server_Data(struct ev_io *_w, char *_address, uint16_t _port, uint16_t _pgsql_port) {
	active = true;
	w = _w;
	size = 1024; // 1KB buffer
	data = (char *)malloc(size);
	memset(uuid_server, 0, sizeof(uuid_server));
	pos = 0;
	len = 0;
	address = strdup(_address);
	port = _port;
	pgsql_port = _pgsql_port;
	events_read = 0;
}

void PgSQL_GTID_Server_Data::resize(size_t _s) {
	char *data_ = (char *)malloc(_s);
	memcpy(data_, data, (_s > size ? size : _s));
	size = _s;
	free(data);
	data = data_;
}

PgSQL_GTID_Server_Data::~PgSQL_GTID_Server_Data() {
	free(address);
	free(data);
}

bool PgSQL_GTID_Server_Data::readall() {
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


bool PgSQL_GTID_Server_Data::gtid_exists(char *gtid_uuid, uint64_t gtid_trxid) {
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

void PgSQL_GTID_Server_Data::read_all_gtids() {
		while (read_next_gtid()) {
		}
	}

void PgSQL_GTID_Server_Data::dump() {
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

bool PgSQL_GTID_Server_Data::writeout() {
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

bool PgSQL_GTID_Server_Data::read_next_gtid() {
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
		memcpy(bs, data+pos+3, l-3);
		bs[l-3] = '\0';
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
		rec_msg[l] = 0;
		//int rc = write(1,data+pos,l+1);
		//fprintf(stdout,"%s\n", rec_msg);
		if (rec_msg[0]=='I') {
			//char rec_uuid[80];
			uint64_t rec_trxid = 0;
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

static std::string gtid_executed_to_string(gtid_set_t& gtid_executed) {
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
	// Extract latest comma only in case 'gtid_executed' isn't empty
	if (gtid_set.empty() == false) {
		gtid_set.pop_back();
	}
	return gtid_set;
}



static void addGtid(const gtid_t& gtid, gtid_set_t& gtid_executed) {
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
	PgHGM->gtid_ev_loop = ev_loop_new (EVBACKEND_POLL | EVFLAG_NOENV);
	if (PgHGM->gtid_ev_loop == NULL) {
		proxy_error("could not initialise GTID sync loop\n");
		exit(EXIT_FAILURE);
	}
	//ev_async_init(gtid_ev_async, gtid_async_cb);
	//ev_async_start(gtid_ev_loop, gtid_ev_async);
	PgHGM->gtid_ev_timer = (struct ev_timer *)malloc(sizeof(struct ev_timer));
	ev_async_init(PgHGM->gtid_ev_async, gtid_async_cb);
	ev_async_start(PgHGM->gtid_ev_loop, PgHGM->gtid_ev_async);
	//ev_timer_init(PgHGM->gtid_ev_timer, gtid_timer_cb, __sync_add_and_fetch(&GloMTH->variables.binlog_reader_connect_retry_msec,0)/1000, 0);
	ev_timer_init(PgHGM->gtid_ev_timer, gtid_timer_cb, 3, 0);
	ev_timer_start(PgHGM->gtid_ev_loop, PgHGM->gtid_ev_timer);
	//ev_ref(gtid_ev_loop);
	ev_run(PgHGM->gtid_ev_loop, 0);
	//sleep(1000);
	return NULL;
}
#endif // 0

//static void * HGCU_thread_run() {
static void * HGCU_thread_run() {
	PtrArray *conn_array=new PtrArray();
	while(1) {
		PgSQL_Connection *myconn= NULL;
		myconn = (PgSQL_Connection *)PgHGM->queue.remove();
		if (myconn==NULL) {
			// intentionally exit immediately
			delete conn_array;
			return NULL;
		}
		conn_array->add(myconn);
		while (PgHGM->queue.size()) {
			myconn=(PgSQL_Connection *)PgHGM->queue.remove();
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
			PgHGM->increase_reset_counter();
			myconn=(PgSQL_Connection *)conn_array->index(i);
			if (myconn->pgsql->net.pvio && myconn->pgsql->net.fd && myconn->pgsql->net.buff) {
				PgSQL_Connection_userinfo *userinfo = myconn->userinfo;
				char *auth_password = NULL;
				if (userinfo->password) {
					if (userinfo->password[0]=='*') { // we don't have the real password, let's pass sha1
						auth_password=userinfo->sha1_pass;
					} else {
						auth_password=userinfo->password;
					}
				}
				//async_exit_status = pgsql_change_user_start(&ret_bool,pgsql,_ui->username, auth_password, _ui->schemaname);
				// we first reset the charset to a default one.
				// this to solve the problem described here:
				// https://github.com/sysown/proxysql/pull/3249#issuecomment-761887970
				if (myconn->pgsql->charset->nr >= 255)
					mysql_options(myconn->pgsql, MYSQL_SET_CHARSET_NAME, myconn->pgsql->charset->csname);
				statuses[i]=mysql_change_user_start(&ret[i], myconn->pgsql, myconn->userinfo->username, auth_password, myconn->userinfo->schemaname);
				if (myconn->pgsql->net.pvio==NULL || myconn->pgsql->net.fd==0 || myconn->pgsql->net.buff==NULL) {
					statuses[i]=0; ret[i]=1;
				}
			} else {
				statuses[i]=0;
				ret[i]=1;
			}
		}
		for (i=0;i<(int)conn_array->len;i++) {
			if (statuses[i]==0) {
				myconn=(PgSQL_Connection *)conn_array->remove_index_fast(i);
				if (!ret[i]) {
					PgHGM->push_MyConn_to_pool(myconn);
				} else {
					myconn->send_quit=false;
					PgHGM->destroy_MyConn_from_pool(myconn);
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
				myconn=(PgSQL_Connection *)conn_array->index(i);
				if (myconn->pgsql->net.pvio && myconn->pgsql->net.fd && myconn->pgsql->net.buff) {
					statuses[i]=wait_for_pgsql(myconn->pgsql, statuses[i]);
					if (myconn->pgsql->net.pvio && myconn->pgsql->net.fd && myconn->pgsql->net.buff) {
						if ((statuses[i] & MYSQL_WAIT_TIMEOUT) == 0) {
							statuses[i]=mysql_change_user_cont(&ret[i], myconn->pgsql, statuses[i]);
							if (myconn->pgsql->net.pvio==NULL || myconn->pgsql->net.fd==0 || myconn->pgsql->net.buff==NULL ) {
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
					myconn=(PgSQL_Connection *)conn_array->remove_index_fast(i);
					if (!ret[i]) {
						myconn->reset();
						PgHGM->push_MyConn_to_pool(myconn);
					} else {
						myconn->send_quit=false;
						PgHGM->destroy_MyConn_from_pool(myconn);
					}
					statuses[i]=statuses[conn_array->len];
					ret[i]=ret[conn_array->len];
					i--;
				}
			}
		}
		while (conn_array->len) {
			// we reached here, and there are still connections
			myconn=(PgSQL_Connection *)conn_array->remove_index_fast(0);
			myconn->send_quit=false;
			PgHGM->destroy_MyConn_from_pool(myconn);
		}
		free(statuses);
		free(errs);
		free(ret);
	}
	delete conn_array;
}


PgSQL_Connection *PgSQL_SrvConnList::index(unsigned int _k) {
	return (PgSQL_Connection *)conns->index(_k);
}

PgSQL_Connection * PgSQL_SrvConnList::remove(int _k) {
	return (PgSQL_Connection *)conns->remove_index_fast(_k);
}

/*
unsigned int PgSQL_SrvConnList::conns_length() {
	return conns->len;
}
*/

PgSQL_SrvConnList::PgSQL_SrvConnList(PgSQL_SrvC *_mysrvc) {
	mysrvc=_mysrvc;
	conns=new PtrArray();
}

void PgSQL_SrvConnList::add(PgSQL_Connection *c) {
	conns->add(c);
}

PgSQL_SrvConnList::~PgSQL_SrvConnList() {
	mysrvc=NULL;
	while (conns_length()) {
		PgSQL_Connection *conn=(PgSQL_Connection *)conns->remove_index_fast(0);
		delete conn;
	}
	delete conns;
}

#if 0
PgSQL_SrvList::PgSQL_SrvList(PgSQL_HGC *_myhgc) {
	myhgc=_myhgc;
	servers=new PtrArray();
}

void PgSQL_SrvList::add(PgSQL_SrvC *s) {
	if (s->myhgc==NULL) {
		s->myhgc=myhgc;
	}
	servers->add(s);
}


int PgSQL_SrvList::find_idx(PgSQL_SrvC *s) {
  for (unsigned int i=0; i<servers->len; i++) {
    PgSQL_SrvC *mysrv=(PgSQL_SrvC *)servers->index(i);
    if (mysrv==s) {
      return (unsigned int)i;
    }
  }
  return -1;
}

void PgSQL_SrvList::remove(PgSQL_SrvC *s) {
	int i=find_idx(s);
	assert(i>=0);
	servers->remove_index_fast((unsigned int)i);
}
#endif // 0

void PgSQL_SrvConnList::drop_all_connections() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Dropping all connections (%u total) on PgSQL_SrvConnList %p for server %s:%d , hostgroup=%d , status=%d\n", conns_length(), this, mysrvc->address, mysrvc->port, mysrvc->myhgc->hid, mysrvc->status);
	while (conns_length()) {
		PgSQL_Connection *conn=(PgSQL_Connection *)conns->remove_index_fast(0);
		delete conn;
	}
}


PgSQL_SrvC::PgSQL_SrvC(
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
	ConnectionsUsed=new PgSQL_SrvConnList(this);
	ConnectionsFree=new PgSQL_SrvConnList(this);
}

void PgSQL_SrvC::connect_error(int err_num, bool get_mutex) {
	// NOTE: this function operates without any mutex
	// although, it is not extremely important if any counter is lost
	// as a single connection failure won't make a significant difference
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Connect failed with code '%d'\n", err_num);
	__sync_fetch_and_add(&connect_ERR,1);
	__sync_fetch_and_add(&PgHGM->status.server_connections_aborted,1);
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
		 * @brief The expected configured retries set by 'pgsql-connect_retries_on_failure' + '2' extra expected
		 *   connection errors.
		 * @details This two extra connections errors are expected:
		 *   1. An initial connection error generated by the datastream and the connection when being created,
		 *     this is, right after the session has requested a connection to the connection pool. This error takes
		 *     places directly in the state machine from 'PgSQL_Connection'. Because of this, we consider this
		 *     additional error to be a consequence of the two states machines, and it's not considered for
		 *     'connect_retries'.
		 *   2. A second connection connection error, which is the initial connection error generated by 'PgSQL_Session'
		 *     when already in the 'CONNECTING_SERVER' state. This error is an 'extra error' to always consider, since
		 *     it's not part of the retries specified by 'pgsql_thread___connect_retries_on_failure', thus, we set the
		 *     'connect_retries' to be 'pgsql_thread___connect_retries_on_failure + 1'.
		 */
		int connect_retries = pgsql_thread___connect_retries_on_failure + 1;
		int max_failures = pgsql_thread___shun_on_failures > connect_retries ? connect_retries : pgsql_thread___shun_on_failures;

		if (__sync_add_and_fetch(&connect_ERR_at_time_last_detected_error,1) >= (unsigned int)max_failures) {
			bool _shu=false;
			if (get_mutex==true)
				PgHGM->wrlock(); // to prevent race conditions, lock here. See #627
			if (status==MYSQL_SERVER_STATUS_ONLINE) {
				status=MYSQL_SERVER_STATUS_SHUNNED;
				shunned_automatic=true;
				_shu=true;
			} else {
				_shu=false;
			}
			if (get_mutex==true)
				PgHGM->wrunlock();
			if (_shu) {
			proxy_error("Shunning server %s:%d with %u errors/sec. Shunning for %u seconds\n", address, port, connect_ERR_at_time_last_detected_error , pgsql_thread___shun_recovery_time_sec);
			}
		}
	}
}

void PgSQL_SrvC::shun_and_killall() {
	status=MYSQL_SERVER_STATUS_SHUNNED;
	shunned_automatic=true;
	shunned_and_kill_all_connections=true;
}

PgSQL_SrvC::~PgSQL_SrvC() {
	if (address) free(address);
	if (comment) free(comment);
	delete ConnectionsUsed;
	delete ConnectionsFree;
}

#if 0
PgSQL_SrvList::~PgSQL_SrvList() {
	myhgc=NULL;
	while (servers->len) {
		PgSQL_SrvC *mysrvc=(PgSQL_SrvC *)servers->remove_index_fast(0);
		delete mysrvc;
	}
	delete servers;
}

PgSQL_HGC::PgSQL_HGC(int _hid) {
	hid=_hid;
	mysrvs=new PgSQL_SrvList(this);
	current_time_now = 0;
	new_connections_now = 0;
	attributes.initialized = false;
	reset_attributes();
	// Uninitialized server defaults. Should later be initialized via 'pgsql_hostgroup_attributes'.
	servers_defaults.weight = -1;
	servers_defaults.max_connections = -1;
	servers_defaults.use_ssl = -1;
}

void PgSQL_HGC::reset_attributes() {
	if (attributes.initialized == false) {
		attributes.init_connect = NULL;
		attributes.comment = NULL;
		attributes.ignore_session_variables_text = NULL;
	}
	attributes.initialized = true;
	attributes.configured = false;
	attributes.max_num_online_servers = 1000000;
	attributes.throttle_connections_per_sec = 1000000;
	attributes.autocommit = -1;
	attributes.free_connections_pct = 10;
	attributes.handle_warnings = -1;
	attributes.multiplex = true;
	attributes.connection_warming = false;
	free(attributes.init_connect);
	attributes.init_connect = NULL;
	free(attributes.comment);
	attributes.comment = NULL;
	free(attributes.ignore_session_variables_text);
	attributes.ignore_session_variables_text = NULL;
	if (attributes.ignore_session_variables_json) {
		delete attributes.ignore_session_variables_json;
		attributes.ignore_session_variables_json = NULL;
	}
}

PgSQL_HGC::~PgSQL_HGC() {
	reset_attributes(); // free all memory
	delete mysrvs;
}
#endif // 0

using metric_name = std::string;
using metric_help = std::string;
using metric_tags = std::map<std::string, std::string>;

using hg_counter_tuple =
	std::tuple<
		PgSQL_p_hg_counter::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using hg_gauge_tuple =
	std::tuple<
		PgSQL_p_hg_gauge::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using hg_dyn_counter_tuple =
	std::tuple<
		PgSQL_p_hg_dyn_counter::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using hg_dyn_gauge_tuple =
	std::tuple<
		PgSQL_p_hg_dyn_gauge::metric,
		metric_name,
		metric_help,
		metric_tags
	>;

using hg_counter_vector = std::vector<hg_counter_tuple>;
using hg_gauge_vector = std::vector<hg_gauge_tuple>;
using hg_dyn_counter_vector = std::vector<hg_dyn_counter_tuple>;
using hg_dyn_gauge_vector = std::vector<hg_dyn_gauge_tuple>;

/**
 * @brief Metrics map holding the metrics for the 'PgSQL_HostGroups_Manager' module.
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
			PgSQL_p_hg_counter::servers_table_version,
			"proxysql_servers_table_version_total",
			"Number of times the \"servers_table\" have been modified.",
			metric_tags {}
		),

		// ====================================================================
		std::make_tuple (
			PgSQL_p_hg_counter::server_connections_created,
			"proxysql_server_connections_total",
			"Total number of server connections (created|delayed|aborted).",
			metric_tags {
				{ "status", "created" }
			}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::server_connections_delayed,
			"proxysql_server_connections_total",
			"Total number of server connections (created|delayed|aborted).",
			metric_tags {
				{ "status", "delayed" }
			}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::server_connections_aborted,
			"proxysql_server_connections_total",
			"Total number of server connections (created|delayed|aborted).",
			metric_tags {
				{ "status", "aborted" }
			}
		),
		// ====================================================================

		// ====================================================================
		std::make_tuple (
			PgSQL_p_hg_counter::client_connections_created,
			"proxysql_client_connections_total",
			"Total number of client connections created.",
			metric_tags {
				{ "status", "created" }
			}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::client_connections_aborted,
			"proxysql_client_connections_total",
			"Total number of client failed connections (or closed improperly).",
			metric_tags {
				{ "status", "aborted" }
			}
		),
		// ====================================================================

		std::make_tuple (
			PgSQL_p_hg_counter::com_autocommit,
			"proxysql_com_autocommit_total",
			"Total queries autocommited.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::com_autocommit_filtered,
			"proxysql_com_autocommit_filtered_total",
			"Total queries filtered autocommit.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::com_rollback,
			"proxysql_com_rollback_total",
			"Total queries rollbacked.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::com_rollback_filtered,
			"proxysql_com_rollback_filtered_total",
			"Total queries filtered rollbacked.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::com_backend_change_user,
			"proxysql_com_backend_change_user_total",
			"Total CHANGE_USER queries backend.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::com_backend_init_db,
			"proxysql_com_backend_init_db_total",
			"Total queries backend INIT DB.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::com_backend_set_names,
			"proxysql_com_backend_set_names_total",
			"Total queries backend SET NAMES.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::com_frontend_init_db,
			"proxysql_com_frontend_init_db_total",
			"Total INIT DB queries frontend.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::com_frontend_set_names,
			"proxysql_com_frontend_set_names_total",
			"Total SET NAMES frontend queries.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::com_frontend_use_db,
			"proxysql_com_frontend_use_db_total",
			"Total USE DB queries frontend.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::com_commit_cnt,
			"proxysql_com_commit_cnt_total",
			"Total queries commit.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::com_commit_cnt_filtered,
			"proxysql_com_commit_cnt_filtered_total",
			"Total queries commit filtered.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::selects_for_update__autocommit0,
			"proxysql_selects_for_update__autocommit0_total",
			"Total queries that are SELECT for update or equivalent.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::access_denied_wrong_password,
			"proxysql_access_denied_wrong_password_total",
			"Total access denied \"wrong password\".",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::access_denied_max_connections,
			"proxysql_access_denied_max_connections_total",
			"Total access denied \"max connections\".",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::access_denied_max_user_connections,
			"proxysql_access_denied_max_user_connections_total",
			"Total access denied \"max user connections\".",
			metric_tags {}
		),

		// ====================================================================
		std::make_tuple (
			PgSQL_p_hg_counter::myhgm_myconnpool_get,
			"proxysql_myhgm_myconnpool_get_total",
			"The number of requests made to the connection pool.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::myhgm_myconnpool_get_ok,
			"proxysql_myhgm_myconnpool_get_ok_total",
			"The number of successful requests to the connection pool (i.e. where a connection was available).",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::myhgm_myconnpool_get_ping,
			"proxysql_myhgm_myconnpool_get_ping_total",
			"The number of connections that were taken from the pool to run a ping to keep them alive.",
			metric_tags {}
		),
		// ====================================================================

		std::make_tuple (
			PgSQL_p_hg_counter::myhgm_myconnpool_push,
			"proxysql_myhgm_myconnpool_push_total",
			"The number of connections returned to the connection pool.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::myhgm_myconnpool_reset,
			"proxysql_myhgm_myconnpool_reset_total",
			"The number of connections that have been reset / re-initialized using \"COM_CHANGE_USER\"",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_counter::myhgm_myconnpool_destroy,
			"proxysql_myhgm_myconnpool_destroy_total",
			"The number of connections considered unhealthy and therefore closed.",
			metric_tags {}
		),

		// ====================================================================

		std::make_tuple (
			PgSQL_p_hg_counter::auto_increment_delay_multiplex,
			"proxysql_myhgm_auto_increment_multiplex_total",
			"The number of times that 'auto_increment_delay_multiplex' has been triggered.",
			metric_tags {}
		),
	},
	// prometheus gauges
	hg_gauge_vector {
		std::make_tuple (
			PgSQL_p_hg_gauge::server_connections_connected,
			"proxysql_server_connections_connected",
			"Backend connections that are currently connected.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_gauge::client_connections_connected,
			"proxysql_client_connections_connected",
			"Client connections that are currently connected.",
			metric_tags {}
		)
	},
	// prometheus dynamic counters
	hg_dyn_counter_vector {
		// connection_pool
		// ====================================================================

		// ====================================================================
		std::make_tuple (
			PgSQL_p_hg_dyn_counter::conn_pool_bytes_data_recv,
			"proxysql_connpool_data_bytes_total",
			"Amount of data (sent|recv) from the backend, excluding metadata.",
			metric_tags {
				{ "traffic_flow", "recv" }
			}
		),
		std::make_tuple (
			PgSQL_p_hg_dyn_counter::conn_pool_bytes_data_sent,
			"proxysql_connpool_data_bytes_total",
			"Amount of data (sent|recv) from the backend, excluding metadata.",
			metric_tags {
				{ "traffic_flow", "sent" }
			}
		),
		// ====================================================================

		// ====================================================================
		std::make_tuple (
			PgSQL_p_hg_dyn_counter::connection_pool_conn_err,
			"proxysql_connpool_conns_total",
			"How many connections have been tried to be established.",
			metric_tags {
				{ "status", "err" }
			}
		),
		std::make_tuple (
			PgSQL_p_hg_dyn_counter::connection_pool_conn_ok,
			"proxysql_connpool_conns_total",
			"How many connections have been tried to be established.",
			metric_tags {
				{ "status", "ok" }
			}
		),
		// ====================================================================

		std::make_tuple (
			PgSQL_p_hg_dyn_counter::connection_pool_queries,
			"proxysql_connpool_conns_queries_total",
			"The number of queries routed towards this particular backend server.",
			metric_tags {}
		),
		// gtid
		std::make_tuple (
			PgSQL_p_hg_dyn_counter::gtid_executed,
			"proxysql_gtid_executed_total",
			"Tracks the number of executed gtid per host and port.",
			metric_tags {}
		),
		// pgsql_error
		std::make_tuple (
			PgSQL_p_hg_dyn_counter::proxysql_pgsql_error,
			"proxysql_pgsql_error_total",
			"Tracks the pgsql errors generated by proxysql.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_dyn_counter::pgsql_error,
			"pgsql_error_total",
			"Tracks the pgsql errors encountered.",
			metric_tags {}
		)
	},
	// prometheus dynamic gauges
	hg_dyn_gauge_vector {
		std::make_tuple (
			PgSQL_p_hg_dyn_gauge::connection_pool_conn_free,
			"proxysql_connpool_conns",
			"How many backend connections are currently (free|used).",
			metric_tags {
				{ "status", "free" }
			}
		),
		std::make_tuple (
			PgSQL_p_hg_dyn_gauge::connection_pool_conn_used,
			"proxysql_connpool_conns",
			"How many backend connections are currently (free|used).",
			metric_tags {
				{ "status", "used" }
			}
		),
		std::make_tuple (
			PgSQL_p_hg_dyn_gauge::connection_pool_latency_us,
			"proxysql_connpool_conns_latency_us",
			"The currently ping time in microseconds, as reported from Monitor.",
			metric_tags {}
		),
		std::make_tuple (
			PgSQL_p_hg_dyn_gauge::connection_pool_status,
			"proxysql_connpool_conns_status",
			"The status of the backend server (1 - ONLINE, 2 - SHUNNED, 3 - OFFLINE_SOFT, 4 - OFFLINE_HARD).",
			metric_tags {}
		)
	}
);

PgSQL_HostGroups_Manager::PgSQL_HostGroups_Manager() {
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
	status.auto_increment_delay_multiplex=0;
	pthread_mutex_init(&readonly_mutex, NULL);
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
	mydb->execute(MYHGM_PgSQL_SERVERS);
	mydb->execute(MYHGM_PgSQL_SERVERS_INCOMING);
	mydb->execute(MYHGM_PgSQL_REPLICATION_HOSTGROUPS);
	mydb->execute(MYHGM_PgSQL_HOSTGROUP_ATTRIBUTES);
	mydb->execute("CREATE INDEX IF NOT EXISTS idx_pgsql_servers_hostname_port ON pgsql_servers (hostname,port)");
	MyHostGroups=new PtrArray();
	runtime_pgsql_servers=NULL;
	incoming_replication_hostgroups=NULL;
	incoming_hostgroup_attributes = NULL;
	incoming_pgsql_servers_v2 = NULL;
	pthread_rwlock_init(&gtid_rwlock, NULL);
	gtid_missing_nodes = false;
	gtid_ev_loop=NULL;
	gtid_ev_timer=NULL;
	gtid_ev_async = (struct ev_async *)malloc(sizeof(struct ev_async));
	pgsql_servers_to_monitor = NULL;

	{
		static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		rand_del[0] = '-';
		for (int i = 1; i < 6; i++) {
			rand_del[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
		}
		rand_del[6] = '-';
		rand_del[7] = 0;
	}
	pthread_mutex_init(&pgsql_errors_mutex, NULL);

	// Initialize prometheus metrics
	init_prometheus_counter_array<PgSQL_hg_metrics_map_idx, PgSQL_p_hg_counter>(hg_metrics_map, this->status.p_counter_array);
	init_prometheus_gauge_array<PgSQL_hg_metrics_map_idx, PgSQL_p_hg_gauge>(hg_metrics_map, this->status.p_gauge_array);
	init_prometheus_dyn_counter_array<PgSQL_hg_metrics_map_idx, PgSQL_p_hg_dyn_counter>(hg_metrics_map, this->status.p_dyn_counter_array);
	init_prometheus_dyn_gauge_array<PgSQL_hg_metrics_map_idx, PgSQL_p_hg_dyn_gauge>(hg_metrics_map, this->status.p_dyn_gauge_array);

	pthread_mutex_init(&pgsql_errors_mutex, NULL);
}

void PgSQL_HostGroups_Manager::init() {
	//conn_reset_queue = NULL;
	//conn_reset_queue = new wqueue<PgSQL_Connection *>();
	HGCU_thread = new std::thread(&HGCU_thread_run);
	//pthread_create(&HGCU_thread_id, NULL, HGCU_thread_run , NULL);

	// gtid initialization;
	//GTID_syncer_thread = new std::thread(&GTID_syncer_run);
	GTID_syncer_thread = nullptr;

	//pthread_create(&GTID_syncer_thread_id, NULL, GTID_syncer_run , NULL);
}

void PgSQL_HostGroups_Manager::shutdown() {
	queue.add(NULL);
	HGCU_thread->join();
	delete HGCU_thread;
	ev_async_send(gtid_ev_loop, gtid_ev_async);
	GTID_syncer_thread->join();
	delete GTID_syncer_thread;
}

PgSQL_HostGroups_Manager::~PgSQL_HostGroups_Manager() {
	while (MyHostGroups->len) {
		PgSQL_HGC *myhgc=(PgSQL_HGC *)MyHostGroups->remove_index_fast(0);
		delete myhgc;
	}
	delete MyHostGroups;
	delete mydb;
	if (admindb) {
		delete admindb;
	}
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
void PgSQL_HostGroups_Manager::wrlock() {
#ifdef MHM_PTHREAD_MUTEX
	pthread_mutex_lock(&lock);
#else
	spin_wrlock(&rwlock);
#endif
}

void PgSQL_HostGroups_Manager::p_update_pgsql_error_counter(p_pgsql_error_type err_type, unsigned int hid, char* address, uint16_t port, unsigned int code) {
	PgSQL_p_hg_dyn_counter::metric metric = PgSQL_p_hg_dyn_counter::pgsql_error;
	if (err_type == p_pgsql_error_type::proxysql) {
		metric = PgSQL_p_hg_dyn_counter::proxysql_pgsql_error;
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

	pthread_mutex_lock(&pgsql_errors_mutex);

	p_inc_map_counter(
		status.p_pgsql_errors_map,
		status.p_dyn_counter_array[metric],
		metric_id,
		metric_labels
	);

	pthread_mutex_unlock(&pgsql_errors_mutex);
}

void PgSQL_HostGroups_Manager::wrunlock() {
#ifdef MHM_PTHREAD_MUTEX
	pthread_mutex_unlock(&lock);
#else
	spin_wrunlock(&rwlock);
#endif
}


void PgSQL_HostGroups_Manager::wait_servers_table_version(unsigned v, unsigned w) {
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

unsigned int PgSQL_HostGroups_Manager::get_servers_table_version() {
	return __sync_fetch_and_add(&status.servers_table_version,0);
}

// we always assume that the calling thread has acquired a rdlock()
int PgSQL_HostGroups_Manager::servers_add(SQLite3_result *resultset) {
	if (resultset==NULL) {
		return 0;
	}
	int rc;
	mydb->execute("DELETE FROM pgsql_servers_incoming");
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;
	//sqlite3 *mydb3=mydb->get_db();
	char *query1=(char *)"INSERT INTO pgsql_servers_incoming VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
	std::string query32s = "INSERT INTO pgsql_servers_incoming VALUES " + generate_multi_rows_query(32,12);
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

SQLite3_result * PgSQL_HostGroups_Manager::execute_query(char *query, char **error) {
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	wrlock();
  mydb->execute_statement(query, error , &cols , &affected_rows , &resultset);
	wrunlock();
	return resultset;
}

void PgSQL_HostGroups_Manager::CUCFT1(
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

void PgSQL_HostGroups_Manager::commit_update_checksums_from_tables(SpookyHash& myhash, bool& init) {
	// Always reset the current table values before recomputing
	for (size_t i = 0; i < table_resultset_checksum.size(); i++) {
		if (i != HGM_TABLES::PgSQL_SERVERS && i != HGM_TABLES::PgSQL_SERVERS_V2) {
			table_resultset_checksum[i] = 0;
		}
	}

	CUCFT1(myhash,init,"pgsql_replication_hostgroups","writer_hostgroup", table_resultset_checksum[HGM_TABLES::PgSQL_REPLICATION_HOSTGROUPS]);
	CUCFT1(myhash,init,"pgsql_hostgroup_attributes","hostgroup_id", table_resultset_checksum[HGM_TABLES::PgSQL_HOSTGROUP_ATTRIBUTES]);
}

/**
 * @brief This code updates the 'hostgroup_server_mapping' table with the most recent pgsql_servers and pgsql_replication_hostgroups 
 *	  records while utilizing checksums to prevent unnecessary updates.
 * 
 * IMPORTANT: Make sure wrlock() is called before calling this method.
 * 
*/
void PgSQL_HostGroups_Manager::update_hostgroup_manager_mappings() {

	if (hgsm_pgsql_servers_checksum != table_resultset_checksum[HGM_TABLES::PgSQL_SERVERS] ||
		hgsm_pgsql_replication_hostgroups_checksum != table_resultset_checksum[HGM_TABLES::PgSQL_REPLICATION_HOSTGROUPS])
	{
		proxy_info("Rebuilding 'Hostgroup_Manager_Mapping' due to checksums change - pgsql_servers { old: 0x%lX, new: 0x%lX }, pgsql_replication_hostgroups { old:0x%lX, new:0x%lX }\n",
			hgsm_pgsql_servers_checksum, table_resultset_checksum[HGM_TABLES::PgSQL_SERVERS],
			hgsm_pgsql_replication_hostgroups_checksum, table_resultset_checksum[HGM_TABLES::PgSQL_REPLICATION_HOSTGROUPS]);

		char* error = NULL;
		int cols = 0;
		int affected_rows = 0;
		SQLite3_result* resultset = NULL;

		hostgroup_server_mapping.clear();

		const char* query = "SELECT DISTINCT hostname, port, '1' is_writer, status, reader_hostgroup, writer_hostgroup, mem_pointer FROM pgsql_replication_hostgroups JOIN pgsql_servers ON hostgroup_id=writer_hostgroup WHERE status<>3 \
							 UNION \
							 SELECT DISTINCT hostname, port, '0' is_writer, status, reader_hostgroup, writer_hostgroup, mem_pointer FROM pgsql_replication_hostgroups JOIN pgsql_servers ON hostgroup_id=reader_hostgroup WHERE status<>3 \
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
						hostgroup_server_mapping.insert( std::pair<std::string,std::unique_ptr<PgSQL_HostGroups_Manager::HostGroup_Server_Mapping>> {
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
				node.srv = reinterpret_cast<PgSQL_SrvC*>(atoll(r->fields[6]));

				HostGroup_Server_Mapping::Type type = (r->fields[2] && r->fields[2][0] == '1') ? HostGroup_Server_Mapping::Type::WRITER : HostGroup_Server_Mapping::Type::READER;
				fetched_server_mapping->add(type, node);
			}
		}
		delete resultset;

		hgsm_pgsql_servers_checksum = table_resultset_checksum[HGM_TABLES::PgSQL_SERVERS];
		hgsm_pgsql_replication_hostgroups_checksum = table_resultset_checksum[HGM_TABLES::PgSQL_REPLICATION_HOSTGROUPS];
	}
}

/**
 * @brief Generates a resultset holding the current Admin 'runtime_pgsql_servers' as reported by Admin.
 * @details Requires caller to hold the mutex 'PgSQL_HostGroups_Manager::wrlock'.
 * @param mydb The db in which to perform the query, typically 'PgSQL_HostGroups_Manager::mydb'.
 * @return An SQLite3 resultset for the query 'MYHGM_GEN_ADMIN_RUNTIME_SERVERS'.
 */
unique_ptr<SQLite3_result> get_admin_runtime_pgsql_servers(SQLite3DB* mydb) {
	char* error = nullptr;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* resultset = nullptr;

	mydb->execute_statement(PGHGM_GEN_CLUSTER_ADMIN_RUNTIME_SERVERS, &error, &cols, &affected_rows, &resultset);

	if (error) {
		proxy_error("SQLite3 query generating 'runtime_pgsql_servers' resultset failed with error '%s'\n", error);
		assert(0);
	}

	return unique_ptr<SQLite3_result>(resultset);
}

/**
 * @brief Generates a resultset with holding the current 'pgsql_servers_v2' table.
 * @details Requires caller to hold the mutex 'ProxySQL_Admin::mysql_servers_wrlock'.
 * @return A resulset holding 'pgsql_servers_v2'.
 */
unique_ptr<SQLite3_result> get_pgsql_servers_v2() {
	char* error = nullptr;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* resultset = nullptr;

	if (GloAdmin && GloAdmin->admindb) {
		GloAdmin->admindb->execute_statement(
			PGHGM_GEN_CLUSTER_ADMIN_PGSQL_SERVERS, &error, &cols, &affected_rows, &resultset
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
 * @brief Updates the global 'pgsql_servers' module checksum.
 * @details If the new computed checksum matches the supplied 'cluster_checksum', the epoch used for the
 *  checksum is the supplied epoch instead of current time. This way we ensure the preservation of the
 *  checksum and epoch fetched from the ProxySQL cluster peer node.
 *
 *  IMPORTANT: This function also generates a new 'global_checksum'. This is because everytime
 *  'runtime_pgsql_servers' change, updating the global checksum is unconditional.
 * @param new_checksum The new computed checksum for 'runtime_pgsql_servers'.
 * @param peer_checksum A checksum fetched from another ProxySQL cluster node, holds the checksum value
 *  and its epoch. Should be empty if no remote checksum is being considered.
 * @param epoch The epoch to be preserved in case the supplied 'peer_checksum' matches the new computed
 *  checksum.
 */
static void update_glovars_pgsql_servers_checksum(
	const string& new_checksum,
	const runtime_pgsql_servers_checksum_t& peer_checksum = {},
	bool update_version = false
) {
	time_t new_epoch = time(NULL);

	update_glovars_checksum_with_peers(
		GloVars.checksums_values.pgsql_servers,
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
 * @brief Updates the global 'pgsql_servers_v2' module checksum.
 * @details Unlike 'update_glovars_pgsql_servers_checksum' this function doesn't generate a new
 *  'global_checksum'. It's caller responsibility to ensure that 'global_checksum' is updated. 
 * @param new_checksum The new computed checksum for 'pgsql_servers_v2'.
 * @param peer_checksum A checksum fetched from another ProxySQL cluster node, holds the checksum value
 *  and its epoch. Should be empty if no remote checksum is being considered.
 * @param epoch The epoch to be preserved in case the supplied 'peer_checksum' matches the new computed
 *  checksum.
 */
static void update_glovars_pgsql_servers_v2_checksum(
	const string& new_checksum,
	const pgsql_servers_v2_checksum_t& peer_checksum = {},
	bool update_version = false
) {
	time_t new_epoch = time(NULL);

	update_glovars_checksum_with_peers(
		GloVars.checksums_values.pgsql_servers_v2,
		new_checksum,
		peer_checksum.value,
		new_epoch,
		peer_checksum.epoch,
		update_version
	);
}

uint64_t PgSQL_HostGroups_Manager::commit_update_checksum_from_pgsql_servers(SQLite3_result* runtime_pgsql_servers) {
	mydb->execute("DELETE FROM pgsql_servers");
	generate_pgsql_servers_table();

	if (runtime_pgsql_servers == nullptr) {
		unique_ptr<SQLite3_result> resultset { get_admin_runtime_pgsql_servers(mydb) };
		save_runtime_pgsql_servers(resultset.release());
	} else {
		save_runtime_pgsql_servers(runtime_pgsql_servers);
	}

	uint64_t raw_checksum = this->runtime_pgsql_servers ? this->runtime_pgsql_servers->raw_checksum() : 0;
	table_resultset_checksum[HGM_TABLES::PgSQL_SERVERS] = raw_checksum;

	return raw_checksum;
}

uint64_t PgSQL_HostGroups_Manager::commit_update_checksum_from_pgsql_servers_v2(SQLite3_result* pgsql_servers_v2) {
	if (pgsql_servers_v2 == nullptr) {
		unique_ptr<SQLite3_result> resultset { get_pgsql_servers_v2() };
		save_pgsql_servers_v2(resultset.release());
	} else {
		save_pgsql_servers_v2(pgsql_servers_v2);
	}

	uint64_t raw_checksum = this->incoming_pgsql_servers_v2 ? this->incoming_pgsql_servers_v2->raw_checksum() : 0;
	table_resultset_checksum[HGM_TABLES::PgSQL_SERVERS_V2] = raw_checksum;

	return raw_checksum;
}

std::string PgSQL_HostGroups_Manager::gen_global_pgsql_servers_v2_checksum(uint64_t servers_v2_hash) {
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

bool PgSQL_HostGroups_Manager::commit(
	const peer_runtime_pgsql_servers_t& peer_runtime_pgsql_servers,
	const peer_pgsql_servers_v2_t& peer_pgsql_servers_v2,
	bool only_commit_runtime_pgsql_servers,
	bool update_version
) {
	// if only_commit_runtime_pgsql_servers is true, pgsql_servers_v2 resultset will not be entertained and will cause memory leak.
	if (only_commit_runtime_pgsql_servers) {
		proxy_info("Generating runtime pgsql servers records only.\n");
	} else {
		proxy_info("Generating runtime pgsql servers and pgsql servers v2 records.\n");
	}

	unsigned long long curtime1=monotonic_time();
	wrlock();
	// purge table
	purge_pgsql_servers_table();
	// if any server has gtid_port enabled, use_gtid is set to true
	// and then has_gtid_port is set too
	bool use_gtid = false;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM pgsql_servers\n");
	mydb->execute("DELETE FROM pgsql_servers");
	generate_pgsql_servers_table();

	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	if (GloMTH->variables.hostgroup_manager_verbose) {
		mydb->execute_statement((char *)"SELECT * FROM pgsql_servers_incoming", &error , &cols , &affected_rows , &resultset);
		if (error) {
			proxy_error("Error on read from pgsql_servers_incoming : %s\n", error);
		} else {
			if (resultset) {
				proxy_info("Dumping pgsql_servers_incoming\n");
				resultset->dump_to_stderr();
			}
		}
		if (resultset) { delete resultset; resultset=NULL; }
	}
	char *query=NULL;
	query=(char *)"SELECT mem_pointer, t1.hostgroup_id, t1.hostname, t1.port FROM pgsql_servers t1 LEFT OUTER JOIN pgsql_servers_incoming t2 ON (t1.hostgroup_id=t2.hostgroup_id AND t1.hostname=t2.hostname AND t1.port=t2.port) WHERE t2.hostgroup_id IS NULL";
	mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		if (GloMTH->variables.hostgroup_manager_verbose) {
			proxy_info("Dumping pgsql_servers LEFT JOIN pgsql_servers_incoming\n");
			resultset->dump_to_stderr();
		}
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			long long ptr=atoll(r->fields[0]);
			proxy_warning("Removed server at address %lld, hostgroup %s, address %s port %s. Setting status OFFLINE HARD and immediately dropping all free connections. Used connections will be dropped when trying to use them\n", ptr, r->fields[1], r->fields[2], r->fields[3]);
			PgSQL_SrvC *mysrvc=(PgSQL_SrvC *)ptr;
			mysrvc->status=MYSQL_SERVER_STATUS_OFFLINE_HARD;
			mysrvc->ConnectionsFree->drop_all_connections();
			char *q1=(char *)"DELETE FROM pgsql_servers WHERE mem_pointer=%lld";
			char *q2=(char *)malloc(strlen(q1)+32);
			sprintf(q2,q1,ptr);
			mydb->execute(q2);
			free(q2);
		}
	}
	if (resultset) { delete resultset; resultset=NULL; }

	// This seems unnecessary. Removed as part of issue #829
	//mydb->execute("DELETE FROM pgsql_servers");
	//generate_pgsql_servers_table();

	mydb->execute("INSERT OR IGNORE INTO pgsql_servers(hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) SELECT hostgroup_id, hostname, port, gtid_port, weight, status, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM pgsql_servers_incoming");

	// SELECT FROM pgsql_servers whatever is not identical in pgsql_servers_incoming, or where mem_pointer=0 (where there is no pointer yet)
	query=(char *)"SELECT t1.*, t2.gtid_port, t2.weight, t2.status, t2.compression, t2.max_connections, t2.max_replication_lag, t2.use_ssl, t2.max_latency_ms, t2.comment FROM pgsql_servers t1 JOIN pgsql_servers_incoming t2 ON (t1.hostgroup_id=t2.hostgroup_id AND t1.hostname=t2.hostname AND t1.port=t2.port) WHERE mem_pointer=0 OR t1.gtid_port<>t2.gtid_port OR t1.weight<>t2.weight OR t1.status<>t2.status OR t1.compression<>t2.compression OR t1.max_connections<>t2.max_connections OR t1.max_replication_lag<>t2.max_replication_lag OR t1.use_ssl<>t2.use_ssl OR t1.max_latency_ms<>t2.max_latency_ms or t1.comment<>t2.comment";
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
	mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {

		if (GloMTH->variables.hostgroup_manager_verbose) {
			proxy_info("Dumping pgsql_servers JOIN pgsql_servers_incoming\n");
			resultset->dump_to_stderr();
		}
		// optimization #829
		int rc;
		sqlite3_stmt *statement1=NULL;
		sqlite3_stmt *statement2=NULL;
		//sqlite3 *mydb3=mydb->get_db();
		char *query1=(char *)"UPDATE pgsql_servers SET mem_pointer = ?1 WHERE hostgroup_id = ?2 AND hostname = ?3 AND port = ?4";
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
		rc = mydb->prepare_v2(query1, &statement1);
		ASSERT_SQLITE_OK(rc, mydb);
		char *query2=(char *)"UPDATE pgsql_servers SET weight = ?1 , status = ?2 , compression = ?3 , max_connections = ?4 , max_replication_lag = ?5 , use_ssl = ?6 , max_latency_ms = ?7 , comment = ?8 , gtid_port = ?9 WHERE hostgroup_id = ?10 AND hostname = ?11 AND port = ?12";
		//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query2, -1, &statement2, 0);
		rc = mydb->prepare_v2(query2, &statement2);
		ASSERT_SQLITE_OK(rc, mydb);

		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			long long ptr=atoll(r->fields[12]); // increase this index every time a new column is added
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d , weight=%d, status=%d, mem_pointer=%llu, hostgroup=%d, compression=%d\n", r->fields[1], atoi(r->fields[2]), atoi(r->fields[4]), (MySerStatus) atoi(r->fields[5]), ptr, atoi(r->fields[0]), atoi(r->fields[6]));
			//fprintf(stderr,"%lld\n", ptr);
			if (ptr==0) {
				if (GloMTH->variables.hostgroup_manager_verbose) {
					proxy_info("Creating new server in HG %d : %s:%d , gtid_port=%d, weight=%d, status=%d\n", atoi(r->fields[0]), r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), atoi(r->fields[4]), (MySerStatus) atoi(r->fields[5]));
				}
				PgSQL_SrvC *mysrvc=new PgSQL_SrvC(r->fields[1], atoi(r->fields[2]), atoi(r->fields[3]), atoi(r->fields[4]), (MySerStatus) atoi(r->fields[5]), atoi(r->fields[6]), atoi(r->fields[7]), atoi(r->fields[8]), atoi(r->fields[9]), atoi(r->fields[10]), r->fields[11]); // add new fields here if adding more columns in pgsql_servers
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Adding new server %s:%d , weight=%d, status=%d, mem_ptr=%p into hostgroup=%d\n", r->fields[1], atoi(r->fields[2]), atoi(r->fields[4]), (MySerStatus) atoi(r->fields[5]), mysrvc, atoi(r->fields[0]));
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
				PgSQL_SrvC *mysrvc=(PgSQL_SrvC *)ptr;
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
					proxy_info("Changing max_connections for server %d:%s:%d (%s:%d) from %d (%ld) to %d\n" , mysrvc->myhgc->hid , mysrvc->address, mysrvc->port, r->fields[1], atoi(r->fields[2]), atoi(r->fields[7]) , mysrvc->max_connections , atoi(r->fields[17]));
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
					rc=(*proxy_sqlite3_bind_int64)(statement2, 1, mysrvc->weight); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement2, 2, mysrvc->status); ASSERT_SQLITE_OK(rc, mydb);
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
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM pgsql_servers_incoming\n");
	mydb->execute("DELETE FROM pgsql_servers_incoming");

	string global_checksum_v2 {};
	if (only_commit_runtime_pgsql_servers == false) {
		// replication
		if (incoming_replication_hostgroups) { // this IF is extremely important, otherwise replication hostgroups may disappear
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM pgsql_replication_hostgroups\n");
			mydb->execute("DELETE FROM pgsql_replication_hostgroups");
			generate_pgsql_replication_hostgroups_table();
		}

		// hostgroup attributes
		if (incoming_hostgroup_attributes) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM pgsql_hostgroup_attributes\n");
			mydb->execute("DELETE FROM pgsql_hostgroup_attributes");
			generate_pgsql_hostgroup_attributes_table();
		}

		uint64_t new_hash = commit_update_checksum_from_pgsql_servers_v2(peer_pgsql_servers_v2.resultset);

		{
			const string new_checksum { get_checksum_from_hash(new_hash) };
			proxy_info("Checksum for table %s is %s\n", "pgsql_servers_v2", new_checksum.c_str());
		}

		global_checksum_v2 = gen_global_pgsql_servers_v2_checksum(new_hash);
		proxy_info("New computed global checksum for 'pgsql_servers_v2' is '%s'\n", global_checksum_v2.c_str());
	}

	// Update 'pgsql_servers' and global checksums
	{
		uint64_t new_hash = commit_update_checksum_from_pgsql_servers(peer_runtime_pgsql_servers.resultset);
		const string new_checksum { get_checksum_from_hash(new_hash) };
		proxy_info("Checksum for table %s is %s\n", "pgsql_servers", new_checksum.c_str());

		pthread_mutex_lock(&GloVars.checksum_mutex);
		if (only_commit_runtime_pgsql_servers == false) {
			update_glovars_pgsql_servers_v2_checksum(global_checksum_v2, peer_pgsql_servers_v2.checksum, true);
		}
		update_glovars_pgsql_servers_checksum(new_checksum, peer_runtime_pgsql_servers.checksum, update_version);
		pthread_mutex_unlock(&GloVars.checksum_mutex);
	}

	// fill Hostgroup_Manager_Mapping with latest records
	update_hostgroup_manager_mappings();

	//ev_async_send(gtid_ev_loop, gtid_ev_async);

	__sync_fetch_and_add(&status.servers_table_version,1);

	// We completely reset read_only_set1. It will generated (completely) again in read_only_action()
	// Note: read_only_set1 will be regenerated all at once
	read_only_set1.erase(read_only_set1.begin(), read_only_set1.end());
	// We completely reset read_only_set2. It will be again written in read_only_action()
	// Note: read_only_set2 will be regenerated one server at the time
	read_only_set2.erase(read_only_set2.begin(), read_only_set2.end());

	this->status.p_counter_array[PgSQL_p_hg_counter::servers_table_version]->Increment();
	pthread_cond_broadcast(&status.servers_table_version_cond);
	pthread_mutex_unlock(&status.servers_table_version_lock);

	// NOTE: In order to guarantee the latest generated version, this should be kept after all the
	// calls to 'generate_pgsql_servers'.
	update_table_pgsql_servers_for_monitor(false);

	wrunlock();
	unsigned long long curtime2=monotonic_time();
	curtime1 = curtime1/1000;
	curtime2 = curtime2/1000;
	proxy_info("PgSQL_HostGroups_Manager::commit() locked for %llums\n", curtime2-curtime1);

	if (GloMTH) {
		GloMTH->signal_all_threads(1);
	}

	return true;
}

/** 
 * @brief Calculate the checksum for the runtime pgsql_servers record, after excluding all the rows
 *    with the status OFFLINE_HARD from the result set
 * 
 * @details The runtime pgsql_servers is now considered as a distinct module and have a separate checksum calculation.
 *    This is because the records in the runtime module may differ from those in the admin pgsql_servers module, which
 *	  can cause synchronization issues within the cluster.
 * 
 * @param runtime_pgsql_servers resultset of runtime pgsql_servers or can be a nullptr.
*/
uint64_t PgSQL_HostGroups_Manager::get_pgsql_servers_checksum(SQLite3_result* runtime_pgsql_servers) {

	//Note: GloVars.checksum_mutex needs to be locked
	SQLite3_result* resultset = nullptr;

	if (runtime_pgsql_servers == nullptr) {
		char* error = NULL;
		int cols = 0;
		int affected_rows = 0;

		mydb->execute_statement(PGHGM_GEN_CLUSTER_ADMIN_RUNTIME_SERVERS, &error, &cols, &affected_rows, &resultset);

		if (resultset) {
			save_runtime_pgsql_servers(resultset);
		} else {
			proxy_info("Checksum for table %s is 0x%lX\n", "pgsql_servers", (long unsigned int)0);
		}
	} else {
		resultset = runtime_pgsql_servers;
		save_runtime_pgsql_servers(runtime_pgsql_servers);
	}

	table_resultset_checksum[HGM_TABLES::PgSQL_SERVERS] = resultset != nullptr ? resultset->raw_checksum() : 0;
	proxy_info("Checksum for table %s is 0x%lX\n", "pgsql_servers", table_resultset_checksum[HGM_TABLES::PgSQL_SERVERS]);

	return table_resultset_checksum[HGM_TABLES::PgSQL_SERVERS];
}

bool PgSQL_HostGroups_Manager::gtid_exists(PgSQL_SrvC *mysrvc, char * gtid_uuid, uint64_t gtid_trxid) {
	bool ret = false;
#if 0
	pthread_rwlock_rdlock(&gtid_rwlock);
	std::string s1 = mysrvc->address;
	s1.append(":");
	s1.append(std::to_string(mysrvc->port));
	std::unordered_map <string, PgSQL_GTID_Server_Data *>::iterator it2;
	it2 = gtid_map.find(s1);
	PgSQL_GTID_Server_Data *gtid_is=NULL;
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
#endif // 0
	return ret;
}

void PgSQL_HostGroups_Manager::generate_pgsql_gtid_executed_tables() {
#if 0
	pthread_rwlock_wrlock(&gtid_rwlock);
	// first, set them all as active = false
	std::unordered_map<string, PgSQL_GTID_Server_Data *>::iterator it = gtid_map.begin();
	while(it != gtid_map.end()) {
		PgSQL_GTID_Server_Data * gtid_si = it->second;
		if (gtid_si) {
			gtid_si->active = false;
		}
		it++;
	}

	// NOTE: We are required to lock while iterating over 'MyHostGroups'. Otherwise race conditions could take place,
	// e.g. servers could be purged by 'purge_pgsql_servers_table' and invalid memory be accessed.
	wrlock();
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
		PgSQL_HGC *myhgc=(PgSQL_HGC *)MyHostGroups->index(i);
		PgSQL_SrvC *mysrvc=NULL;
		for (unsigned int j=0; j<myhgc->mysrvs->servers->len; j++) {
			mysrvc=myhgc->mysrvs->idx(j);
			if (mysrvc->gtid_port) {
				std::string s1 = mysrvc->address;
				s1.append(":");
				s1.append(std::to_string(mysrvc->port));
				std::unordered_map <string, PgSQL_GTID_Server_Data *>::iterator it2;
				it2 = gtid_map.find(s1);
				PgSQL_GTID_Server_Data *gtid_is=NULL;
				if (it2!=gtid_map.end()) {
					gtid_is=it2->second;
					if (gtid_is == NULL) {
						gtid_map.erase(it2);
					}
				}
				if (gtid_is) {
					gtid_is->active = true;
				} else if (mysrvc->status != MYSQL_SERVER_STATUS_OFFLINE_HARD) {
					// we didn't find it. Create it
					/*
					struct ev_io *watcher = (struct ev_io *)malloc(sizeof(struct ev_io));
					gtid_is = new PgSQL_GTID_Server_Data(watcher, mysrvc->address, mysrvc->port, mysrvc->gtid_port);
					gtid_map.emplace(s1,gtid_is);
					*/
					struct ev_io * c = NULL;
					c = new_connector(mysrvc->address, mysrvc->gtid_port, mysrvc->port);
					if (c) {
						gtid_is = (PgSQL_GTID_Server_Data *)c->data;
						gtid_map.emplace(s1,gtid_is);
						//pthread_mutex_lock(&ev_loop_mutex);
						ev_io_start(PgHGM->gtid_ev_loop,c);
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
		PgSQL_GTID_Server_Data * gtid_si = it->second;
		if (gtid_si && gtid_si->active == false) {
			to_remove.push_back(it->first);
		}
		it++;
	}
	for (std::vector<string>::iterator it3=to_remove.begin(); it3!=to_remove.end(); ++it3) {
		it = gtid_map.find(*it3);
		PgSQL_GTID_Server_Data * gtid_si = it->second;
		ev_io_stop(PgHGM->gtid_ev_loop, gtid_si->w);
		close(gtid_si->w->fd);
		free(gtid_si->w);
		gtid_map.erase(*it3);
	}
	pthread_rwlock_unlock(&gtid_rwlock);
#endif // 0
}

void PgSQL_HostGroups_Manager::purge_pgsql_servers_table() {
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
		PgSQL_HGC *myhgc=(PgSQL_HGC *)MyHostGroups->index(i);
		PgSQL_SrvC *mysrvc=NULL;
		for (unsigned int j=0; j<myhgc->mysrvs->servers->len; j++) {
			mysrvc=myhgc->mysrvs->idx(j);
			if (mysrvc->status==MYSQL_SERVER_STATUS_OFFLINE_HARD) {
				if (mysrvc->ConnectionsUsed->conns_length()==0 && mysrvc->ConnectionsFree->conns_length()==0) {
					// no more connections for OFFLINE_HARD server, removing it
					mysrvc=(PgSQL_SrvC *)myhgc->mysrvs->servers->remove_index_fast(j);
					j--;
					delete mysrvc;
				}
			}
		}
	}
}



void PgSQL_HostGroups_Manager::generate_pgsql_servers_table(int *_onlyhg) {
	int rc;
	sqlite3_stmt *statement1=NULL;
	sqlite3_stmt *statement32=NULL;

	PtrArray *lst=new PtrArray();
	//sqlite3 *mydb3=mydb->get_db();
	char *query1=(char *)"INSERT INTO pgsql_servers VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query1, -1, &statement1, 0);
	rc = mydb->prepare_v2(query1, &statement1);
	ASSERT_SQLITE_OK(rc, mydb);
	std::string query32s = "INSERT INTO pgsql_servers VALUES " + generate_multi_rows_query(32,13);
	char *query32 = (char *)query32s.c_str();
	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query32, -1, &statement32, 0);
	rc = mydb->prepare_v2(query32, &statement32);
	ASSERT_SQLITE_OK(rc, mydb);

	if (pgsql_thread___hostgroup_manager_verbose) {
		if (_onlyhg==NULL) {
			proxy_info("Dumping current MySQL Servers structures for hostgroup ALL\n");
		} else {
			int hidonly=*_onlyhg;
			proxy_info("Dumping current MySQL Servers structures for hostgroup %d\n", hidonly);
		}
	}
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
		PgSQL_HGC *myhgc=(PgSQL_HGC *)MyHostGroups->index(i);
		if (_onlyhg) {
			int hidonly=*_onlyhg;
			if (myhgc->hid!=(unsigned int)hidonly) {
				// skipping this HG
				continue;
			}
		}
		PgSQL_SrvC *mysrvc=NULL;
		for (unsigned int j=0; j<myhgc->mysrvs->servers->len; j++) {
			mysrvc=myhgc->mysrvs->idx(j);
			if (pgsql_thread___hostgroup_manager_verbose) {
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
				fprintf(stderr,"HID: %d , address: %s , port: %d , gtid_port: %d , weight: %ld , status: %s , max_connections: %ld , max_replication_lag: %u , use_ssl: %u , max_latency_ms: %u , comment: %s\n", mysrvc->myhgc->hid, mysrvc->address, mysrvc->port, mysrvc->gtid_port, mysrvc->weight, st, mysrvc->max_connections, mysrvc->max_replication_lag, mysrvc->use_ssl, mysrvc->max_latency_us*1000, mysrvc->comment);
			}
			lst->add(mysrvc);
			if (lst->len==32) {
				while (lst->len) {
					int i=lst->len;
					i--;
					PgSQL_SrvC *mysrvc=(PgSQL_SrvC *)lst->remove_index_fast(0);
					uintptr_t ptr=(uintptr_t)mysrvc;
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+1, mysrvc->myhgc->hid); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_text)(statement32, (i*13)+2, mysrvc->address, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+3, mysrvc->port); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+4, mysrvc->gtid_port); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+5, mysrvc->weight); ASSERT_SQLITE_OK(rc, mydb);
					rc=(*proxy_sqlite3_bind_int64)(statement32, (i*13)+6, mysrvc->status); ASSERT_SQLITE_OK(rc, mydb);
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
		PgSQL_SrvC *mysrvc=(PgSQL_SrvC *)lst->remove_index_fast(0);
		uintptr_t ptr=(uintptr_t)mysrvc;
		rc=(*proxy_sqlite3_bind_int64)(statement1, 1, mysrvc->myhgc->hid); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_text)(statement1, 2, mysrvc->address, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 3, mysrvc->port); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 4, mysrvc->gtid_port); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 5, mysrvc->weight); ASSERT_SQLITE_OK(rc, mydb);
		rc=(*proxy_sqlite3_bind_int64)(statement1, 6, mysrvc->status); ASSERT_SQLITE_OK(rc, mydb);
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
	if (pgsql_thread___hostgroup_manager_verbose) {
		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		if (_onlyhg==NULL) {
			mydb->execute_statement((char *)"SELECT hostgroup_id hid, hostname, port, gtid_port gtid, weight, status, compression cmp, max_connections max_conns, max_replication_lag max_lag, use_ssl ssl, max_latency_ms max_lat, comment, mem_pointer FROM pgsql_servers", &error , &cols , &affected_rows , &resultset);
		} else {
			int hidonly=*_onlyhg;
			char *q1 = (char *)malloc(256);
			sprintf(q1,"SELECT hostgroup_id hid, hostname, port, gtid_port gtid, weight, status, compression cmp, max_connections max_conns, max_replication_lag max_lag, use_ssl ssl, max_latency_ms max_lat, comment, mem_pointer FROM pgsql_servers WHERE hostgroup_id=%d" , hidonly);
			mydb->execute_statement(q1, &error , &cols , &affected_rows , &resultset);
			free(q1);
		}
		if (error) {
			proxy_error("Error on read from pgsql_servers : %s\n", error);
		} else {
			if (resultset) {
				if (_onlyhg==NULL) {
					proxy_info("Dumping pgsql_servers: ALL\n");
				} else {
					int hidonly=*_onlyhg;
					proxy_info("Dumping pgsql_servers: HG %d\n", hidonly);
				}
				resultset->dump_to_stderr();
			}
		}
		if (resultset) { delete resultset; resultset=NULL; }
	}
	delete lst;
}

void PgSQL_HostGroups_Manager::generate_pgsql_replication_hostgroups_table() {
	if (incoming_replication_hostgroups==NULL)
		return;
	if (pgsql_thread___hostgroup_manager_verbose) {
		proxy_info("New pgsql_replication_hostgroups table\n");
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
			sprintf(query,"INSERT INTO pgsql_replication_hostgroups VALUES(%s,%s,'%s','%s')",r->fields[0], r->fields[1], r->fields[2], o);
			if (o!=r->fields[3]) { // there was a copy
				free(o);
			}
		//} else {
			//sprintf(query,"INSERT INTO pgsql_replication_hostgroups VALUES(%s,%s,NULL)",r->fields[0],r->fields[1]);
		//}
		mydb->execute(query);
		if (pgsql_thread___hostgroup_manager_verbose) {
			fprintf(stderr,"writer_hostgroup: %s , reader_hostgroup: %s, check_type %s, comment: %s\n", r->fields[0],r->fields[1], r->fields[2], r->fields[3]);
		}
		free(query);
	}
	incoming_replication_hostgroups=NULL;
}

void PgSQL_HostGroups_Manager::update_table_pgsql_servers_for_monitor(bool lock) {
	if (lock) {
		wrlock();
	}

	std::lock_guard<std::mutex> pgsql_servers_lock(this->pgsql_servers_to_monitor_mutex);

	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* resultset = NULL;
	char* query = const_cast<char*>("SELECT hostname, port, status, use_ssl FROM pgsql_servers WHERE status != 3 GROUP BY hostname, port");

	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
	mydb->execute_statement(query, &error , &cols , &affected_rows , &resultset);

	if (error != nullptr) {
		proxy_error("Error on read from pgsql_servers : %s\n", error);
	} else {
		if (resultset != nullptr) {
			delete this->pgsql_servers_to_monitor;
			this->pgsql_servers_to_monitor = resultset;
		}
	}

	if (lock) {
		wrunlock();
	}

	MySQL_Monitor::trigger_dns_cache_update();
}

SQLite3_result * PgSQL_HostGroups_Manager::dump_table_pgsql(const string& name) {
	char * query = (char *)"";
	if (name == "pgsql_replication_hostgroups") {
		query=(char *)"SELECT writer_hostgroup, reader_hostgroup, check_type, comment FROM pgsql_replication_hostgroups";
	} else if (name == "pgsql_hostgroup_attributes") {
		query=(char *)"SELECT hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, init_connect, multiplex, connection_warming, throttle_connections_per_sec, ignore_session_variables, hostgroup_settings, servers_defaults, comment FROM pgsql_hostgroup_attributes ORDER BY hostgroup_id";
	} else if (name == "pgsql_servers") {
		query = (char *)PGHGM_GEN_ADMIN_RUNTIME_SERVERS;
	} else if (name == "cluster_pgsql_servers") {
		query = (char *)PGHGM_GEN_CLUSTER_ADMIN_RUNTIME_SERVERS;
	} else {
		assert(0);
	}
	wrlock();
	if (name == "pgsql_servers") {
		purge_pgsql_servers_table();
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM pgsql_servers\n");
		mydb->execute("DELETE FROM pgsql_servers");
		generate_pgsql_servers_table();
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


PgSQL_HGC * PgSQL_HostGroups_Manager::MyHGC_create(unsigned int _hid) {
	PgSQL_HGC *myhgc=new PgSQL_HGC(_hid);
	return myhgc;
}

PgSQL_HGC * PgSQL_HostGroups_Manager::MyHGC_find(unsigned int _hid) {
	if (MyHostGroups->len < 100) {
		// for few HGs, we use the legacy search
		for (unsigned int i=0; i<MyHostGroups->len; i++) {
			PgSQL_HGC *myhgc=(PgSQL_HGC *)MyHostGroups->index(i);
			if (myhgc->hid==_hid) {
				return myhgc;
			}
		}
	} else {
		// for a large number of HGs, we use the unordered_map
		// this search is slower for a small number of HGs, therefore we use
		// it only for large number of HGs
		std::unordered_map<unsigned int, PgSQL_HGC *>::const_iterator it = MyHostGroups_map.find(_hid);
		if (it != MyHostGroups_map.end()) {
			PgSQL_HGC *myhgc = it->second;
			return myhgc;
		}
	}
	return NULL;
}

PgSQL_HGC * PgSQL_HostGroups_Manager::MyHGC_lookup(unsigned int _hid) {
	PgSQL_HGC *myhgc=NULL;
	myhgc=MyHGC_find(_hid);
	if (myhgc==NULL) {
		myhgc=MyHGC_create(_hid);
	} else {
		return myhgc;
	}
	assert(myhgc);
	MyHostGroups->add(myhgc);
	MyHostGroups_map.emplace(_hid,myhgc);
	return myhgc;
}

void PgSQL_HostGroups_Manager::increase_reset_counter() {
	wrlock();
	status.myconnpoll_reset++;
	wrunlock();
}
void PgSQL_HostGroups_Manager::push_MyConn_to_pool(PgSQL_Connection *c, bool _lock) {
	assert(c->parent);
	PgSQL_SrvC *mysrvc=NULL;
	if (_lock)
		wrlock();
	c->auto_increment_delay_token = 0;
	status.myconnpoll_push++;
	mysrvc=(PgSQL_SrvC *)c->parent;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning PgSQL_Connection %p, server %s:%d with status %d\n", c, mysrvc->address, mysrvc->port, mysrvc->status);
	mysrvc->ConnectionsUsed->remove(c);
	if (GloMTH == NULL) { goto __exit_push_MyConn_to_pool; }
	if (c->largest_query_length > (unsigned int)GloMTH->variables.threshold_query_length) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying PgSQL_Connection %p, server %s:%d with status %d . largest_query_length = %lu\n", c, mysrvc->address, mysrvc->port, mysrvc->status, c->largest_query_length);
		delete c;
		goto __exit_push_MyConn_to_pool;
	}
	if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) {
		if (c->async_state_machine==ASYNC_IDLE) {
			if (GloMTH == NULL) { goto __exit_push_MyConn_to_pool; }
			if (c->local_stmts->get_num_backend_stmts() > (unsigned int)GloMTH->variables.max_stmts_per_connection) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying PgSQL_Connection %p, server %s:%d with status %d because has too many prepared statements\n", c, mysrvc->address, mysrvc->port, mysrvc->status);
//				delete c;
				mysrvc->ConnectionsUsed->add(c);
				destroy_MyConn_from_pool(c, false);
			} else {
				c->optimize();
				mysrvc->ConnectionsFree->add(c);
			}
		} else {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying PgSQL_Connection %p, server %s:%d with status %d\n", c, mysrvc->address, mysrvc->port, mysrvc->status);
			delete c;
		}
	} else {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying PgSQL_Connection %p, server %s:%d with status %d\n", c, mysrvc->address, mysrvc->port, mysrvc->status);
		delete c;
	}
__exit_push_MyConn_to_pool:
	if (_lock)
		wrunlock();
}

void PgSQL_HostGroups_Manager::push_MyConn_to_pool_array(PgSQL_Connection **ca, unsigned int cnt) {
	unsigned int i=0;
	PgSQL_Connection *c=NULL;
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

PgSQL_SrvC *PgSQL_HGC::get_random_MySrvC(char * gtid_uuid, uint64_t gtid_trxid, int max_lag_ms, PgSQL_Session *sess) {
	PgSQL_SrvC *mysrvc=NULL;
	unsigned int j;
	unsigned int sum=0;
	unsigned int TotalUsedConn=0;
	unsigned int l=mysrvs->cnt();
	static time_t last_hg_log = 0;
#ifdef TEST_AURORA
	unsigned long long a1 = array_mysrvc_total/10000;
	array_mysrvc_total += l;
	unsigned long long a2 = array_mysrvc_total/10000;
	if (a2 > a1) {
		fprintf(stderr, "Total: %llu, Candidates: %llu\n", array_mysrvc_total-l, array_mysrvc_cands);
	}
#endif // TEST_AURORA
	PgSQL_SrvC *mysrvcCandidates_static[32];
	PgSQL_SrvC **mysrvcCandidates = mysrvcCandidates_static;
	unsigned int num_candidates = 0;
	bool max_connections_reached = false;
	if (l>32) {
		mysrvcCandidates = (PgSQL_SrvC **)malloc(sizeof(PgSQL_SrvC *)*l);
	}
	if (l) {
		//int j=0;
		for (j=0; j<l; j++) {
			mysrvc=mysrvs->idx(j);
			if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) { // consider this server only if ONLINE
				if (mysrvc->ConnectionsUsed->conns_length() < mysrvc->max_connections) { // consider this server only if didn't reach max_connections
					if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : pgsql_thread___default_max_latency_ms *1000 ) ) { // consider the host only if not too far
						if (gtid_trxid) {
							if (PgHGM->gtid_exists(mysrvc, gtid_uuid, gtid_trxid)) {
								sum+=mysrvc->weight;
								TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
								mysrvcCandidates[num_candidates]=mysrvc;
								num_candidates++;
							}
						} else {
							if (max_lag_ms >= 0) {
								if ((unsigned int)max_lag_ms >= mysrvc->aws_aurora_current_lag_us/1000) {
									sum+=mysrvc->weight;
									TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
									mysrvcCandidates[num_candidates]=mysrvc;
									num_candidates++;
								} else {
									sess->thread->status_variables.stvar[st_var_aws_aurora_replicas_skipped_during_query]++;
								}
							} else {
								sum+=mysrvc->weight;
								TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
								mysrvcCandidates[num_candidates]=mysrvc;
								num_candidates++;
							}
						}
					}
				} else {
					max_connections_reached = true;
				}
			} else {
				if (mysrvc->status==MYSQL_SERVER_STATUS_SHUNNED) {
					// try to recover shunned servers
					if (mysrvc->shunned_automatic && pgsql_thread___shun_recovery_time_sec) {
						time_t t;
						t=time(NULL);
						// we do all these changes without locking . We assume the server is not used from long
						// even if the server is still in used and any of the follow command fails it is not critical
						// because this is only an attempt to recover a server that is probably dead anyway

						// the next few lines of code try to solve issue #530
						int max_wait_sec = (pgsql_thread___shun_recovery_time_sec * 1000 >= pgsql_thread___connect_timeout_server_max ? pgsql_thread___connect_timeout_server_max /1000 - 1 : pgsql_thread___shun_recovery_time_sec);
						if (max_wait_sec < 1) { // min wait time should be at least 1 second
							max_wait_sec = 1;
						}
						if (t > mysrvc->time_last_detected_error && (t - mysrvc->time_last_detected_error) > max_wait_sec) {
							if (
								(mysrvc->shunned_and_kill_all_connections==false) // it is safe to bring it back online
								||
								(mysrvc->shunned_and_kill_all_connections==true && mysrvc->ConnectionsUsed->conns_length()==0 && mysrvc->ConnectionsFree->conns_length()==0) // if shunned_and_kill_all_connections is set, ensure all connections are already dropped
							) {
#ifdef DEBUG
								if (GloMTH->variables.hostgroup_manager_verbose >= 3) {
									proxy_info("Unshunning server %s:%d.\n", mysrvc->address, mysrvc->port);
								}
#endif
								mysrvc->status=MYSQL_SERVER_STATUS_ONLINE;
								mysrvc->shunned_automatic=false;
								mysrvc->shunned_and_kill_all_connections=false;
								mysrvc->connect_ERR_at_time_last_detected_error=0;
								mysrvc->time_last_detected_error=0;
								// note: the following function scans all the hostgroups.
								// This is ok for now because we only have a global mutex.
								// If one day we implement a mutex per hostgroup (unlikely,
								// but possible), this must be taken into consideration
								if (pgsql_thread___unshun_algorithm == 1) {
									PgHGM->unshun_server_all_hostgroups(mysrvc->address, mysrvc->port, t, max_wait_sec, &mysrvc->myhgc->hid);
								}
								// if a server is taken back online, consider it immediately
								if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : pgsql_thread___default_max_latency_ms *1000 ) ) { // consider the host only if not too far
									if (gtid_trxid) {
										if (PgHGM->gtid_exists(mysrvc, gtid_uuid, gtid_trxid)) {
											sum+=mysrvc->weight;
											TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
											mysrvcCandidates[num_candidates]=mysrvc;
											num_candidates++;
										}
									} else {
										if (max_lag_ms >= 0) {
											if ((unsigned int)max_lag_ms >= mysrvc->aws_aurora_current_lag_us/1000) {
												sum+=mysrvc->weight;
												TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
												mysrvcCandidates[num_candidates]=mysrvc;
												num_candidates++;
											}
										} else {
											sum+=mysrvc->weight;
											TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
											mysrvcCandidates[num_candidates]=mysrvc;
											num_candidates++;
										}
									}
								}
							}
						}
					}
				}
			}
		}
		if (max_lag_ms > 0) { // we are using AWS Aurora, as this logic is implemented only here
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
		if (sum==0) {
			// per issue #531 , we try a desperate attempt to bring back online any shunned server
			// we do this lowering the maximum wait time to 10%
			// most of the follow code is copied from few lines above
			time_t t;
			t=time(NULL);
			int max_wait_sec = (pgsql_thread___shun_recovery_time_sec * 1000 >= pgsql_thread___connect_timeout_server_max ? pgsql_thread___connect_timeout_server_max /10000 - 1 : pgsql_thread___shun_recovery_time_sec /10 );
			if (max_wait_sec < 1) { // min wait time should be at least 1 second
				max_wait_sec = 1;
			}
			if (t - last_hg_log > 1) { // log this at most once per second to avoid spamming the logs
				last_hg_log = time(NULL);

				if (gtid_trxid) {
					proxy_error("Hostgroup %u has no servers ready for GTID '%s:%ld'. Waiting for replication...\n", hid, gtid_uuid, gtid_trxid);
				} else {
					proxy_error("Hostgroup %u has no servers available%s! Checking servers shunned for more than %u second%s\n", hid,
						(max_connections_reached ? " or max_connections reached for all servers" : ""), max_wait_sec, max_wait_sec == 1 ? "" : "s");
				}
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
						if ( mysrvc->current_latency_us < ( mysrvc->max_latency_us ? mysrvc->max_latency_us : pgsql_thread___default_max_latency_ms *1000 ) ) { // consider the host only if not too far
							if (gtid_trxid) {
								if (PgHGM->gtid_exists(mysrvc, gtid_uuid, gtid_trxid)) {
									sum+=mysrvc->weight;
									TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
									mysrvcCandidates[num_candidates]=mysrvc;
									num_candidates++;
								}
							} else {
								if (max_lag_ms >= 0) {
									if ((unsigned int)max_lag_ms >= mysrvc->aws_aurora_current_lag_us/1000) {
										sum+=mysrvc->weight;
										TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
										mysrvcCandidates[num_candidates]=mysrvc;
										num_candidates++;
									}
								} else {
									sum+=mysrvc->weight;
									TotalUsedConn+=mysrvc->ConnectionsUsed->conns_length();
									mysrvcCandidates[num_candidates]=mysrvc;
									num_candidates++;
								}
							}
						}
					}
				}
			}
		}
		if (sum==0) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning PgSQL_SrvC NULL because no backend ONLINE or with weight\n");
			if (l>32) {
				free(mysrvcCandidates);
			}
#ifdef TEST_AURORA
			array_mysrvc_cands += num_candidates;
#endif // TEST_AURORA
			return NULL; // if we reach here, we couldn't find any target
		}

/*
		unsigned int New_sum=0;
		unsigned int New_TotalUsedConn=0;
		// we will now scan again to ignore overloaded servers
		for (j=0; j<num_candidates; j++) {
			mysrvc = mysrvcCandidates[j];
			unsigned int len=mysrvc->ConnectionsUsed->conns_length();
			if ((len * sum) <= (TotalUsedConn * mysrvc->weight * 1.5 + 1)) {

				New_sum+=mysrvc->weight;
				New_TotalUsedConn+=len;
			} else {
				// remove the candidate
				if (j+1 < num_candidates) {
					mysrvcCandidates[j] = mysrvcCandidates[num_candidates-1];
				}
				j--;
				num_candidates--;
			}
		}
*/

		unsigned int New_sum=sum;

		if (New_sum==0) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning PgSQL_SrvC NULL because no backend ONLINE or with weight\n");
			if (l>32) {
				free(mysrvcCandidates);
			}
#ifdef TEST_AURORA
			array_mysrvc_cands += num_candidates;
#endif // TEST_AURORA
			return NULL; // if we reach here, we couldn't find any target
		}

		// latency awareness algorithm is enabled only when compiled with USE_MYSRVC_ARRAY
		if (sess && sess->thread->variables.min_num_servers_lantency_awareness) {
			if ((int) num_candidates >= sess->thread->variables.min_num_servers_lantency_awareness) {
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
					sess->thread->status_variables.stvar[st_var_ConnPool_get_conn_latency_awareness]++;
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


		unsigned int k;
		if (New_sum > 32768) {
			k=rand()%New_sum;
		} else {
			k=fastrand()%New_sum;
		}
		k++;
		New_sum=0;

		for (j=0; j<num_candidates; j++) {
			mysrvc = mysrvcCandidates[j];
			New_sum+=mysrvc->weight;
			if (k<=New_sum) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning PgSQL_SrvC %p, server %s:%d\n", mysrvc, mysrvc->address, mysrvc->port);
				if (l>32) {
					free(mysrvcCandidates);
				}
#ifdef TEST_AURORA
				array_mysrvc_cands += num_candidates;
#endif // TEST_AURORA
				return mysrvc;
			}
		}
	} else {
		time_t t = time(NULL);

		if (t - last_hg_log > 1) {
			last_hg_log = time(NULL);
			proxy_error("Hostgroup %u has no servers available!\n", hid);
		}
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning PgSQL_SrvC NULL\n");
	if (l>32) {
		free(mysrvcCandidates);
	}
#ifdef TEST_AURORA
	array_mysrvc_cands += num_candidates;
#endif // TEST_AURORA
	return NULL; // if we reach here, we couldn't find any target
}

//unsigned int PgSQL_SrvList::cnt() {
//	return servers->len;
//}

//PgSQL_SrvC * PgSQL_SrvList::idx(unsigned int i) { return (PgSQL_SrvC *)servers->index(i); }

void PgSQL_SrvConnList::get_random_MyConn_inner_search(unsigned int start, unsigned int end, unsigned int& conn_found_idx, unsigned int& connection_quality_level, unsigned int& number_of_matching_session_variables, const PgSQL_Connection * client_conn) {
	char *schema = client_conn->userinfo->schemaname;
	PgSQL_Connection * conn=NULL;
	unsigned int k;
	for (k = start;  k < end; k++) {
		conn = (PgSQL_Connection *)conns->index(k);
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
					int rca = pgsql_thread___reset_connection_algorithm;
					if (rca==1) {
						int ql = GloMTH->variables.connpoll_reset_queue_length;
						if (ql==0) {
							// if:
							// pgsql-reset_connection_algorithm=1 and
							// pgsql-connpoll_reset_queue_length=0
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



PgSQL_Connection * PgSQL_SrvConnList::get_random_MyConn(PgSQL_Session *sess, bool ff) {
	PgSQL_Connection * conn=NULL;
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
	bool connection_warming = pgsql_thread___connection_warming;
	int free_connections_pct = pgsql_thread___free_connections_pct;
	if (mysrvc->myhgc->attributes.configured == true) {
		// pgsql_hostgroup_attributes takes priority
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
			PgSQL_Connection * client_conn = sess->client_myds->myconn;
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
								PgSQL_Connection* conn = mysrvc->ConnectionsFree->remove(0);
								delete conn;

								conns_free = mysrvc->ConnectionsFree->conns_length();
								connections_to_free -= 1;
							}
						}

						// we must create a new connection
						conn = new PgSQL_Connection();
						conn->parent=mysrvc;
						// if attributes.multiplex == true , STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG is set to false. And vice-versa
						conn->set_status(!conn->parent->myhgc->attributes.multiplex, STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG);
						__sync_fetch_and_add(&PgHGM->status.server_connections_created, 1);
						proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
					}
					break;
				case 1: //tracked options are OK , but CHANGE USER is required
					// we may consider creating a new connection
					{
					unsigned int conns_free = mysrvc->ConnectionsFree->conns_length();
					unsigned int conns_used = mysrvc->ConnectionsUsed->conns_length();
					if ((conns_used > conns_free) && (mysrvc->max_connections > (conns_free/2 + conns_used/2)) ) {
						conn = new PgSQL_Connection();
						conn->parent=mysrvc;
						// if attributes.multiplex == true , STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG is set to false. And vice-versa
						conn->set_status(!conn->parent->myhgc->attributes.multiplex, STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG);
						__sync_fetch_and_add(&PgHGM->status.server_connections_created, 1);
						proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
					} else {
						conn=(PgSQL_Connection *)conns->remove_index_fast(conn_found_idx);
					}
					}
					break;
				case 2: // tracked options are OK , CHANGE USER is not required, but some SET statement or INIT_DB needs to be executed
				case 3: // tracked options are OK , CHANGE USER is not required, and it seems that SET statements or INIT_DB ARE not required
					// here we return the best connection we have, no matter if connection_quality_level is 2 or 3
					conn=(PgSQL_Connection *)conns->remove_index_fast(conn_found_idx);
					break;
				default: // this should never happen
					// LCOV_EXCL_START
					assert(0);
					break;
					// LCOV_EXCL_STOP
			}
		} else {
			conn=(PgSQL_Connection *)conns->remove_index_fast(i);
		}
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
		return conn;
	} else {
		unsigned long long curtime = monotonic_time();
		curtime = curtime / 1000 / 1000; // convert to second
		PgSQL_HGC *_myhgc = mysrvc->myhgc;
		if (curtime > _myhgc->current_time_now) {
			_myhgc->current_time_now = curtime;
			_myhgc->new_connections_now = 0;
		}
		_myhgc->new_connections_now++;
		unsigned int throttle_connections_per_sec_to_hostgroup = (unsigned int) pgsql_thread___throttle_connections_per_sec_to_hostgroup;
		if (_myhgc->attributes.configured == true) {
			// pgsql_hostgroup_attributes takes priority
			throttle_connections_per_sec_to_hostgroup = _myhgc->attributes.throttle_connections_per_sec;
		}
		if (_myhgc->new_connections_now > (unsigned int) throttle_connections_per_sec_to_hostgroup) {
			__sync_fetch_and_add(&PgHGM->status.server_connections_delayed, 1);
			return NULL;
		} else {
			conn = new PgSQL_Connection();
			conn->parent=mysrvc;
			// if attributes.multiplex == true , STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG is set to false. And vice-versa
			conn->set_status(!conn->parent->myhgc->attributes.multiplex, STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG);
			__sync_fetch_and_add(&PgHGM->status.server_connections_created, 1);
			proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Returning MySQL Connection %p, server %s:%d\n", conn, conn->parent->address, conn->parent->port);
			return  conn;
		}
	}
	return NULL; // never reach here
}

void PgSQL_HostGroups_Manager::unshun_server_all_hostgroups(const char * address, uint16_t port, time_t t, int max_wait_sec, unsigned int *skip_hid) {
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
		PgSQL_HGC *myhgc=(PgSQL_HGC *)MyHostGroups->index(i);
		if (skip_hid != NULL && myhgc->hid == *skip_hid) {
			// if skip_hid is not NULL, we skip that specific hostgroup
			continue;
		}
		bool found = false; // was this server already found in this hostgroup?
		for (j=0; found==false && j<(int)myhgc->mysrvs->cnt(); j++) {
			PgSQL_SrvC *mysrvc=(PgSQL_SrvC *)myhgc->mysrvs->servers->index(j);
			if (mysrvc->status==MYSQL_SERVER_STATUS_SHUNNED) {
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
							mysrvc->status=MYSQL_SERVER_STATUS_ONLINE;
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

PgSQL_Connection * PgSQL_HostGroups_Manager::get_MyConn_from_pool(unsigned int _hid, PgSQL_Session *sess, bool ff, char * gtid_uuid, uint64_t gtid_trxid, int max_lag_ms) {
	PgSQL_Connection * conn=NULL;
	wrlock();
	status.myconnpoll_get++;
	PgSQL_HGC *myhgc=MyHGC_lookup(_hid);
	PgSQL_SrvC *mysrvc = NULL;
#ifdef TEST_AURORA
	for (int i=0; i<10; i++)
#endif // TEST_AURORA
	mysrvc = myhgc->get_random_MySrvC(gtid_uuid, gtid_trxid, max_lag_ms, sess);
	if (mysrvc) { // a PgSQL_SrvC exists. If not, we return NULL = no targets
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

void PgSQL_HostGroups_Manager::destroy_MyConn_from_pool(PgSQL_Connection *c, bool _lock) {
	bool to_del=true; // the default, legacy behavior
	PgSQL_SrvC *mysrvc=(PgSQL_SrvC *)c->parent;
	if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE && c->send_quit && queue.size() < __sync_fetch_and_add(&GloMTH->variables.connpoll_reset_queue_length,0)) {
		if (c->async_state_machine==ASYNC_IDLE) {
			// overall, the backend seems healthy and so it is the connection. Try to reset it
			if (c->is_connection_in_reusable_state() == false) {
				// client library error . We must not try to save the connection
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Not trying to reset PgSQL_Connection %p, server %s:%d . Error %s\n", c, mysrvc->address, mysrvc->port, c->get_error_code_with_message().c_str());
			} else {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Trying to reset PgSQL_Connection %p, server %s:%d\n", c, mysrvc->address, mysrvc->port);
				to_del=false;
				queue.add(c);
			}
		} else {
		// the connection seems health, but we are trying to destroy it
		// probably because there is a long running query
		// therefore we will try to kill the connection
			if (pgsql_thread___kill_backend_connection_when_disconnect) {
				int myerr=mysql_errno(c->pgsql);
				switch (myerr) {
					case 1231:
						break;
					default:
					if (c->pgsql->thread_id) {
						PgSQL_Connection_userinfo *ui=c->userinfo;
						char *auth_password=NULL;
						if (ui->password) {
							if (ui->password[0]=='*') { // we don't have the real password, let's pass sha1
								auth_password=ui->sha1_pass;
							} else {
								auth_password=ui->password;
							}
						}
						KillArgs *ka = new KillArgs(ui->username, auth_password, c->parent->address, c->parent->port, c->parent->myhgc->hid, c->pgsql->thread_id, KILL_CONNECTION, c->parent->use_ssl, NULL, c->connected_host_details.ip);
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
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Destroying PgSQL_Connection %p, server %s:%d\n", c, mysrvc->address, mysrvc->port);
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

void reset_hg_attrs_server_defaults(PgSQL_SrvC* mysrvc) {
	mysrvc->weight = -1;
	mysrvc->max_connections = -1;
	mysrvc->use_ssl = -1;
}

void update_hg_attrs_server_defaults(PgSQL_SrvC* mysrvc, PgSQL_HGC* myhgc) {
	if (mysrvc->weight == -1) {
		if (myhgc->servers_defaults.weight != -1) {
			mysrvc->weight = myhgc->servers_defaults.weight;
		} else {
			// Same harcoded default as in 'CREATE TABLE pgsql_servers ...'
			mysrvc->weight = 1;
		}
	}
	if (mysrvc->max_connections == -1) {
		if (myhgc->servers_defaults.max_connections != -1) {
			mysrvc->max_connections = myhgc->servers_defaults.max_connections;
		} else {
			// Same harcoded default as in 'CREATE TABLE pgsql_servers ...'
			mysrvc->max_connections = 1000;
		}
	}
	if (mysrvc->use_ssl == -1) {
		if (myhgc->servers_defaults.use_ssl != -1) {
			mysrvc->use_ssl = myhgc->servers_defaults.use_ssl;
		} else {
			// Same harcoded default as in 'CREATE TABLE pgsql_servers ...'
			mysrvc->use_ssl = 0;
		}
	}
}

void PgSQL_HostGroups_Manager::add(PgSQL_SrvC *mysrvc, unsigned int _hid) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Adding PgSQL_SrvC %p (%s:%d) for hostgroup %d\n", mysrvc, mysrvc->address, mysrvc->port, _hid);

	// Since metrics for servers are stored per-endpoint; the metrics for a particular endpoint can live longer than the
	// 'PgSQL_SrvC' itself. For example, a failover or a server config change could remove the server from a particular
	// hostgroup, and a subsequent one bring it back to the original hostgroup. For this reason, everytime a 'mysrvc' is
	// created and added to a particular hostgroup, we update the endpoint metrics for it.
	std::string endpoint_id { std::to_string(_hid) + ":" + string { mysrvc->address } + ":" + std::to_string(mysrvc->port) };

	mysrvc->bytes_recv = get_prometheus_counter_val(this->status.p_conn_pool_bytes_data_recv_map, endpoint_id);
	mysrvc->bytes_sent = get_prometheus_counter_val(this->status.p_conn_pool_bytes_data_sent_map, endpoint_id);
	mysrvc->connect_ERR = get_prometheus_counter_val(this->status.p_connection_pool_conn_err_map, endpoint_id);
	mysrvc->connect_OK = get_prometheus_counter_val(this->status.p_connection_pool_conn_ok_map, endpoint_id);
	mysrvc->queries_sent = get_prometheus_counter_val(this->status.p_connection_pool_queries_map, endpoint_id);

	PgSQL_HGC *myhgc=MyHGC_lookup(_hid);
	update_hg_attrs_server_defaults(mysrvc, myhgc);
	myhgc->mysrvs->add(mysrvc);
}

void PgSQL_HostGroups_Manager::replication_lag_action_inner(PgSQL_HGC *myhgc, const char *address, unsigned int port, int current_replication_lag) {
	int j;
	for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
		PgSQL_SrvC *mysrvc=(PgSQL_SrvC *)myhgc->mysrvs->servers->index(j);
		if (strcmp(mysrvc->address,address)==0 && mysrvc->port==port) {
			if (mysrvc->status==MYSQL_SERVER_STATUS_ONLINE) {
				if (
//					(current_replication_lag==-1 )
//					||
					(
						current_replication_lag>=0 &&
						mysrvc->max_replication_lag > 0 && // see issue #4018
						((unsigned int)current_replication_lag > mysrvc->max_replication_lag)
					)
				) {
					// always increase the counter
					mysrvc->cur_replication_lag_count += 1;
					if (mysrvc->cur_replication_lag_count >= (unsigned int)mysql_thread___monitor_replication_lag_count) {
						proxy_warning("Shunning server %s:%d from HG %u with replication lag of %d second, count number: '%d'\n", address, port, myhgc->hid, current_replication_lag, mysrvc->cur_replication_lag_count);
						mysrvc->status=MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG;
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
				if (mysrvc->status==MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) {
					if (
						(current_replication_lag>=0 && ((unsigned int)current_replication_lag <= mysrvc->max_replication_lag))
						||
						(current_replication_lag==-2) // see issue 959
					) {
						mysrvc->status=MYSQL_SERVER_STATUS_ONLINE;
						proxy_warning("Re-enabling server %s:%d from HG %u with replication lag of %d second\n", address, port, myhgc->hid, current_replication_lag);
						mysrvc->cur_replication_lag_count = 0;
					}
				}
			}
			return;
		}
	}
}

void PgSQL_HostGroups_Manager::replication_lag_action(const std::list<replication_lag_server_t>& pgsql_servers) {

	//this method does not use admin table, so this lock is not needed. 
	//GloAdmin->mysql_servers_wrlock();
	unsigned long long curtime1 = monotonic_time();
	wrlock();

	for (const auto& server : pgsql_servers) {

		const int hid = std::get<PgSQL_REPLICATION_LAG_SERVER_T::PG_RLS_HOSTGROUP_ID>(server);
		const std::string& address = std::get<PgSQL_REPLICATION_LAG_SERVER_T::PG_RLS_ADDRESS>(server);
		const unsigned int port = std::get<PgSQL_REPLICATION_LAG_SERVER_T::PG_RLS_PORT>(server);
		const int current_replication_lag = std::get<PgSQL_REPLICATION_LAG_SERVER_T::PG_RLS_CURRENT_REPLICATION_LAG>(server);

		if (mysql_thread___monitor_replication_lag_group_by_host == false) {
			// legacy check. 1 check per server per hostgroup
			PgSQL_HGC *myhgc = MyHGC_find(hid);
			replication_lag_action_inner(myhgc,address.c_str(),port,current_replication_lag);
		}
		else {
			// only 1 check per server, no matter the hostgroup
			// all hostgroups must be searched
			for (unsigned int i=0; i<MyHostGroups->len; i++) {
				PgSQL_HGC*myhgc=(PgSQL_HGC*)MyHostGroups->index(i);
				replication_lag_action_inner(myhgc,address.c_str(),port,current_replication_lag);
			}
		}
	}

	wrunlock();
	//GloAdmin->mysql_servers_wrunlock();

	unsigned long long curtime2 = monotonic_time();
	curtime1 = curtime1 / 1000;
	curtime2 = curtime2 / 1000;
	proxy_debug(PROXY_DEBUG_MONITOR, 7, "PgSQL_HostGroups_Manager::replication_lag_action() locked for %llums (server count:%ld)\n", curtime2 - curtime1, pgsql_servers.size());
}

void PgSQL_HostGroups_Manager::drop_all_idle_connections() {
	// NOTE: the caller should hold wrlock
	int i, j;
	for (i=0; i<(int)MyHostGroups->len; i++) {
		PgSQL_HGC *myhgc=(PgSQL_HGC *)MyHostGroups->index(i);
		for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
			PgSQL_SrvC *mysrvc=(PgSQL_SrvC *)myhgc->mysrvs->servers->index(j);
			if (mysrvc->status!=MYSQL_SERVER_STATUS_ONLINE) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d is not online\n", mysrvc->address, mysrvc->port);
				//__sync_fetch_and_sub(&status.server_connections_connected, mysrvc->ConnectionsFree->conns->len);
				mysrvc->ConnectionsFree->drop_all_connections();
			}

			// Drop idle connections if beyond max_connection
			while (mysrvc->ConnectionsFree->conns_length() && mysrvc->ConnectionsUsed->conns_length()+mysrvc->ConnectionsFree->conns_length() > mysrvc->max_connections) {
				PgSQL_Connection *conn=mysrvc->ConnectionsFree->remove(0);
				delete conn;
			}

			//PtrArray *pa=mysrvc->ConnectionsFree->conns;
			PgSQL_SrvConnList *mscl=mysrvc->ConnectionsFree;
			int free_connections_pct = pgsql_thread___free_connections_pct;
			if (mysrvc->myhgc->attributes.configured == true) {
				// pgsql_hostgroup_attributes takes priority
				free_connections_pct = mysrvc->myhgc->attributes.free_connections_pct;
			}
			while (mscl->conns_length() > free_connections_pct*mysrvc->max_connections/100) {
				PgSQL_Connection *mc=mscl->remove(0);
				delete mc;
			}

			// drop all connections with life exceeding pgsql-connection_max_age
			if (pgsql_thread___connection_max_age_ms) {
				unsigned long long curtime=monotonic_time();
				int i=0;
				for (i=0; i<(int)mscl->conns_length() ; i++) {
					PgSQL_Connection *mc=mscl->index(i);
					unsigned long long intv = pgsql_thread___connection_max_age_ms;
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
int PgSQL_HostGroups_Manager::get_multiple_idle_connections(int _hid, unsigned long long _max_last_time_used, PgSQL_Connection **conn_list, int num_conn) {
	wrlock();
	drop_all_idle_connections();
	int num_conn_current=0;
	int j,k;
	PgSQL_HGC* myhgc = NULL;
	// Multimap holding the required info for accesing the oldest idle connections found.
	std::multimap<uint64_t,std::pair<PgSQL_SrvC*,int32_t>> oldest_idle_connections {};

	for (int i=0; i<(int)MyHostGroups->len; i++) {
		if (_hid == -1) {
			// all hostgroups must be examined
			// as of version 2.3.2 , this is always the case
			myhgc=(PgSQL_HGC *)MyHostGroups->index(i);
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
			PgSQL_SrvC *mysrvc=(PgSQL_SrvC *)myhgc->mysrvs->servers->index(j);
			//PtrArray *pa=mysrvc->ConnectionsFree->conns;
			PgSQL_SrvConnList *mscl=mysrvc->ConnectionsFree;
			for (k=0; k<(int)mscl->conns_length(); k++) {
				PgSQL_Connection *mc=mscl->index(k);
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
	// 1. Filter the found connections by 'PgSQL_SrvC'.
	// 2. Order by indexes on 'ConnectionsFree' in desc order.
	// 3. Move the conns from 'ConnectionsFree' into 'ConnectionsUsed'.
	std::unordered_map<PgSQL_SrvC*,vector<int>> mysrvcs_conns_idxs {};

	// 1. Filter the connections by 'PgSQL_SrvC'.
	//
	// We extract this for being able to later iterate through the obtained 'PgSQL_SrvC' using the conn indexes.
	for (const auto& conn_info : oldest_idle_connections) {
		PgSQL_SrvC* mysrvc = conn_info.second.first;
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
		PgSQL_SrvC* mysrvc = conn_info.first;

		for (const int conn_idx : conn_info.second) {
			PgSQL_SrvConnList* mscl = mysrvc->ConnectionsFree;
			PgSQL_Connection* mc = mscl->remove(conn_idx);
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

void PgSQL_HostGroups_Manager::save_incoming_pgsql_table(SQLite3_result *s, const string& name) {
	SQLite3_result ** inc = NULL;
	if (name == "pgsql_replication_hostgroups") {
		inc = &incoming_replication_hostgroups;
	} else if (name == "pgsql_hostgroup_attributes") {
		inc = &incoming_hostgroup_attributes;
	} else {
		assert(0);
	}
	if (*inc != nullptr) {
		delete *inc;
		*inc = nullptr;
	}
	*inc = s;
}

void PgSQL_HostGroups_Manager::save_runtime_pgsql_servers(SQLite3_result *s) {
	if (runtime_pgsql_servers) {
		delete runtime_pgsql_servers;
		runtime_pgsql_servers = nullptr;
	}
	runtime_pgsql_servers=s;
}

void PgSQL_HostGroups_Manager::save_pgsql_servers_v2(SQLite3_result* s) {
	if (incoming_pgsql_servers_v2) {
		delete incoming_pgsql_servers_v2;
		incoming_pgsql_servers_v2 = nullptr;
	}
	incoming_pgsql_servers_v2 = s;
}

SQLite3_result* PgSQL_HostGroups_Manager::get_current_pgsql_table(const string& name) {
	if (name == "pgsql_replication_hostgroups") {
		return this->incoming_replication_hostgroups;
	} else if (name == "pgsql_hostgroup_attributes") {
		return this->incoming_hostgroup_attributes;
	} else if (name == "cluster_pgsql_servers") {
		return this->runtime_pgsql_servers;
	} else if (name == "pgsql_servers_v2") {
		return this->incoming_pgsql_servers_v2;
	} else {
		assert(0);
	}
	return NULL;
}



SQLite3_result * PgSQL_HostGroups_Manager::SQL3_Free_Connections() {
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
	result->add_column_definition(SQLITE_TEXT,"pgsql_info");
	unsigned long long curtime = monotonic_time();
	wrlock();
	int i,j, k, l;
	for (i=0; i<(int)MyHostGroups->len; i++) {
		PgSQL_HGC *myhgc=(PgSQL_HGC *)MyHostGroups->index(i);
		for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
			PgSQL_SrvC *mysrvc=(PgSQL_SrvC *)myhgc->mysrvs->servers->index(j);
			if (mysrvc->status!=MYSQL_SERVER_STATUS_ONLINE) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d is not online\n", mysrvc->address, mysrvc->port);
				mysrvc->ConnectionsFree->drop_all_connections();
			}
			// drop idle connections if beyond max_connection
			while (mysrvc->ConnectionsFree->conns_length() && mysrvc->ConnectionsUsed->conns_length()+mysrvc->ConnectionsFree->conns_length() > mysrvc->max_connections) {
				//PgSQL_Connection *conn=(PgSQL_Connection *)mysrvc->ConnectionsFree->conns->remove_index_fast(0);
				PgSQL_Connection *conn=mysrvc->ConnectionsFree->remove(0);
				delete conn;
			}
			char buf[1024];
			for (l=0; l < (int) mysrvc->ConnectionsFree->conns_length(); l++) {
				char **pta=(char **)malloc(sizeof(char *)*colnum);
				PgSQL_Connection *conn = mysrvc->ConnectionsFree->index(l);
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
					MYSQL *_my = conn->pgsql;
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

void PgSQL_HostGroups_Manager::p_update_connection_pool_update_counter(
	const std::string& endpoint_id, const std::map<std::string, std::string>& labels, std::map<std::string,
	prometheus::Counter*>& m_map, unsigned long long value, PgSQL_p_hg_dyn_counter::metric idx
) {
	const auto& counter_id = m_map.find(endpoint_id);
	if (counter_id != m_map.end()) {
		const auto& cur_val = counter_id->second->Value();
		counter_id->second->Increment(value - cur_val);
	} else {
		auto& new_counter = status.p_dyn_counter_array[idx];
		m_map.insert(
			{
				endpoint_id,
				std::addressof(new_counter->Add(labels))
			}
		);
	}
}

void PgSQL_HostGroups_Manager::p_update_connection_pool_update_gauge(
	const std::string& endpoint_id, const std::map<std::string, std::string>& labels,
	std::map<std::string, prometheus::Gauge*>& m_map, unsigned long long value, PgSQL_p_hg_dyn_gauge::metric idx
) {
	const auto& counter_id = m_map.find(endpoint_id);
	if (counter_id != m_map.end()) {
		counter_id->second->Set(value);
	} else {
		auto& new_counter = status.p_dyn_gauge_array[idx];
		m_map.insert(
			{
				endpoint_id,
				std::addressof(new_counter->Add(labels))
			}
		);
	}
}

void PgSQL_HostGroups_Manager::p_update_connection_pool() {
	std::vector<string> cur_servers_ids {};
	wrlock();
	for (int i = 0; i < static_cast<int>(MyHostGroups->len); i++) {
		PgSQL_HGC *myhgc = static_cast<PgSQL_HGC*>(MyHostGroups->index(i));
		for (int j = 0; j < static_cast<int>(myhgc->mysrvs->cnt()); j++) {
			PgSQL_SrvC *mysrvc = static_cast<PgSQL_SrvC*>(myhgc->mysrvs->servers->index(j));
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
				status.p_conn_pool_bytes_data_recv_map, mysrvc->bytes_recv, PgSQL_p_hg_dyn_counter::conn_pool_bytes_data_recv);

			// proxysql_connection_pool_bytes_data_sent metric
			std::map<std::string, std::string> sent_pool_bytes_labels = common_labels;
			sent_pool_bytes_labels.insert({"traffic_flow", "sent"});
			p_update_connection_pool_update_counter(endpoint_id, sent_pool_bytes_labels,
				status.p_conn_pool_bytes_data_sent_map, mysrvc->bytes_sent, PgSQL_p_hg_dyn_counter::conn_pool_bytes_data_sent);

			// proxysql_connection_pool_conn_err metric
			std::map<std::string, std::string> pool_conn_err_labels = common_labels;
			pool_conn_err_labels.insert({"status", "err"});
			p_update_connection_pool_update_counter(endpoint_id, pool_conn_err_labels,
				status.p_connection_pool_conn_err_map, mysrvc->connect_ERR, PgSQL_p_hg_dyn_counter::connection_pool_conn_err);

			// proxysql_connection_pool_conn_ok metric
			std::map<std::string, std::string> pool_conn_ok_labels = common_labels;
			pool_conn_ok_labels.insert({"status", "ok"});
			p_update_connection_pool_update_counter(endpoint_id, pool_conn_ok_labels,
				status.p_connection_pool_conn_ok_map, mysrvc->connect_OK, PgSQL_p_hg_dyn_counter::connection_pool_conn_ok);

			// proxysql_connection_pool_conn_free metric
			std::map<std::string, std::string> pool_conn_free_labels = common_labels;
			pool_conn_free_labels.insert({"status", "free"});
			p_update_connection_pool_update_gauge(endpoint_id, pool_conn_free_labels,
				status.p_connection_pool_conn_free_map, mysrvc->ConnectionsFree->conns_length(), PgSQL_p_hg_dyn_gauge::connection_pool_conn_free);

			// proxysql_connection_pool_conn_used metric
			std::map<std::string, std::string> pool_conn_used_labels = common_labels;
			pool_conn_used_labels.insert({"status", "used"});
			p_update_connection_pool_update_gauge(endpoint_id, pool_conn_used_labels,
				status.p_connection_pool_conn_used_map, mysrvc->ConnectionsUsed->conns_length(), PgSQL_p_hg_dyn_gauge::connection_pool_conn_used);

			// proxysql_connection_pool_latency_us metric
			p_update_connection_pool_update_gauge(endpoint_id, common_labels,
				status.p_connection_pool_latency_us_map, mysrvc->current_latency_us, PgSQL_p_hg_dyn_gauge::connection_pool_latency_us);

			// proxysql_connection_pool_queries metric
			p_update_connection_pool_update_counter(endpoint_id, common_labels,
				status.p_connection_pool_queries_map, mysrvc->queries_sent, PgSQL_p_hg_dyn_counter::connection_pool_queries);

			// proxysql_connection_pool_status metric
			p_update_connection_pool_update_gauge(endpoint_id, common_labels,
				status.p_connection_pool_status_map, mysrvc->status + 1, PgSQL_p_hg_dyn_gauge::connection_pool_status);
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
		status.p_dyn_gauge_array[PgSQL_p_hg_dyn_gauge::connection_pool_status]->Remove(gauge);
		status.p_connection_pool_status_map.erase(key);

		gauge = status.p_connection_pool_conn_used_map[key];
		status.p_dyn_gauge_array[PgSQL_p_hg_dyn_gauge::connection_pool_conn_free]->Remove(gauge);
		status.p_connection_pool_conn_used_map.erase(key);

		gauge = status.p_connection_pool_conn_free_map[key];
		status.p_dyn_gauge_array[PgSQL_p_hg_dyn_gauge::connection_pool_conn_used]->Remove(gauge);
		status.p_connection_pool_conn_free_map.erase(key);

		gauge = status.p_connection_pool_latency_us_map[key];
		status.p_dyn_gauge_array[PgSQL_p_hg_dyn_gauge::connection_pool_latency_us]->Remove(gauge);
		status.p_connection_pool_latency_us_map.erase(key);
	}

	wrunlock();
}

SQLite3_result * PgSQL_HostGroups_Manager::SQL3_Connection_Pool(bool _reset, int *hid) {
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
		PgSQL_HGC *myhgc=(PgSQL_HGC *)MyHostGroups->index(i);
		for (j=0; j<(int)myhgc->mysrvs->cnt(); j++) {
			PgSQL_SrvC *mysrvc=(PgSQL_SrvC *)myhgc->mysrvs->servers->index(j);
			if (hid == NULL) {
				if (mysrvc->status!=MYSQL_SERVER_STATUS_ONLINE) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Server %s:%d is not online\n", mysrvc->address, mysrvc->port);
					//__sync_fetch_and_sub(&status.server_connections_connected, mysrvc->ConnectionsFree->conns->len);
					mysrvc->ConnectionsFree->drop_all_connections();
				}
				// drop idle connections if beyond max_connection
				while (mysrvc->ConnectionsFree->conns_length() && mysrvc->ConnectionsUsed->conns_length()+mysrvc->ConnectionsFree->conns_length() > mysrvc->max_connections) {
					//PgSQL_Connection *conn=(PgSQL_Connection *)mysrvc->ConnectionsFree->conns->remove_index_fast(0);
					PgSQL_Connection *conn=mysrvc->ConnectionsFree->remove(0);
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

void PgSQL_HostGroups_Manager::read_only_action(char *hostname, int port, int read_only) {
	// define queries
	const char *Q1B=(char *)"SELECT hostgroup_id,status FROM ( SELECT DISTINCT writer_hostgroup FROM pgsql_replication_hostgroups JOIN pgsql_servers WHERE (hostgroup_id=writer_hostgroup) AND hostname='%s' AND port=%d UNION SELECT DISTINCT writer_hostgroup FROM pgsql_replication_hostgroups JOIN pgsql_servers WHERE (hostgroup_id=reader_hostgroup) AND hostname='%s' AND port=%d) LEFT JOIN pgsql_servers ON hostgroup_id=writer_hostgroup AND hostname='%s' AND port=%d";
	const char *Q2A=(char *)"DELETE FROM pgsql_servers WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT writer_hostgroup FROM pgsql_replication_hostgroups WHERE writer_hostgroup=pgsql_servers.hostgroup_id) AND status='OFFLINE_HARD'";
	const char *Q2B=(char *)"UPDATE OR IGNORE pgsql_servers SET hostgroup_id=(SELECT writer_hostgroup FROM pgsql_replication_hostgroups WHERE reader_hostgroup=pgsql_servers.hostgroup_id) WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT reader_hostgroup FROM pgsql_replication_hostgroups WHERE reader_hostgroup=pgsql_servers.hostgroup_id)";
	const char *Q3A=(char *)"INSERT OR IGNORE INTO pgsql_servers(hostgroup_id, hostname, port, gtid_port, status, weight, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment) SELECT reader_hostgroup, hostname, port, gtid_port, status, weight, max_connections, max_replication_lag, use_ssl, max_latency_ms, pgsql_servers.comment FROM pgsql_servers JOIN pgsql_replication_hostgroups ON pgsql_servers.hostgroup_id=pgsql_replication_hostgroups.writer_hostgroup WHERE hostname='%s' AND port=%d";
	const char *Q3B=(char *)"DELETE FROM pgsql_servers WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT reader_hostgroup FROM pgsql_replication_hostgroups WHERE reader_hostgroup=pgsql_servers.hostgroup_id)";
	const char *Q4=(char *)"UPDATE OR IGNORE pgsql_servers SET hostgroup_id=(SELECT reader_hostgroup FROM pgsql_replication_hostgroups WHERE writer_hostgroup=pgsql_servers.hostgroup_id) WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT writer_hostgroup FROM pgsql_replication_hostgroups WHERE writer_hostgroup=pgsql_servers.hostgroup_id)";
	const char *Q5=(char *)"DELETE FROM pgsql_servers WHERE hostname='%s' AND port=%d AND hostgroup_id IN (SELECT writer_hostgroup FROM pgsql_replication_hostgroups WHERE writer_hostgroup=pgsql_servers.hostgroup_id)";
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
		const char *q1 = (const char *)"SELECT DISTINCT hostname,port FROM pgsql_replication_hostgroups JOIN pgsql_servers ON hostgroup_id=writer_hostgroup AND status<>3";
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
					char *q = (char *)"SELECT * FROM pgsql_servers WHERE hostname=\"%s\" AND port=%d";
					query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
					sprintf(query2,q,hostname,port);
					admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
					if (error2) {
						proxy_error("Error on read from pgsql_servers : %s\n", error2);
					} else {
						if (resultset2) {
							proxy_info("read_only_action RO=0 phase 1 : Dumping pgsql_servers for %s:%d\n", hostname, port);
							resultset2->dump_to_stderr();
						}
					}
					if (resultset2) { delete resultset2; resultset2=NULL; }
					free(query2);
				}
				GloAdmin->save_proxysql_servers_runtime_to_database(false); // SAVE PgSQL SERVERS FROM RUNTIME
				if (GloMTH->variables.hostgroup_manager_verbose) {
					char *error2=NULL;
					int cols2=0;
					int affected_rows2=0;
					SQLite3_result *resultset2=NULL;
					char * query2 = NULL;
					char *q = (char *)"SELECT * FROM pgsql_servers WHERE hostname=\"%s\" AND port=%d";
					query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
					sprintf(query2,q,hostname,port);
					admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
					if (error2) {
						proxy_error("Error on read from pgsql_servers : %s\n", error2);
					} else {
						if (resultset2) {
							proxy_info("read_only_action RO=0 phase 2 : Dumping pgsql_servers for %s:%d\n", hostname, port);
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
					char *q = (char *)"SELECT * FROM pgsql_servers WHERE hostname=\"%s\" AND port=%d";
					query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
					sprintf(query2,q,hostname,port);
					admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
					if (error2) {
						proxy_error("Error on read from pgsql_servers : %s\n", error2);
					} else {
						if (resultset2) {
							proxy_info("read_only_action RO=0 phase 3 : Dumping pgsql_servers for %s:%d\n", hostname, port);
							resultset2->dump_to_stderr();
						}
					}
					if (resultset2) { delete resultset2; resultset2=NULL; }
					free(query2);
				}
				GloAdmin->load_proxysql_servers_to_runtime(); // LOAD PgSQL SERVERS TO RUNTIME
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
						char *q = (char *)"SELECT * FROM pgsql_servers WHERE hostname=\"%s\" AND port=%d";
						query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
						sprintf(query2,q,hostname,port);
						admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
						if (error2) {
							proxy_error("Error on read from pgsql_servers : %s\n", error2);
						} else {
							if (resultset2) {
								proxy_info("read_only_action RO=0 , rows=%d , phase 1 : Dumping pgsql_servers for %s:%d\n", num_rows, hostname, port);
								resultset2->dump_to_stderr();
							}
						}
						if (resultset2) { delete resultset2; resultset2=NULL; }
						free(query2);
					}
					GloAdmin->save_proxysql_servers_runtime_to_database(false); // SAVE PgSQL SERVERS FROM RUNTIME
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
						char *q = (char *)"SELECT * FROM pgsql_servers WHERE hostname=\"%s\" AND port=%d";
						query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
						sprintf(query2,q,hostname,port);
						admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
						if (error2) {
							proxy_error("Error on read from pgsql_servers : %s\n", error2);
						} else {
							if (resultset2) {
								proxy_info("read_only_action RO=0 , rows=%d , phase 2 : Dumping pgsql_servers for %s:%d\n", num_rows, hostname, port);
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
						char *q = (char *)"SELECT * FROM pgsql_servers WHERE hostname=\"%s\" AND port=%d";
						query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
						sprintf(query2,q,hostname,port);
						admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
						if (error2) {
							proxy_error("Error on read from pgsql_servers : %s\n", error2);
						} else {
							if (resultset2) {
								proxy_info("read_only_action RO=0 , rows=%d , phase 3 : Dumping pgsql_servers for %s:%d\n", num_rows, hostname, port);
								resultset2->dump_to_stderr();
							}
						}
						if (resultset2) { delete resultset2; resultset2=NULL; }
						free(query2);
					}
					GloAdmin->load_proxysql_servers_to_runtime(); // LOAD PgSQL SERVERS TO RUNTIME
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
					char *q = (char *)"SELECT * FROM pgsql_servers WHERE hostname=\"%s\" AND port=%d";
					query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
					sprintf(query2,q,hostname,port);
					admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
					if (error2) {
						proxy_error("Error on read from pgsql_servers : %s\n", error2);
					} else {
						if (resultset2) {
							proxy_info("read_only_action RO=1 phase 1 : Dumping pgsql_servers for %s:%d\n", hostname, port);
							resultset2->dump_to_stderr();
						}
					}
					if (resultset2) { delete resultset2; resultset2=NULL; }
					free(query2);
				}
				GloAdmin->save_proxysql_servers_runtime_to_database(false); // SAVE PgSQL SERVERS FROM RUNTIME
				sprintf(query,Q4,hostname,port);
				admindb->execute(query);
				if (GloMTH->variables.hostgroup_manager_verbose) {
					char *error2=NULL;
					int cols2=0;
					int affected_rows2=0;
					SQLite3_result *resultset2=NULL;
					char * query2 = NULL;
					char *q = (char *)"SELECT * FROM pgsql_servers WHERE hostname=\"%s\" AND port=%d";
					query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
					sprintf(query2,q,hostname,port);
					admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
					if (error2) {
						proxy_error("Error on read from pgsql_servers : %s\n", error2);
					} else {
						if (resultset2) {
							proxy_info("read_only_action RO=1 phase 2 : Dumping pgsql_servers for %s:%d\n", hostname, port);
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
					char *q = (char *)"SELECT * FROM pgsql_servers WHERE hostname=\"%s\" AND port=%d";
					query2 = (char *)malloc(strlen(q)+strlen(hostname)+32);
					sprintf(query2,q,hostname,port);
					admindb->execute_statement(query2, &error2 , &cols2 , &affected_rows2 , &resultset2);
					if (error2) {
						proxy_error("Error on read from pgsql_servers : %s\n", error2);
					} else {
						if (resultset2) {
							proxy_info("read_only_action RO=1 phase 3 : Dumping pgsql_servers for %s:%d\n", hostname, port);
							resultset2->dump_to_stderr();
						}
					}
					if (resultset2) { delete resultset2; resultset2=NULL; }
					free(query2);
				}
				GloAdmin->load_proxysql_servers_to_runtime(); // LOAD PgSQL SERVERS TO RUNTIME
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
 * @param pgsql_servers List of servers having hostname, port and read only value.
 * 
 */
void PgSQL_HostGroups_Manager::read_only_action_v2(const std::list<read_only_server_t>& pgsql_servers) {

	bool update_pgsql_servers_table = false;

	unsigned long long curtime1 = monotonic_time();
	wrlock();
	for (const auto& server : pgsql_servers) {
		bool is_writer = false;
		const std::string& hostname = std::get<PgSQL_READ_ONLY_SERVER_T::PG_ROS_HOSTNAME>(server);
		const int port = std::get<PgSQL_READ_ONLY_SERVER_T::PG_ROS_PORT>(server);
		const int read_only = std::get<PgSQL_READ_ONLY_SERVER_T::PG_ROS_READONLY>(server);
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

				update_pgsql_servers_table = true;
				proxy_info("Regenerating table 'pgsql_servers' due to actions on server '%s:%d'\n", hostname.c_str(), port);
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

					update_pgsql_servers_table = true;
					proxy_info("Regenerating table 'pgsql_servers' due to actions on server '%s:%d'\n", hostname.c_str(), port);
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

				update_pgsql_servers_table = true;
				proxy_info("Regenerating table 'pgsql_servers' due to actions on server '%s:%d'\n", hostname.c_str(), port);
			}
		} else {
			// LCOV_EXCL_START
			assert(0);
			break;
			// LCOV_EXCL_STOP
		}
	}

	if (update_pgsql_servers_table) {
		purge_pgsql_servers_table();
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "DELETE FROM pgsql_servers\n");
		mydb->execute("DELETE FROM pgsql_servers");
		generate_pgsql_servers_table();

		// Update the global checksums after 'pgsql_servers' regeneration
		{
			unique_ptr<SQLite3_result> resultset { get_admin_runtime_pgsql_servers(mydb) };
			uint64_t raw_checksum = resultset ? resultset->raw_checksum() : 0;

			// This is required to be updated to avoid extra rebuilding member 'hostgroup_server_mapping'
			// during 'commit'. For extra details see 'hgsm_pgsql_servers_checksum' @details.
			hgsm_pgsql_servers_checksum = raw_checksum;

			string mysrvs_checksum { get_checksum_from_hash(raw_checksum) };
			save_runtime_pgsql_servers(resultset.release());
			proxy_info("Checksum for table %s is %s\n", "pgsql_servers", mysrvs_checksum.c_str());

			pthread_mutex_lock(&GloVars.checksum_mutex);
			update_glovars_pgsql_servers_checksum(mysrvs_checksum);
			pthread_mutex_unlock(&GloVars.checksum_mutex);
		}
	}
	wrunlock();
	unsigned long long curtime2 = monotonic_time();
	curtime1 = curtime1 / 1000;
	curtime2 = curtime2 / 1000;
	proxy_debug(PROXY_DEBUG_MONITOR, 7, "PgSQL_HostGroups_Manager::read_only_action_v2() locked for %llums (server count:%ld)\n", curtime2 - curtime1, pgsql_servers.size());
}

// shun_and_killall
// this function is called only from MySQL_Monitor::monitor_ping()
// it temporary disables a host that is not responding to pings, and mark the host in a way that when used the connection will be dropped
// return true if the status was changed
bool PgSQL_HostGroups_Manager::shun_and_killall(char *hostname, int port) {
	time_t t = time(NULL);
	bool ret = false;
	wrlock();
	PgSQL_SrvC *mysrvc=NULL;
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
	PgSQL_HGC *myhgc=(PgSQL_HGC *)MyHostGroups->index(i);
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
					// if Monitor is enabled and pgsql-monitor_ping_interval is
					// set too high, ProxySQL will unshun hosts that are not
					// available. For this reason time_last_detected_error will
					// be tuned in the future
					if (mysql_thread___monitor_enabled) {
						int a = pgsql_thread___shun_recovery_time_sec;
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
void PgSQL_HostGroups_Manager::set_server_current_latency_us(char *hostname, int port, unsigned int _current_latency_us) {
	wrlock();
	PgSQL_SrvC *mysrvc=NULL;
  for (unsigned int i=0; i<MyHostGroups->len; i++) {
    PgSQL_HGC *myhgc=(PgSQL_HGC *)MyHostGroups->index(i);
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

void PgSQL_HostGroups_Manager::p_update_metrics() {
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::servers_table_version], status.servers_table_version);
	// Update *server_connections* related metrics
	status.p_gauge_array[PgSQL_p_hg_gauge::server_connections_connected]->Set(status.server_connections_connected);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::server_connections_aborted], status.server_connections_aborted);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::server_connections_created], status.server_connections_created);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::server_connections_delayed], status.server_connections_delayed);

	// Update *client_connections* related metrics
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::client_connections_created], status.client_connections_created);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::client_connections_aborted], status.client_connections_aborted);
	status.p_gauge_array[PgSQL_p_hg_gauge::client_connections_connected]->Set(status.client_connections);

	// Update *acess_denied* related metrics
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::access_denied_wrong_password], status.access_denied_wrong_password);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::access_denied_max_connections], status.access_denied_max_connections);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::access_denied_max_user_connections], status.access_denied_max_user_connections);

	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::selects_for_update__autocommit0], status.select_for_update_or_equivalent);

	// Update *com_* related metrics
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::com_autocommit], status.autocommit_cnt);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::com_autocommit_filtered], status.autocommit_cnt_filtered);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::com_commit_cnt], status.commit_cnt);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::com_commit_cnt_filtered], status.commit_cnt_filtered);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::com_rollback], status.rollback_cnt);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::com_rollback_filtered], status.rollback_cnt_filtered);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::com_backend_init_db], status.backend_init_db);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::com_backend_change_user], status.backend_change_user);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::com_backend_set_names], status.backend_set_names);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::com_frontend_init_db], status.frontend_init_db);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::com_frontend_set_names], status.frontend_set_names);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::com_frontend_use_db], status.frontend_use_db);

	// Update *myconnpoll* related metrics
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::myhgm_myconnpool_get], status.myconnpoll_get);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::myhgm_myconnpool_get_ok], status.myconnpoll_get_ok);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::myhgm_myconnpool_get_ping], status.myconnpoll_get_ping);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::myhgm_myconnpool_push], status.myconnpoll_push);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::myhgm_myconnpool_reset], status.myconnpoll_reset);
	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::myhgm_myconnpool_destroy], status.myconnpoll_destroy);

	p_update_counter(status.p_counter_array[PgSQL_p_hg_counter::auto_increment_delay_multiplex], status.auto_increment_delay_multiplex);

	// Update the *connection_pool* metrics
	this->p_update_connection_pool();
	// Update the *gtid_executed* metrics
	this->p_update_pgsql_gtid_executed();
}

SQLite3_result * PgSQL_HostGroups_Manager::SQL3_Get_ConnPool_Stats() {
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


unsigned long long PgSQL_HostGroups_Manager::Get_Memory_Stats() {
	unsigned long long intsize=0;
	wrlock();
	PgSQL_SrvC *mysrvc=NULL;
  for (unsigned int i=0; i<MyHostGroups->len; i++) {
		intsize+=sizeof(PgSQL_HGC);
    PgSQL_HGC *myhgc=(PgSQL_HGC *)MyHostGroups->index(i);
		unsigned int j,k;
		unsigned int l=myhgc->mysrvs->cnt();
		if (l) {
			for (j=0; j<l; j++) {
				intsize+=sizeof(PgSQL_SrvC);
				mysrvc=myhgc->mysrvs->idx(j);
				intsize+=((mysrvc->ConnectionsUsed->conns_length())*sizeof(PgSQL_Connection *));
				for (k=0; k<mysrvc->ConnectionsFree->conns_length(); k++) {
					//PgSQL_Connection *myconn=(PgSQL_Connection *)mysrvc->ConnectionsFree->conns->index(k);
					PgSQL_Connection *myconn=mysrvc->ConnectionsFree->index(k);
					intsize+=sizeof(PgSQL_Connection)+sizeof(MYSQL);
					intsize+=myconn->pgsql->net.max_packet;
					intsize+=(4096*15); // ASYNC_CONTEXT_DEFAULT_STACK_SIZE
					if (myconn->query_result) {
						intsize+=myconn->query_result->current_size();
					}
				}
				intsize+=((mysrvc->ConnectionsUsed->conns_length())*sizeof(PgSQL_Connection *));
			}
		}
	}
	wrunlock();
	return intsize;
}

PgSQL_Group_Replication_Info::PgSQL_Group_Replication_Info(int w, int b, int r, int o, int mw, int mtb, bool _a, int _w, char *c) {
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

PgSQL_Group_Replication_Info::~PgSQL_Group_Replication_Info() {
	if (comment) {
		free(comment);
		comment=NULL;
	}
}

bool PgSQL_Group_Replication_Info::update(int b, int r, int o, int mw, int mtb, bool _a, int _w, char *c) {
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

void PgSQL_HostGroups_Manager::p_update_pgsql_gtid_executed() {
	pthread_rwlock_wrlock(&gtid_rwlock);

	std::unordered_map<string, PgSQL_GTID_Server_Data*>::iterator it = gtid_map.begin();
	while(it != gtid_map.end()) {
		PgSQL_GTID_Server_Data* gtid_si = it->second;
		std::string address {};
		std::string port {};
		std::string endpoint_id {};

		if (gtid_si) {
			address = std::string(gtid_si->address);
			port = std::to_string(gtid_si->pgsql_port);
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
				this->status.p_dyn_counter_array[PgSQL_p_hg_dyn_counter::gtid_executed];

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

SQLite3_result * PgSQL_HostGroups_Manager::get_stats_pgsql_gtid_executed() {
	const int colnum = 4;
	SQLite3_result * result = new SQLite3_result(colnum);
	result->add_column_definition(SQLITE_TEXT,"hostname");
	result->add_column_definition(SQLITE_TEXT,"port");
	result->add_column_definition(SQLITE_TEXT,"gtid_executed");
	result->add_column_definition(SQLITE_TEXT,"events");
	int k;
	pthread_rwlock_wrlock(&gtid_rwlock);
	std::unordered_map<string, PgSQL_GTID_Server_Data *>::iterator it = gtid_map.begin();
	while(it != gtid_map.end()) {
		PgSQL_GTID_Server_Data * gtid_si = it->second;
		char buf[64];
		char **pta=(char **)malloc(sizeof(char *)*colnum);
		if (gtid_si) {
			pta[0]=strdup(gtid_si->address);
			sprintf(buf,"%d", (int)gtid_si->pgsql_port);
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
		char **pta=(char **)malloc(sizeof(char *)*PgSQL_ERRORS_STATS_FIELD_NUM);
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
		for (i=0;i<PgSQL_ERRORS_STATS_FIELD_NUM;i++) {
			assert(pta[i]);
			free(pta[i]);
		}
		free(pta);
	}
};

void PgSQL_HostGroups_Manager::add_pgsql_errors(int hostgroup, char *hostname, int port, char *username, char *address, char *schemaname, int err_no, char *last_error) {
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
	pthread_mutex_lock(&pgsql_errors_mutex);

	it=pgsql_errors_umap.find(hash1);

	if (it != pgsql_errors_umap.end()) {
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
		pgsql_errors_umap.insert(std::make_pair(hash1,(void *)mes));
	}
	pthread_mutex_unlock(&pgsql_errors_mutex);
}

SQLite3_result * PgSQL_HostGroups_Manager::get_pgsql_errors(bool reset) {
	SQLite3_result *result=new SQLite3_result(PgSQL_ERRORS_STATS_FIELD_NUM);
	pthread_mutex_lock(&pgsql_errors_mutex);
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
	for (std::unordered_map<uint64_t, void *>::iterator it=pgsql_errors_umap.begin(); it!=pgsql_errors_umap.end(); ++it) {
		MySQL_Errors_stats *mes=(MySQL_Errors_stats *)it->second;
		char **pta=mes->get_row();
		result->add_row(pta);
		mes->free_row(pta);
		if (reset) {
			delete mes;
		}
	}
	if (reset) {
		pgsql_errors_umap.erase(pgsql_errors_umap.begin(),pgsql_errors_umap.end());
	}
	pthread_mutex_unlock(&pgsql_errors_mutex);
	return result;
}

PgSQL_AWS_Aurora_Info::PgSQL_AWS_Aurora_Info(int w, int r, int _port, char *_end_addr, int maxl, int al, int minl, int lnc, int ci, int ct, bool _a, int wiar, int nrw, char *c) {
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

PgSQL_AWS_Aurora_Info::~PgSQL_AWS_Aurora_Info() {
	if (comment) {
		free(comment);
		comment=NULL;
	}
	if (domain_name) {
		free(domain_name);
		domain_name=NULL;
	}
}

bool PgSQL_AWS_Aurora_Info::update(int r, int _port, char *_end_addr, int maxl, int al, int minl, int lnc, int ci, int ct, bool _a, int wiar, int nrw, char *c) {
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
 * @brief Initializes the supplied 'PgSQL_HGC' with the specified 'hostgroup_settings'.
 * @details Input verification is performed in the supplied 'hostgroup_settings'. It's expected to be a valid
 *  JSON that may contain the following fields:
 *   - handle_warnings: Value must be >= 0.
 *
 *  In case input verification fails for a field, supplied 'PgSQL_HGC' is NOT updated for that field. An error
 *  message is logged specifying the source of the error.
 *
 * @param hostgroup_settings String containing a JSON defined in 'pgsql_hostgroup_attributes'.
 * @param myhgc The 'PgSQL_HGC' of the target hostgroup of the supplied 'hostgroup_settings'.
 */
void init_myhgc_hostgroup_settings(const char* hostgroup_settings, PgSQL_HGC* myhgc) {
	const uint32_t hid = myhgc->hid;

	if (hostgroup_settings[0] != '\0') {
		try {
			nlohmann::json j = nlohmann::json::parse(hostgroup_settings);

			const auto handle_warnings_check = [](int8_t handle_warnings) -> bool { return handle_warnings == 0 || handle_warnings == 1; };
			int8_t handle_warnings = PgSQL_j_get_srv_default_int_val<int8_t>(j, hid, "handle_warnings", handle_warnings_check);
			myhgc->attributes.handle_warnings = handle_warnings;
		}
		catch (const json::exception& e) {
			proxy_error(
				"JSON parsing for 'pgsql_hostgroup_attributes.hostgroup_settings' for hostgroup %d failed with exception `%s`.\n",
				hid, e.what()
			);
		}
	}
}

/**
 * @brief Initializes the supplied 'PgSQL_HGC' with the specified 'servers_defaults'.
 * @details Input verification is performed in the supplied 'server_defaults'. It's expected to be a valid
 *  JSON that may contain the following fields:
 *   - weight: Must be an unsigned integer >= 0.
 *   - max_connections: Must be an unsigned integer >= 0.
 *   - use_ssl: Must be a integer with either value 0 or 1.
 *
 *  In case input verification fails for a field, supplied 'PgSQL_HGC' is NOT updated for that field. An error
 *  message is logged specifying the source of the error.
 *
 * @param servers_defaults String containing a JSON defined in 'pgsql_hostgroup_attributes'.
 * @param myhgc The 'PgSQL_HGC' of the target hostgroup of the supplied 'servers_defaults'.
 */
void init_myhgc_servers_defaults(char* servers_defaults, PgSQL_HGC* myhgc) {
	uint32_t hid = myhgc->hid;

	if (strcmp(servers_defaults, "") != 0) {
		try {
		    nlohmann::json j = nlohmann::json::parse(servers_defaults);

			const auto weight_check = [] (int64_t weight) -> bool { return weight >= 0; };
			int64_t weight = PgSQL_j_get_srv_default_int_val<int64_t>(j, hid, "weight", weight_check);

			myhgc->servers_defaults.weight = weight;

			const auto max_conns_check = [] (int64_t max_conns) -> bool { return max_conns >= 0; };
			int64_t max_conns = PgSQL_j_get_srv_default_int_val<int64_t>(j, hid, "max_connections", max_conns_check);

			myhgc->servers_defaults.max_connections = max_conns;

			const auto use_ssl_check = [] (int32_t use_ssl) -> bool { return use_ssl == 0 || use_ssl == 1; };
			int32_t use_ssl = PgSQL_j_get_srv_default_int_val<int32_t>(j, hid, "use_ssl", use_ssl_check);

			myhgc->servers_defaults.use_ssl = use_ssl;
		} catch (const json::exception& e) {
			proxy_error(
				"JSON parsing for 'pgsql_hostgroup_attributes.servers_defaults' for hostgroup %d failed with exception `%s`.\n",
				hid, e.what()
			);
		}
	}
}

void PgSQL_HostGroups_Manager::generate_pgsql_hostgroup_attributes_table() {
	if (incoming_hostgroup_attributes==NULL) {
		return;
	}
	int rc;
	sqlite3_stmt *statement=NULL;

	const char * query=(const char *)"INSERT INTO pgsql_hostgroup_attributes ( "
		"hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, "
		"init_connect, multiplex, connection_warming, throttle_connections_per_sec, "
		"ignore_session_variables, hostgroup_settings, servers_defaults, comment) VALUES "
		"(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

	//rc=(*proxy_sqlite3_prepare_v2)(mydb3, query, -1, &statement, 0);
	rc = mydb->prepare_v2(query, &statement);
	ASSERT_SQLITE_OK(rc, mydb);
	proxy_info("New pgsql_hostgroup_attributes table\n");
	bool current_configured[MyHostGroups->len];
	// set configured = false to all
	// in this way later we can known which HG were updated
	for (unsigned int i=0; i<MyHostGroups->len; i++) {
		PgSQL_HGC *myhgc=(PgSQL_HGC *)MyHostGroups->index(i);
		current_configured[i] = myhgc->attributes.configured;
		myhgc->attributes.configured = false;
	}

	/**
	 * @brief We iterate the whole resultset incoming_hostgroup_attributes and configure
	 * both the hostgroup in memory, but also pupulate table pgsql_hostgroup_attributes
	 *   connection errors.
	 * @details for each row in incoming_hostgroup_attributes:
	 *   1. it finds (or create) the hostgroup
	 *   2. it writes the in pgsql_hostgroup_attributes
	 *   3. it finds (or create) the attributes of the hostgroup
	*/
	for (std::vector<SQLite3_row *>::iterator it = incoming_hostgroup_attributes->rows.begin() ; it != incoming_hostgroup_attributes->rows.end(); ++it) {
		SQLite3_row *r=*it;
		unsigned int hid = (unsigned int)atoi(r->fields[0]);
		PgSQL_HGC *myhgc = MyHGC_lookup(hid); // note: MyHGC_lookup() will create the HG if doesn't exist!
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
		PgSQL_HGC *myhgc=(PgSQL_HGC *)MyHostGroups->index(i);
		if (myhgc->attributes.configured == false) {
			if (current_configured[i] == true) {
				// if configured == false and previously it was configured == true , reset to defaults
				proxy_info("Resetting hostgroup attributes for hostgroup %u\n", myhgc->hid);
				myhgc->reset_attributes();
			}
		}
	}

	delete incoming_hostgroup_attributes;
	incoming_hostgroup_attributes=NULL;
}

int PgSQL_HostGroups_Manager::create_new_server_in_hg(
	uint32_t hid, const PgSQL_srv_info_t& srv_info, const PgSQL_srv_opts_t& srv_opts
) {
	int32_t res = -1;
	PgSQL_SrvC* mysrvc = find_server_in_hg(hid, srv_info.addr, srv_info.port);

	if (mysrvc == nullptr) {
		char* c_hostname { const_cast<char*>(srv_info.addr.c_str()) };
		PgSQL_SrvC* mysrvc = new PgSQL_SrvC(
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
		// If the server is found as 'OFFLINE_HARD' we reset the 'PgSQL_SrvC' values corresponding with the
		// 'servers_defaults' (as in a new 'PgSQL_SrvC' creation). We then later update these values with the
		// 'servers_defaults' attributes from its corresponding 'PgSQL_HGC'. This way we ensure uniform behavior
		// of new servers, and 'OFFLINE_HARD' ones when a user update 'servers_defaults' values, and reloads
		// the servers to runtime.
		if (mysrvc && mysrvc->status == MYSQL_SERVER_STATUS_OFFLINE_HARD) {
			reset_hg_attrs_server_defaults(mysrvc);
			update_hg_attrs_server_defaults(mysrvc, mysrvc->myhgc);
			mysrvc->status = MYSQL_SERVER_STATUS_ONLINE;

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

int PgSQL_HostGroups_Manager::remove_server_in_hg(uint32_t hid, const string& addr, uint16_t port) {
	PgSQL_SrvC* mysrvc = find_server_in_hg(hid, addr, port);
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
	mysrvc->status=MYSQL_SERVER_STATUS_OFFLINE_HARD;
	mysrvc->ConnectionsFree->drop_all_connections();

	// TODO-NOTE: This is only required in case the caller isn't going to perform:
	//   - Full deletion of servers in the target 'hid'.
	//   - Table regeneration for the servers in the target 'hid'.
	// This is a very common pattern when further operations have been performed over the
	// servers, e.g. a set of servers additions and deletions over the target hostgroups.
	// ////////////////////////////////////////////////////////////////////////

	// Remove the server from the table
	const string del_srv_query { "DELETE FROM pgsql_servers WHERE mem_pointer=" + std::to_string(mysrvc_addr) };
	mydb->execute(del_srv_query.c_str());

	// ////////////////////////////////////////////////////////////////////////

	return 0;
}

PgSQL_SrvC* PgSQL_HostGroups_Manager::find_server_in_hg(unsigned int _hid, const std::string& addr, int port) {
	PgSQL_SrvC* f_server = nullptr;

	PgSQL_HGC* myhgc = nullptr;
	for (uint32_t i = 0; i < MyHostGroups->len; i++) {
		myhgc = static_cast<PgSQL_HGC*>(MyHostGroups->index(i));

		if (myhgc->hid == _hid) {
			break;
		}
	}

	if (myhgc != nullptr) {
		for (uint32_t j = 0; j < myhgc->mysrvs->cnt(); j++) {
			PgSQL_SrvC* mysrvc = static_cast<PgSQL_SrvC*>(myhgc->mysrvs->servers->index(j));

			if (strcmp(mysrvc->address, addr.c_str()) == 0 && mysrvc->port == port) {
				f_server = mysrvc;
			}
		}
	}

	return f_server;
}

void PgSQL_HostGroups_Manager::HostGroup_Server_Mapping::copy_if_not_exists(Type dest_type, Type src_type) {

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

		if (node.srv->status == MYSQL_SERVER_STATUS_SHUNNED ||
			node.srv->status == MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) {
			// Status updated from "*SHUNNED" to "ONLINE" as "read_only" value was successfully 
			// retrieved from the backend server, indicating server is now online.
			node.srv->status = MYSQL_SERVER_STATUS_ONLINE;
		}

		PgSQL_SrvC* new_srv = insert_HGM(get_hostgroup_id(dest_type, node), node.srv);
			
		if (!new_srv) assert(0);
			
		node.srv = new_srv;
		dest_nodes.push_back(node);
	}
}

void PgSQL_HostGroups_Manager::HostGroup_Server_Mapping::remove(Type type, size_t index) {

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

void PgSQL_HostGroups_Manager::HostGroup_Server_Mapping::clear(Type type) {

	for (const auto& node : mapping[type]) {
		remove_HGM(node.srv);
	}

	mapping[type].clear();
}

unsigned int PgSQL_HostGroups_Manager::HostGroup_Server_Mapping::get_hostgroup_id(Type type, const Node& node) const {

	if (type == Type::WRITER)
		return node.writer_hostgroup_id;
	else if (type == Type::READER)
		return node.reader_hostgroup_id;
	else
		assert(0);
}

PgSQL_SrvC* PgSQL_HostGroups_Manager::HostGroup_Server_Mapping::insert_HGM(unsigned int hostgroup_id, const PgSQL_SrvC* srv) {

	PgSQL_HGC* myhgc = myHGM->MyHGC_lookup(hostgroup_id);

	if (!myhgc)
		return NULL;

	PgSQL_SrvC* ret_srv = NULL;
	
	for (uint32_t j = 0; j < myhgc->mysrvs->cnt(); j++) {
		PgSQL_SrvC* mysrvc = static_cast<PgSQL_SrvC*>(myhgc->mysrvs->servers->index(j));
		if (strcmp(mysrvc->address, srv->address) == 0 && mysrvc->port == srv->port) {
			if (mysrvc->status == MYSQL_SERVER_STATUS_OFFLINE_HARD) {
				
				mysrvc->gtid_port = srv->gtid_port;
				mysrvc->weight = srv->weight;
				mysrvc->compression = srv->compression;
				mysrvc->max_connections = srv->max_connections;
				mysrvc->max_replication_lag = srv->max_replication_lag;
				mysrvc->use_ssl = srv->use_ssl;
				mysrvc->max_latency_us = srv->max_latency_us;
				mysrvc->comment = strdup(srv->comment);
				mysrvc->status = MYSQL_SERVER_STATUS_ONLINE;

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
			proxy_info("Creating new server in HG %d : %s:%d , gtid_port=%d, weight=%ld, status=%d\n", hostgroup_id, srv->address, srv->port, srv->gtid_port, srv->weight, srv->status);
		}

		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 5, "Adding new server %s:%d , weight=%ld, status=%d, mem_ptr=%p into hostgroup=%d\n", srv->address, srv->port, srv->weight, srv->status, srv, hostgroup_id);

		ret_srv = new PgSQL_SrvC(srv->address, srv->port, srv->gtid_port, srv->weight, srv->status, srv->compression,
			srv->max_connections, srv->max_replication_lag, srv->use_ssl, (srv->max_latency_us / 1000), srv->comment);

		myhgc->mysrvs->add(ret_srv);
	}

	return ret_srv;
}

void PgSQL_HostGroups_Manager::HostGroup_Server_Mapping::remove_HGM(PgSQL_SrvC* srv) {
	proxy_warning("Removed server at address %p, hostgroup %d, address %s port %d. Setting status OFFLINE HARD and immediately dropping all free connections. Used connections will be dropped when trying to use them\n", (void*)srv, srv->myhgc->hid, srv->address, srv->port);
	srv->status = MYSQL_SERVER_STATUS_OFFLINE_HARD;
	srv->ConnectionsFree->drop_all_connections();
}
