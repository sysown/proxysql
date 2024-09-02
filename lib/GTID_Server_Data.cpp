#include "MySQL_HostGroups_Manager.h"

#include "ev.h"
#include <iterator>


extern ProxySQL_Admin *GloAdmin;

extern MySQL_Threads_Handler *GloMTH;

extern MySQL_Monitor *GloMyMon;

static pthread_mutex_t ev_loop_mutex = PTHREAD_MUTEX_INITIALIZER;

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
	if (GloMTH == nullptr) { return; }
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
	int s;

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		close(s);
		return NULL;
	}

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

	int status = connect(s, res->ai_addr, res->ai_addrlen);

	// Free linked list
	freeaddrinfo(res);

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
	memset(uuid_server, 0, sizeof(uuid_server));
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
	// Extract latest comma only in case 'gtid_executed' isn't empty
	if (gtid_set.empty() == false) {
		gtid_set.pop_back();
	}
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

void * GTID_syncer_run() {
	//struct ev_loop * gtid_ev_loop;
	//gtid_ev_loop = NULL;
	set_thread_name("GTID");
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

