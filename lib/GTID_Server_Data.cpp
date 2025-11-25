#include "GTID_Server_Data.h"
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

/**
 * @brief Data reception callback for established GTID server connections
 *
 * This callback handles reading GTID data from established connections to binlog readers.
 * It processes incoming GTID information and manages connection failures gracefully.
 *
 * On successful read:
 * - Processes the received GTID data
 * - Calls dump() to parse and update GTID sets
 *
 * On read failure:
 * - Marks the server connection as inactive
 * - Sets gtid_missing_nodes flag to trigger reconnection
 * - Performs proper cleanup of socket and watcher resources
 * - Clears the watcher reference to maintain clean state
 *
 * @param loop The event loop (unused in this implementation)
 * @param w The I/O watcher for data reception
 * @param revents The events that triggered this callback
 *
 * @note This function is critical for maintaining GTID synchronization stability
 * @note Proper resource cleanup prevents memory leaks and maintains system stability
 */
void reader_cb(struct ev_loop *loop, struct ev_io *w, int revents) {
	pthread_mutex_lock(&ev_loop_mutex);
	if (revents & EV_READ) {
		GTID_Server_Data *sd = (GTID_Server_Data *)w->data;
		bool rc = true;
		rc = sd->readall();
		if (rc == false) {
			MyHGM->gtid_missing_nodes = true;
			sd->active = false;
			proxy_warning("GTID: failed to read from ProxySQL binlog reader on port %d for server %s:%d\n", sd->port, sd->address, sd->mysql_port);

			ev_io_stop(MyHGM->gtid_ev_loop, w);
			close(w->fd);
			free(w);
			sd->w = nullptr;
		} else {
			sd->dump();
		}
	}
	pthread_mutex_unlock(&ev_loop_mutex);
}

/**
 * @brief Connection establishment callback for GTID server connections
 *
 * This callback is triggered when a non-blocking connect() operation completes.
 * It handles both successful connections and connection failures with proper
 * resource cleanup and state management.
 *
 * On successful connection:
 * - Stops and frees the connect watcher
 * - Creates a new read watcher for data reception
 * - Starts the read watcher to begin GTID data processing
 *
 * On connection failure:
 * - Marks server as inactive
 * - Logs appropriate warning messages
 * - Performs proper cleanup of socket and watcher resources
 *
 * @param loop The event loop (unused in this implementation)
 * @param w The I/O watcher for the connection
 * @param revents The events that triggered this callback
 *
 * @note This function ensures proper resource management to prevent memory leaks
 * @note Takes ev_loop_mutex to ensure thread-safe operations
 */
void connect_cb(EV_P_ ev_io *w, int revents) {
	pthread_mutex_lock(&ev_loop_mutex);
	if (revents & EV_WRITE) {
		int fd = w->fd;
		GTID_Server_Data *sd = (GTID_Server_Data *)w->data;

		// connect() completed, this watcher is no longer needed
		ev_io_stop(MyHGM->gtid_ev_loop, w);
		free(w);
		sd->w = nullptr;

		// Based on fd status, proceed to next step -> waiting for read event on the socket
		int error = 0;
		socklen_t optlen = sizeof(error);
		int rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &optlen);
		if (rc == -1 || error != 0) {
			/* connection failed */
			MyHGM->gtid_missing_nodes = true;
			sd->active = false;
			proxy_warning("GTID: failed to connect to ProxySQL binlog reader on port %d for server %s:%d\n", sd->port, sd->address, sd->mysql_port);
			close(fd);
		} else {
			struct ev_io *read_watcher = (struct ev_io *) malloc(sizeof(struct ev_io));
			read_watcher->data = sd;
			sd->w = read_watcher;
			ev_io_init(read_watcher, reader_cb, fd, EV_READ);
			ev_io_start(MyHGM->gtid_ev_loop, read_watcher);
		}
	}
	pthread_mutex_unlock(&ev_loop_mutex);
}

struct ev_io * new_connect_watcher(char *address, uint16_t gtid_port, uint16_t mysql_port) {
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

/**
 * @brief Reads data from the GTID server connection socket
 *
 * Reads available data from the socket connection to the binlog reader.
 * Handles different read conditions to provide robust connection management:
 * - Successful read: Data is appended to internal buffer
 * - EOF (rc == 0): Connection was gracefully closed by peer
 * - Error conditions: Distinguishes between transient (EINTR/EAGAIN) and fatal errors
 *
 * This function is critical for maintaining stable GTID synchronization and
 * properly detecting connection failures for reconnection handling.
 *
 * @return bool True if read was successful or should be retried, false on fatal errors
 *
 * @note Expands buffer automatically when full to prevent data loss
 * @note EINTR and EAGAIN are not treated as errors for non-blocking sockets
 */
bool GTID_Server_Data::readall() {
	if (size == len) {
		// buffer is full, expand
		resize(len * 2);
	}

	int rc = 0;
	rc = read(w->fd, data+len, size-len);
	if (rc > 0) {
		len += rc;
		return true;
	}

	int myerr = errno;
	if (rc == 0) {
		proxy_info("Read returned EOF\n");
		return false;
	}

	// rc == -1
	proxy_error("Read failed, error %d\n", myerr);
	if(myerr == EINTR || myerr == EAGAIN) {
		// non-blocking fd, so this should not be considered as an error
		return true;
	} else {
		return false;
	}
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
		char *token = NULL;
		char *subtoken = NULL;
		char *str1 = NULL;
		char *str2 = NULL;
		bool updated = false;

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
				} else { // we are reading the trxids
					uint64_t trx_from;
					uint64_t trx_to;
					sscanf(subtoken,"%lu-%lu",&trx_from,&trx_to);
					updated = addGtidInterval(gtid_executed, uuid_server, trx_from, trx_to) || updated;
			   }
			}
		}
		pos += l+1;
		free(bs);

		if (updated) {
			events_read++;
		}
	} else {
		strncpy(rec_msg,data+pos,l);
		pos += l+1;
		rec_msg[l] = 0;
		if (rec_msg[0]=='I') {
			uint64_t rec_trxid = 0;
			char *a = NULL;
			int ul = 0;
			switch (rec_msg[1]) {
				case '1':
					a = strchr(rec_msg+3,':');
					ul = a-rec_msg-3;
					strncpy(uuid_server,rec_msg+3,ul);
					uuid_server[ul] = 0;
					rec_trxid=atoll(a+1);
					break;
				case '2':
					rec_trxid=atoll(rec_msg+3);
					break;
				default:
					break;
			}
			std::string s = uuid_server;
			gtid_t new_gtid = std::make_pair(s,rec_trxid);
			addGtid(new_gtid,gtid_executed);
			events_read++;
		}
	}
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

/**
 * @brief Adds or updates a GTID interval in the executed set
 *
 * This function intelligently merges GTID intervals to prevent events_count reset
 * when a binlog reader reconnects and provides updated GTID sets. It handles
 * reconnection scenarios where the server provides updated transaction ID ranges.
 *
 * For example, during reconnection:
 * - Before disconnection: server_UUID:1-10
 * - After reconnection: server_UUID:1-19
 *
 * This function will update the existing interval rather than replacing it,
 * preserving the events_count metric accuracy.
 *
 * @param gtid_executed Reference to the GTID set to update
 * @param server_uuid The server UUID string
 * @param txid_start Starting transaction ID of the interval
 * @param txid_end Ending transaction ID of the interval
 * @return bool True if the GTID set was updated, false if interval already existed
 *
 * @note This function is critical for maintaining accurate GTID metrics across
 *       binlog reader reconnections and preventing events_count resets.
 */
bool addGtidInterval(gtid_set_t& gtid_executed, std::string server_uuid, int64_t txid_start, int64_t txid_end) {
	bool updated = true;

	auto it = gtid_executed.find(server_uuid);
	if (it == gtid_executed.end()) {
		gtid_executed[server_uuid].emplace_back(txid_start, txid_end);
		return updated;
	}

	bool insert = true;

	// When ProxySQL reconnects with binlog reader, it might
	// receive updated txid intervals in the bootstrap message.
	// For example,
	// before disconnection -> server_UUID:1-10
	// after reconnection   -> server_UUID:1-19
	auto &txid_intervals = it->second;
	for (auto &interval : txid_intervals) {
		if (interval.first == txid_start) {
			if(interval.second == txid_end) {
				updated = false;
			} else {
				interval.second = txid_end;
			}
			insert = false;
			break;
		}
	}

	if (insert) {
		txid_intervals.emplace_back(txid_start, txid_end);

	}

	return updated;
}

void * GTID_syncer_run() {
	//struct ev_loop * gtid_ev_loop;
	//gtid_ev_loop = NULL;
	set_thread_name("GTID", GloVars.set_thread_name);
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

