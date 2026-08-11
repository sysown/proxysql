#include "GTID_Server_Data.h"
#include "MySQL_HostGroups_Manager.h"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <climits>
#include <cstring>
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
			if (sd->active == false) {
				// protocol error detected during parsing (e.g. unsupported message type)
				MyHGM->gtid_missing_nodes = true;
				proxy_warning("GTID: protocol error from ProxySQL binlog reader on port %d for server %s:%d , disconnecting\n", sd->port, sd->address, sd->mysql_port);
				ev_io_stop(MyHGM->gtid_ev_loop, w);
				close(w->fd);
				free(w);
				sd->w = nullptr;
			}
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
	pthread_rwlock_init(&executed_rwlock, nullptr);
}

void GTID_Server_Data::resize(size_t _s) {
	char *data_ = (char *)malloc(_s);
	memcpy(data_, data, (_s > size ? size : _s));
	size = _s;
	free(data);
	data = data_;
}

GTID_Server_Data::~GTID_Server_Data() {
	pthread_rwlock_destroy(&executed_rwlock);
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
	pthread_rwlock_rdlock(&executed_rwlock);
	bool found = gtid_executed.has_gtid((std::string)gtid_uuid, gtid_trxid);
	pthread_rwlock_unlock(&executed_rwlock);
	return found;
}

bool GTID_Server_Data::add_gtid_from_ok(const char* gtid) {
	if (gtid == nullptr) {
		return false;
	}

	const char* sep = strrchr(gtid, ':');
	if (sep == nullptr || sep == gtid || sep[1] == '\0') {
		return false;
	}

	std::string uuid(gtid, static_cast<size_t>(sep - gtid));
	uuid.erase(std::remove(uuid.begin(), uuid.end(), '-'), uuid.end());
	if (uuid.size() != 32 || !std::all_of(uuid.begin(), uuid.end(), [](unsigned char c) {
			return std::isxdigit(c) != 0;
		})) {
		return false;
	}

	errno = 0;
	char* end = nullptr;
	unsigned long long parsed = strtoull(sep + 1, &end, 10);
	if (errno == ERANGE || end == sep + 1 || *end != '\0' || parsed == 0 ||
			parsed > static_cast<unsigned long long>(LLONG_MAX)) {
		return false;
	}

	pthread_rwlock_wrlock(&executed_rwlock);
	bool updated = gtid_executed.add(uuid, static_cast<trxid_t>(parsed));
	pthread_rwlock_unlock(&executed_rwlock);
	return updated;
}

std::string GTID_Server_Data::gtid_executed_to_string() {
	pthread_rwlock_rdlock(&executed_rwlock);
	std::string executed = gtid_executed.to_string();
	pthread_rwlock_unlock(&executed_rwlock);
	return executed;
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

/*
 * The wire format for the binlogreader is five distinct messages, in plaintext:
 *
 * ST=<uuid>:<trxid>[-<trxid>][,<uuid>:<trxid>[-<trxid>], ...] : Bootstrap message, providing individual transaction ID or trxid ranges for all seen UUID servers.
 * I1=<uuid>:<trxid>                                            : Latest seen single trxid for a given UUID.
 * I2=<trxid>                                                   : Latest seen single trxid, reusing UUID from previous I1/I3 message.
 * I3=<uuid>:<trxid_start>-<trxid_end>                         : Latest seen trxid range for a given UUID.
 * I4=<trxid_start>-<trxid_end>                                : Latest seen trxid range, reusing UUID from previous I1/I3 message.
 */
bool GTID_Server_Data::read_next_gtid() {
	pthread_rwlock_wrlock(&executed_rwlock);
	if (len==0) {
		pthread_rwlock_unlock(&executed_rwlock);
		return false;
	}
	void *nlp = NULL;
	nlp = memchr(data+pos,'\n',len-pos);
	if (nlp == NULL) {
		pthread_rwlock_unlock(&executed_rwlock);
		return false;
	}
	int l = (char *)nlp - (data+pos);
	char rec_msg[80];
	if (strncmp(data+pos,(char *)"ST=",3)==0) {
		// we are reading the bootstrap
		bool invalid_msg = false;
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
					*p = '\0';
				} else { // we are reading the trxid or trxid range
					TrxId_Interval iv(trxid_t(0));
					if (!TrxId_Interval::parse(subtoken, &iv)) {
						invalid_msg = true;
						break;
					}
					updated = gtid_executed.add((std::string)uuid_server, iv) || updated;
				}
			}
			if (invalid_msg || j == 0 || j%2 != 0) {
				invalid_msg = true;
				break;
			}
		}
		pos += l+1;
		free(bs);

		if (invalid_msg) {
			proxy_warning("GTID: invalid bootstrap message from binlog reader on port %d for server %s:%d, disconnecting\n",
				port, address, mysql_port);
			active = false;
			pthread_rwlock_unlock(&executed_rwlock);
			return false;
		}

		if (updated) {
			events_read++;
		}
	} else {
		strncpy(rec_msg,data+pos,l);
		pos += l+1;
		rec_msg[l] = 0;
		bool invalid_msg = false;
		if (rec_msg[0]=='I') {
			char *a = NULL;
			int ul = 0;
			switch (rec_msg[1]) {
				case '1': // single trxid with UUID
					a = strchr(rec_msg+3,':');
					if (a == NULL) {
						invalid_msg = true;
						break;
					}
					ul = a-rec_msg-3;
					strncpy(uuid_server,rec_msg+3,ul);
					uuid_server[ul] = 0;
					gtid_executed.add((std::string)uuid_server, (trxid_t)atoll(a+1));
					events_read++;
					break;
				case '2': // single trxid, reuse last UUID
					gtid_executed.add((std::string)uuid_server, (trxid_t)atoll(rec_msg+3));
					events_read++;
					break;
				case '3': // trxid range with UUID
					a = strchr(rec_msg+3,':');
					if (a == NULL) {
						invalid_msg = true;
						break;
					}
					ul = a-rec_msg-3;
					strncpy(uuid_server,rec_msg+3,ul);
					uuid_server[ul] = 0;
					{
						TrxId_Interval iv(trxid_t(0));
						if (!TrxId_Interval::parse(a+1, &iv)) {
							invalid_msg = true;
							break;
						}
						gtid_executed.add((std::string)uuid_server, iv);
					}
					events_read++;
					break;
				case '4': // trxid range, reuse last UUID
					{
						TrxId_Interval iv(trxid_t(0));
						if (!TrxId_Interval::parse(rec_msg+3, &iv)) {
							invalid_msg = true;
							break;
						}
						gtid_executed.add((std::string)uuid_server, iv);
					}
					events_read++;
					break;
				default:
					invalid_msg = true;
			}

			if (invalid_msg) {
				proxy_warning("GTID: invalid or unsupported message (%s) from binlog reader on port %d for server %s:%d, disconnecting\n",
					rec_msg, port, address, mysql_port);
				active = false;
				pthread_rwlock_unlock(&executed_rwlock);
				return false;
			}
		}
	}
	pthread_rwlock_unlock(&executed_rwlock);
	return true;
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
