#ifndef __CLASS_MYSQL_HOSTGROUPS_MANAGER_H
#define __CLASS_MYSQL_HOSTGROUPS_MANAGER_H
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_gtid.h"

#include <thread>
#include <iostream>

#include "thread.h"
#include "wqueue.h"


#include "ev.h"

/*
	Enabling STRESSTEST_POOL ProxySQL will do a lot of loops in the connection pool
	This is for internal testing ONLY!!!!
#define STRESSTEST_POOL
*/

#define MHM_PTHREAD_MUTEX


// we have 2 versions of the same tables: with (debug) and without (no debug) checks
#ifdef DEBUG
#define MYHGM_MYSQL_SERVERS "CREATE TABLE mysql_servers ( hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , gtid_port INT NOT NULL DEFAULT 0 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , status INT CHECK (status IN (0, 1, 2, 3, 4)) NOT NULL DEFAULT 0 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , mem_pointer INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostgroup_id, hostname, port) )"
#define MYHGM_MYSQL_SERVERS_INCOMING "CREATE TABLE mysql_servers_incoming ( hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , gtid_port INT NOT NULL DEFAULT 0 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , status INT CHECK (status IN (0, 1, 2, 3, 4)) NOT NULL DEFAULT 0 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port))"
#else
#define MYHGM_MYSQL_SERVERS "CREATE TABLE mysql_servers ( hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , gtid_port INT NOT NULL DEFAULT 0 , weight INT NOT NULL DEFAULT 1 , status INT NOT NULL DEFAULT 0 , compression INT NOT NULL DEFAULT 0 , max_connections INT NOT NULL DEFAULT 1000 , max_replication_lag INT NOT NULL DEFAULT 0 , use_ssl INT NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , mem_pointer INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostgroup_id, hostname, port) )"
#define MYHGM_MYSQL_SERVERS_INCOMING "CREATE TABLE mysql_servers_incoming ( hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , gtid_port INT NOT NULL DEFAULT 0 , weight INT NOT NULL DEFAULT 1 , status INT NOT NULL DEFAULT 0 , compression INT NOT NULL DEFAULT 0 , max_connections INT NOT NULL DEFAULT 1000 , max_replication_lag INT NOT NULL DEFAULT 0 , use_ssl INT NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED NOT NULL DEFAULT 0 , comment VARCHAR NOT NULL DEFAULT '' , PRIMARY KEY (hostgroup_id, hostname, port))"
#endif /* DEBUG */
#define MYHGM_MYSQL_REPLICATION_HOSTGROUPS "CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>=0) , check_type VARCHAR CHECK (LOWER(check_type) IN ('read_only','innodb_read_only','super_read_only')) NOT NULL DEFAULT 'read_only' , comment VARCHAR NOT NULL DEFAULT '' , UNIQUE (reader_hostgroup))"

#define MYHGM_MYSQL_GROUP_REPLICATION_HOSTGROUPS "CREATE TABLE mysql_group_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0) , offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1)) NOT NULL DEFAULT 0 , max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0 , comment VARCHAR , UNIQUE (reader_hostgroup) , UNIQUE (offline_hostgroup) , UNIQUE (backup_writer_hostgroup))"

#define MYHGM_MYSQL_GALERA_HOSTGROUPS "CREATE TABLE mysql_galera_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , backup_writer_hostgroup INT CHECK (backup_writer_hostgroup>=0 AND backup_writer_hostgroup<>writer_hostgroup) NOT NULL , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND backup_writer_hostgroup<>reader_hostgroup AND reader_hostgroup>0) , offline_hostgroup INT NOT NULL CHECK (offline_hostgroup<>writer_hostgroup AND offline_hostgroup<>reader_hostgroup AND backup_writer_hostgroup<>offline_hostgroup AND offline_hostgroup>=0) , active INT CHECK (active IN (0,1)) NOT NULL DEFAULT 1 , max_writers INT NOT NULL CHECK (max_writers >= 0) DEFAULT 1 , writer_is_also_reader INT CHECK (writer_is_also_reader IN (0,1,2)) NOT NULL DEFAULT 0 , max_transactions_behind INT CHECK (max_transactions_behind>=0) NOT NULL DEFAULT 0 , comment VARCHAR , UNIQUE (reader_hostgroup) , UNIQUE (offline_hostgroup) , UNIQUE (backup_writer_hostgroup))"

typedef std::unordered_map<std::uint64_t, void *> umap_mysql_errors;

class MySrvConnList;
class MySrvC;
class MySrvList;
class MyHGC;

enum MySerStatus {
	MYSQL_SERVER_STATUS_ONLINE,
	MYSQL_SERVER_STATUS_SHUNNED,
	MYSQL_SERVER_STATUS_OFFLINE_SOFT,
	MYSQL_SERVER_STATUS_OFFLINE_HARD,
	MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG
};


std::string gtid_executed_to_string(gtid_set_t& gtid_executed);
void addGtid(const gtid_t& gtid, gtid_set_t& gtid_executed);

class GTID_Server_Data {
	public:
	char *address;
	uint16_t port;
	uint16_t mysql_port;
	char *data;
	size_t len;
	size_t size;
	size_t pos;
	struct ev_io *w;
	char uuid_server[64];
	unsigned long long events_read;
	gtid_set_t gtid_executed;
	bool active;
	GTID_Server_Data(struct ev_io *_w, char *_address, uint16_t _port, uint16_t _mysql_port);
	void resize(size_t _s);
	~GTID_Server_Data();
	bool readall();
	bool writeout();
	bool read_next_gtid();
/*
	GTID_Server_Data(struct ev_io *_w, char *_address, uint16_t _port, uint16_t _mysql_port) {
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
	}
	void resize(size_t _s) {
		char *data_ = (char *)malloc(_s);
		memcpy(data_, data, (_s > size ? size : _s));
		size = _s;
		free(data);
		data = data_;
	}
	~GTID_Server_Data() {
		free(address);
		free(data);
	}
	bool readall() {
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
			fprintf(stderr,"read returned %d bytes, error %d\n", rc, myerr);
			if (
				//(rc == 0) ||
				(rc==-1 && myerr != EINTR && myerr != EAGAIN)
			) {
				ret = false;
			}
		}
		return ret;
	}
	bool writeout() {
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
	bool read_next_gtid() {
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
				fprintf(stdout,"%s:%lu\n", uuid_server, rec_trxid);
				std::string s = uuid_server;
				gtid_t new_gtid = std::make_pair(s,rec_trxid);
				addGtid(new_gtid,gtid_executed);
				//return true;
			}
		}
		std::cout << "current pos " << gtid_executed_to_string(gtid_executed) << std::endl << std::endl;
		return true;
	}
*/
	bool gtid_exists(char *gtid_uuid, uint64_t gtid_trxid);
	void read_all_gtids();
	void dump();
/*
	bool gtid_exists(char *gtid_uuid, uint64_t gtid_trxid) {
		std::string s = gtid_uuid;
		auto it = gtid_executed.find(s);
		fprintf(stderr,"Checking if server %s:%d has GTID %s:%lu ... ", address, port, gtid_uuid, gtid_trxid);
		if (it == gtid_executed.end()) {
			fprintf(stderr,"NO\n");
			return false;
		}
		for (auto itr = it->second.begin(); itr != it->second.end(); ++itr) {
			if ((int64_t)gtid_trxid >= itr->first && (int64_t)gtid_trxid <= itr->second) {
				fprintf(stderr,"YES\n");
				return true;
			}
		}
		fprintf(stderr,"NO\n");
		return false;
	}
	void read_all_gtids() {
		while (read_next_gtid()) {
		}
	}
	void dump() {
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
*/
};



class MySrvConnList {
	private:
	PtrArray *conns;
	MySrvC *mysrvc;
	int find_idx(MySQL_Connection *c) {
		//for (unsigned int i=0; i<conns_length(); i++) {
		for (unsigned int i=0; i<conns->len; i++) {
			MySQL_Connection *conn = NULL;
			conn = (MySQL_Connection *)conns->index(i);
			if (conn==c) {
				return (unsigned int)i;
			}
		}
		return -1;
	}
	public:
	MySrvConnList(MySrvC *);
	~MySrvConnList();
	void add(MySQL_Connection *);
	void remove(MySQL_Connection *c) {
		int i = -1;
		i = find_idx(c);
		assert(i>=0);
		conns->remove_index_fast((unsigned int)i);
	}
	MySQL_Connection *remove(int);
	MySQL_Connection * get_random_MyConn(MySQL_Session *sess, bool ff);
	unsigned int conns_length() { return conns->len; }
	void drop_all_connections();
	MySQL_Connection *index(unsigned int);
};

class MySrvC {	// MySQL Server Container
	public:
	MyHGC *myhgc;
	char *address;
	uint16_t port;
	uint16_t gtid_port;
	uint16_t flags;
	unsigned int weight;
	enum MySerStatus status;
	unsigned int compression;
	unsigned int max_connections;
	unsigned int max_replication_lag;
	unsigned int max_connections_used; // The maximum number of connections that has been opened
	unsigned int connect_OK;
	unsigned int connect_ERR;
	// note that these variables are in microsecond, while user defines max lantency in millisecond
	unsigned int current_latency_us;
	unsigned int max_latency_us;
	time_t time_last_detected_error;
	unsigned int connect_ERR_at_time_last_detected_error;
	unsigned long long queries_sent;
	unsigned long long queries_gtid_sync;
	unsigned long long bytes_sent;
	unsigned long long bytes_recv;
	bool shunned_automatic;
	bool shunned_and_kill_all_connections; // if a serious failure is detected, this will cause all connections to die even if the server is just shunned
	bool use_ssl;
	char *comment;
	MySrvConnList *ConnectionsUsed;
	MySrvConnList *ConnectionsFree;
	MySrvC(char *, uint16_t, uint16_t, unsigned int, enum MySerStatus, unsigned int, unsigned int _max_connections, unsigned int _max_replication_lag, unsigned int _use_ssl, unsigned int _max_latency_ms, char *_comment);
	~MySrvC();
	void connect_error(int);
	void shun_and_killall();
	/**
	 * Update the maximum number of used connections
	 * @return 
	 *  the maximum number of used connections
	 */
	unsigned int update_max_connections_used()
	{
		unsigned int connections_used = ConnectionsUsed->conns_length();
		if (max_connections_used < connections_used)
			max_connections_used = connections_used;
		return max_connections_used;
	}
};

class MySrvList {	// MySQL Server List
	private:
	MyHGC *myhgc;
	int find_idx(MySrvC *);
	public:
	PtrArray *servers;
	unsigned int cnt() { return servers->len; }
	MySrvList(MyHGC *);
	~MySrvList();
	void add(MySrvC *);
	void remove(MySrvC *);
	MySrvC * idx(unsigned int i) {return (MySrvC *)servers->index(i); }
};

class MyHGC {	// MySQL Host Group Container
	public:
	unsigned int hid;
	unsigned long long current_time_now;
	uint32_t new_connections_now;
	MySrvList *mysrvs;
	MyHGC(int);
	~MyHGC();
	MySrvC *get_random_MySrvC(char * gtid_uuid, uint64_t gtid_trxid);
};

class Group_Replication_Info {
	public:
	int writer_hostgroup;
	int backup_writer_hostgroup;
	int reader_hostgroup;
	int offline_hostgroup;
	int max_writers;
	int max_transactions_behind;
	char *comment;
	bool active;
	int writer_is_also_reader;
	bool __active;
	bool need_converge; // this is set to true on LOAD MYSQL SERVERS TO RUNTIME . This ensure that checks wil take an action
	int current_num_writers;
	int current_num_backup_writers;
	int current_num_readers;
	int current_num_offline;
	Group_Replication_Info(int w, int b, int r, int o, int mw, int mtb, bool _a, int _w, char *c);
	bool update(int b, int r, int o, int mw, int mtb, bool _a, int _w, char *c);
	~Group_Replication_Info();
};

class Galera_Info {
	public:
	int writer_hostgroup;
	int backup_writer_hostgroup;
	int reader_hostgroup;
	int offline_hostgroup;
	int max_writers;
	int max_transactions_behind;
	char *comment;
	bool active;
	int writer_is_also_reader;
	bool __active;
	bool need_converge; // this is set to true on LOAD MYSQL SERVERS TO RUNTIME . This ensure that checks wil take an action
	int current_num_writers;
	int current_num_backup_writers;
	int current_num_readers;
	int current_num_offline;
	Galera_Info(int w, int b, int r, int o, int mw, int mtb, bool _a, int _w, char *c);
	bool update(int b, int r, int o, int mw, int mtb, bool _a, int _w, char *c);
	~Galera_Info();
};

class MySQL_HostGroups_Manager {
	private:
	SQLite3DB	*admindb;
	SQLite3DB	*mydb;
	pthread_mutex_t readonly_mutex;
#ifdef MHM_PTHREAD_MUTEX
	pthread_mutex_t lock;
#else
	rwlock_t rwlock;
#endif
	PtrArray *MyHostGroups;

	MyHGC * MyHGC_find(unsigned int);
	MyHGC * MyHGC_create(unsigned int);

	void add(MySrvC *, unsigned int);
	void purge_mysql_servers_table();
	void generate_mysql_servers_table(int *_onlyhg=NULL);
	void generate_mysql_replication_hostgroups_table();
	SQLite3_result *incoming_replication_hostgroups;

	void generate_mysql_group_replication_hostgroups_table();
	SQLite3_result *incoming_group_replication_hostgroups;

	pthread_mutex_t Group_Replication_Info_mutex;
	std::map<int , Group_Replication_Info *> Group_Replication_Info_Map;

	void generate_mysql_galera_hostgroups_table();
	SQLite3_result *incoming_galera_hostgroups;

	pthread_mutex_t Galera_Info_mutex;
	std::map<int , Galera_Info *> Galera_Info_Map;

	std::thread *HGCU_thread;

	std::thread *GTID_syncer_thread;
	//pthread_t GTID_syncer_thread_id;
	//pthread_t HGCU_thread_id;

	char rand_del[8];
	pthread_mutex_t mysql_errors_mutex;
	umap_mysql_errors mysql_errors_umap;

	public:
	pthread_rwlock_t gtid_rwlock;
	std::unordered_map <string, GTID_Server_Data *> gtid_map;
	struct ev_async * gtid_ev_async;
	struct ev_loop * gtid_ev_loop;
	struct ev_timer * gtid_ev_timer;
	bool gtid_missing_nodes;
	struct {
		unsigned int servers_table_version;
		pthread_mutex_t servers_table_version_lock;
		pthread_cond_t servers_table_version_cond;
		unsigned long client_connections_aborted;
		unsigned long client_connections_created;
		int client_connections;
		unsigned long server_connections_aborted;
		unsigned long server_connections_created;
		unsigned long server_connections_delayed;
		unsigned long server_connections_connected;
		unsigned long myconnpoll_get;
		unsigned long myconnpoll_get_ok;
		unsigned long myconnpoll_get_ping;
		unsigned long myconnpoll_push;
		unsigned long myconnpoll_reset;
		unsigned long myconnpoll_destroy;
		unsigned long long autocommit_cnt;
		unsigned long long commit_cnt;
		unsigned long long rollback_cnt;
		unsigned long long autocommit_cnt_filtered;
		unsigned long long commit_cnt_filtered;
		unsigned long long rollback_cnt_filtered;
		unsigned long long backend_change_user;
		unsigned long long backend_init_db;
		unsigned long long backend_set_names;
		unsigned long long frontend_init_db;
		unsigned long long frontend_set_names;
		unsigned long long frontend_use_db;
	} status;
	wqueue<MySQL_Connection *> queue;
	MySQL_HostGroups_Manager();
	~MySQL_HostGroups_Manager();
	void init();
	void wrlock();
	void wrunlock();
	bool server_add(unsigned int hid, char *add, uint16_t p=3306, uint16_t gp=0, unsigned int _weight=1, enum MySerStatus status=MYSQL_SERVER_STATUS_ONLINE, unsigned int _comp=0, unsigned int _max_connections=100, unsigned int _max_replication_lag=0, unsigned int _use_ssl=0, unsigned int _max_latency_ms=0, char *comment=NULL);
	int servers_add(SQLite3_result *resultset); // faster version of server_add
	bool commit();

	void set_incoming_replication_hostgroups(SQLite3_result *);
	void set_incoming_group_replication_hostgroups(SQLite3_result *);
	void set_incoming_galera_hostgroups(SQLite3_result *);
	SQLite3_result * execute_query(char *query, char **error);
	SQLite3_result *dump_table_mysql_servers();
	SQLite3_result *dump_table_mysql_replication_hostgroups();
	SQLite3_result *dump_table_mysql_group_replication_hostgroups();
	SQLite3_result *dump_table_mysql_galera_hostgroups();
	MyHGC * MyHGC_lookup(unsigned int);
	
	void MyConn_add_to_pool(MySQL_Connection *);

	MySQL_Connection * get_MyConn_from_pool(unsigned int hid, MySQL_Session *sess, bool ff, char * gtid_uuid, uint64_t gtid_trxid);

	void drop_all_idle_connections();
	int get_multiple_idle_connections(int, unsigned long long, MySQL_Connection **, int);
	SQLite3_result * SQL3_Connection_Pool(bool _reset);

	void push_MyConn_to_pool(MySQL_Connection *, bool _lock=true);
	void push_MyConn_to_pool_array(MySQL_Connection **, unsigned int);
	void destroy_MyConn_from_pool(MySQL_Connection *, bool _lock=true);	

	void replication_lag_action(int, char*, unsigned int, int);
	void read_only_action(char *hostname, int port, int read_only);
	unsigned int get_servers_table_version();
	void wait_servers_table_version(unsigned, unsigned);
	bool shun_and_killall(char *hostname, int port);
	void set_server_current_latency_us(char *hostname, int port, unsigned int _current_latency_us);
	unsigned long long Get_Memory_Stats();

	void update_group_replication_set_offline(char *_hostname, int _port, int _writer_hostgroup, char *error);
	void update_group_replication_set_read_only(char *_hostname, int _port, int _writer_hostgroup, char *error);
	void update_group_replication_set_writer(char *_hostname, int _port, int _writer_hostgroup);
	void converge_group_replication_config(int _writer_hostgroup);

	void update_galera_set_offline(char *_hostname, int _port, int _writer_hostgroup, char *error);
	void update_galera_set_read_only(char *_hostname, int _port, int _writer_hostgroup, char *error);
	void update_galera_set_writer(char *_hostname, int _port, int _writer_hostgroup);
	void converge_galera_config(int _writer_hostgroup);

	SQLite3_result * get_stats_mysql_gtid_executed();
	void generate_mysql_gtid_executed_tables();
	bool gtid_exists(MySrvC *mysrvc, char * gtid_uuid, uint64_t gtid_trxid);

	SQLite3_result *SQL3_Get_ConnPool_Stats();
	void increase_reset_counter();

	void add_mysql_errors(int hostgroup, char *hostname, int port, char *username, char *schemaname, int err_no, char *last_error);

};

#endif /* __CLASS_MYSQL_HOSTGROUPS_MANAGER_H */
