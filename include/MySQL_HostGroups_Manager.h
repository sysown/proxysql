#ifndef __CLASS_MYSQL_HOSTGROUPS_MANAGER_H
#define __CLASS_MYSQL_HOSTGROUPS_MANAGER_H
#include "proxysql.h"
#include "cpp.h"

#define MYHGM_MYSQL_SERVERS "CREATE TABLE mysql_servers ( hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , status INT CHECK (status IN (0, 1, 2, 3, 4)) NOT NULL DEFAULT 0 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , mem_pointer INT NOT NULL DEFAULT 0 , PRIMARY KEY (hostgroup_id, hostname, port) )"
#define MYHGM_MYSQL_SERVERS_INCOMING "CREATE TABLE mysql_servers_incoming ( hostgroup_id INT NOT NULL DEFAULT 0 , hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , weight INT CHECK (weight >= 0) NOT NULL DEFAULT 1 , status INT CHECK (status IN (0, 1, 2, 3, 4)) NOT NULL DEFAULT 0 , compression INT CHECK (compression >=0 AND compression <= 102400) NOT NULL DEFAULT 0 , max_connections INT CHECK (max_connections >=0) NOT NULL DEFAULT 1000 , max_replication_lag INT CHECK (max_replication_lag >= 0 AND max_replication_lag <= 126144000) NOT NULL DEFAULT 0 , use_ssl INT CHECK (use_ssl IN(0,1)) NOT NULL DEFAULT 0 , max_latency_ms INT UNSIGNED CHECK (max_latency_ms>=0) NOT NULL DEFAULT 0 , PRIMARY KEY (hostgroup_id, hostname, port))"
#define MYHGM_MYSQL_REPLICATION_HOSTGROUPS "CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT CHECK (writer_hostgroup>=0) NOT NULL PRIMARY KEY , reader_hostgroup INT NOT NULL CHECK (reader_hostgroup<>writer_hostgroup AND reader_hostgroup>0) , UNIQUE (reader_hostgroup))"

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



class MySrvConnList {
	private:
	MySrvC *mysrvc;
	int find_idx(MySQL_Connection *);
	public:
	PtrArray *conns;
	MySrvConnList(MySrvC *);
	~MySrvConnList();
	void add(MySQL_Connection *);
	void remove(MySQL_Connection *);
	MySQL_Connection * get_random_MyConn();
	void drop_all_connections();
};

class MySrvC {	// MySQL Server Container
	public:
	MyHGC *myhgc;
	char *address;
	uint16_t port;
	uint16_t flags;
	unsigned int weight;
	enum MySerStatus status;
	unsigned int compression;
	unsigned int max_connections;
	unsigned int max_replication_lag;
	unsigned int connect_OK;
	unsigned int connect_ERR;
	// note that these variables are in microsecond, while user defines max lantency in millisecond
	unsigned int current_latency_us;
	unsigned int max_latency_us;
	time_t time_last_detected_error;
	unsigned int connect_ERR_at_time_last_detected_error;
	unsigned long long queries_sent;
	unsigned long long bytes_sent;
	unsigned long long bytes_recv;
	bool shunned_automatic;
	bool shunned_and_kill_all_connections; // if a serious failure is detected, this will cause all connections to die even if the server is just shunned
	bool use_ssl;
	//uint8_t charset;
	MySrvConnList *ConnectionsUsed;
	MySrvConnList *ConnectionsFree;
	MySrvC(char *, uint16_t, unsigned int, enum MySerStatus, unsigned int, unsigned int _max_connections, unsigned int _max_replication_lag, unsigned int _use_ssl, unsigned int _max_latency_ms);
	~MySrvC();
	void connect_error(int);
	void shun_and_killall();
};

class MySrvList {	// MySQL Server List
	private:
	MyHGC *myhgc;
	int find_idx(MySrvC *);
//	int find_idx(MySQL_Connection *);
	public:
	PtrArray *servers;
	unsigned int cnt();
	MySrvList(MyHGC *);
	~MySrvList();
	void add(MySrvC *);
	void remove(MySrvC *);
	MySrvC * idx(unsigned int);
};

class MyHGC {	// MySQL Host Group Container
	public:
	unsigned int hid;
	MySrvList *mysrvs;
	MyHGC(int);
	~MyHGC();
	MySrvC *get_random_MySrvC();
};

class MySQL_HostGroups_Manager {
	private:
	SQLite3DB	*admindb;
	SQLite3DB	*mydb;
	rwlock_t rwlock;
	PtrArray *MyHostGroups;

	MyHGC * MyHGC_find(unsigned int);
	MyHGC * MyHGC_create(unsigned int);

	void add(MySrvC *, unsigned int);
	void purge_mysql_servers_table();
	void generate_mysql_servers_table();
	void generate_mysql_replication_hostgroups_table();
	SQLite3_result *incoming_replication_hostgroups;

	public:
	struct {
		unsigned int servers_table_version;
		unsigned long client_connections_aborted;
		unsigned long client_connections_created;
		int client_connections;
		unsigned long server_connections_aborted;
		unsigned long server_connections_created;
		unsigned long server_connections_connected;
		unsigned long myconnpoll_get;
		unsigned long myconnpoll_get_ok;
		unsigned long myconnpoll_get_ping;
		unsigned long myconnpoll_push;
		unsigned long myconnpoll_destroy;
		unsigned long long autocommit_cnt;
		unsigned long long commit_cnt;
		unsigned long long rollback_cnt;
		unsigned long long autocommit_cnt_filtered;
		unsigned long long commit_cnt_filtered;
		unsigned long long rollback_cnt_filtered;
	} status;
	MySQL_HostGroups_Manager();
	~MySQL_HostGroups_Manager();
	void rdlock();
	void rdunlock();
	void wrlock();
	void wrunlock();
	bool server_add(unsigned int hid, char *add, uint16_t p=3306, unsigned int _weight=1, enum MySerStatus status=MYSQL_SERVER_STATUS_ONLINE, unsigned int _comp=0, unsigned int _max_connections=100, unsigned int _max_replication_lag=0, unsigned int _use_ssl=0, unsigned int _max_latency_ms=0);
	bool commit();

	void set_incoming_replication_hostgroups(SQLite3_result *);
	SQLite3_result * execute_query(char *query, char **error);
	SQLite3_result *dump_table_mysql_servers();
	SQLite3_result *dump_table_mysql_replication_hostgroups();
	MyHGC * MyHGC_lookup(unsigned int);
	
	void MyConn_add_to_pool(MySQL_Connection *);

	MySQL_Connection * get_MyConn_from_pool(unsigned int);

	void drop_all_idle_connections();
	int get_multiple_idle_connections(int, unsigned long long, MySQL_Connection **, int);
	SQLite3_result * SQL3_Connection_Pool();

	void push_MyConn_to_pool(MySQL_Connection *);
	void destroy_MyConn_from_pool(MySQL_Connection *);	

	void replication_lag_action(int, char*, unsigned int, int);
	void read_only_action(char *hostname, int port, int read_only);
	unsigned int get_servers_table_version();
	void shun_and_killall(char *hostname, int port);
	void set_server_current_latency_ms(char *hostname, int port, unsigned int _current_latency_ms);
};

#endif /* __CLASS_MYSQL_HOSTGROUPS_MANAGER_H */
