#define ADMIN_SQLITE_TABLE_SERVER_STATUS "CREATE TABLE server_status ( status INT NOT NULL PRIMARY KEY, status_desc VARCHAR NOT NULL, UNIQUE(status_desc) )"
#define ADMIN_SQLITE_TABLE_SERVERS "CREATE TABLE servers ( hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , read_only INT NOT NULL DEFAULT 1, status INT NOT NULL DEFAULT ('OFFLINE') REFERENCES server_status(status) , PRIMARY KEY(hostname, port) )"
#define ADMIN_SQLITE_TABLE_HOSTGROUPS "CREATE TABLE hostgroups ( hostgroup_id INT NOT NULL DEFAULT 0, hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306, FOREIGN KEY (hostname, port) REFERENCES servers (hostname, port) , PRIMARY KEY (hostgroup_id, hostname, port) )"
#define ADMIN_SQLITE_TABLE_USERS "CREATE TABLE users ( username VARCHAR NOT NULL PRIMARY KEY , password VARCHAR , active INT NOT NULL DEFAULT 1)"
#define ADMIN_SQLITE_TABLE_DEBUG_LEVELS "CREATE TABLE debug_levels (module VARCHAR NOT NULL PRIMARY KEY, verbosity INT NOT NULL DEFAULT 0)"
#define ADMIN_SQLITE_TABLE_GLOBAL_VARIABLES "CREATE TABLE global_variables ( name VARCHAR NOT NULL PRIMARY KEY , value VARCHAR NOT NULL )"
#define ADMIN_SQLITE_TABLE_QUERY_RULES "CREATE TABLE query_rules (rule_id INT NOT NULL PRIMARY KEY, active INT NOT NULL DEFAULT 0, username VARCHAR, schemaname VARCHAR, flagIN INT NOT NULL DEFAULT 0, match_pattern VARCHAR NOT NULL, negate_match_pattern INT NOT NULL DEFAULT 0, flagOUT INT NOT NULL DEFAULT 0, replace_pattern VARCHAR, destination_hostgroup INT NOT NULL DEFAULT 0, audit_log INT NOT NULL DEFAULT 0, performance_log INT NOT NULL DEFAULT 0, cache_tag INT NOT NULL DEFAULT 0, invalidate_cache_tag INT NOT NULL DEFAULT 0, invalidate_cache_pattern VARCHAR, cache_ttl INT NOT NULL DEFAULT 0)"
#define ADMIN_SQLITE_TABLE_DEFAULT_HOSTGROUPS "CREATE TABLE default_hostgroups (username VARCHAR, schemaname VARCHAR, hostgroup_id INT NOT NULL DEFAULT 0, PRIMARY KEY(username, schemaname))"

/*
#define ADMIN_SQLITE_DUMP_TABLE_SERVER_STATUS "SELECT 'INSERT INTO server_status VALUES (' || quote(status) || ',' || quote(status_desc) || ')' FROM server_status"
#define ADMIN_SQLITE_DUMP_TABLE_SERVERS "SELECT 'INSERT INTO servers VALUES (' || quote(hostname) || ',' || quote(port) || ',' || quote(read_only) || ',' || quote(status) || ')' FROM servers"
#define ADMIN_SQLITE_DUMP_TABLE_HOSTGROUPS "SELECT 'INSERT INTO hostgroups VALUES (' || quote(hostgroup_id) || ',' || quote(hostname) || ',' || quote(port) || ')' FROM hostgroups"
#define ADMIN_SQLITE_DUMP_TABLE_USERS "SELECT 'INSERT INTO users VALUES (' || quote(username) || ',' || quote(password) || ',' || quote(active) || ')' FROM users"
#define ADMIN_SQLITE_DUMP_TABLE_DEBUG_LEVELS "SELECT 'INSERT INTO debug_levels VALUES (' || quote(module) || ',' || quote(verbosity) || ')' FROM debug_levels"

#define ADMIN_SQLITE_DUMP_TABLE_QUERY_RULES "SELECT 'INSERT INTO query_rules VALUES (' || quote(rule_id) || ',' || quote(active) || ',' || quote(username) || ',' || quote(schemaname) || ',' || quote(flagIN) || ',' || quote(match_pattern) || ',' || quote(negate_match_pattern) || ',' || quote(flagOUT) || ',' || quote(replace_pattern) || ',' || quote(destination_hostgroup) || ',' || quote(audit_log) || ',' || quote(performance_log) || ',' || quote(cache_tag) || ',' || quote(invalidate_cache_tag) || ',' || quote(invalidate_cache_pattern) || ',' || quote(cache_ttl) || ')' FROM query_rules"
*/

#define ADMIN_SQLITE_TABLE_BACKUP_SERVER_STATUS "CREATE TABLE server_status ( status INT NOT NULL PRIMARY KEY, status_desc VARCHAR NOT NULL, UNIQUE(status_desc) )"
#define ADMIN_SQLITE_TABLE_BACKUP_SERVERS "CREATE TABLE servers ( hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , read_only INT NOT NULL DEFAULT 1, status INT NOT NULL DEFAULT ('OFFLINE') REFERENCES server_status(status) , PRIMARY KEY(hostname, port) )"
#define ADMIN_SQLITE_TABLE_BACKUP_HOSTGROUPS "CREATE TABLE hostgroups ( hostgroup_id INT NOT NULL DEFAULT 0, hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306, FOREIGN KEY (hostname, port) REFERENCES servers (hostname, port) , PRIMARY KEY (hostgroup_id, hostname, port) )"
#define ADMIN_SQLITE_TABLE_BACKUP_USERS "CREATE TABLE users ( username VARCHAR NOT NULL PRIMARY KEY , password VARCHAR , active INT NOT NULL DEFAULT 1)"
#define ADMIN_SQLITE_TABLE_BACKUP_DEBUG_LEVELS "CREATE TABLE debug_levels (module VARCHAR NOT NULL PRIMARY KEY, verbosity INT NOT NULL DEFAULT 0)"
#define ADMIN_SQLITE_TABLE_BACKUP_GLOBAL_VARIABLES "CREATE TABLE global_variables ( name VARCHAR NOT NULL PRIMARY KEY , value VARCHAR NOT NULL )"
#define ADMIN_SQLITE_TABLE_BACKUP_QUERY_RULES "CREATE TABLE query_rules (rule_id INT NOT NULL PRIMARY KEY, active INT NOT NULL DEFAULT 0, username VARCHAR, schemaname VARCHAR, flagIN INT NOT NULL DEFAULT 0, match_pattern VARCHAR NOT NULL, negate_match_pattern INT NOT NULL DEFAULT 0, flagOUT INT NOT NULL DEFAULT 0, replace_pattern VARCHAR, destination_hostgroup INT NOT NULL DEFAULT 0, audit_log INT NOT NULL DEFAULT 0, performance_log INT NOT NULL DEFAULT 0, cache_tag INT NOT NULL DEFAULT 0, invalidate_cache_tag INT NOT NULL DEFAULT 0, invalidate_cache_pattern VARCHAR, cache_ttl INT NOT NULL DEFAULT 0)"

//#define ADMIN_SQLITE_TABLE_SERVERS "CREATE TABLE servers ( name VARCHAR NOT NULL PRIMARY KEY, hostname VARCHAR NOT NULL , port INT NOT NULL DEFAULT 3306 , read_only INT NOT NULL DEFAULT 1, status VARCHAR NOT NULL DEFAULT ('OFFLINE') REFERENCES server_status(status), hostgroup INT NOT NULL DEFAULT 0)"
//#define ADMIN_SQLITE_TABLE_QUERY_RULES "CREATE TABLE query_rules (rule_id INT NOT NULL PRIMARY KEY, username VARCHAR, schemaname VARCHAR, flagIN INT NOT NULL DEFAULT 0, match_pattern VARCHAR NOT NULL, negate_match_pattern INT NOT NULL DEFAULT 0, flagOUT INT NOT NULL DEFAULT 0, replace_pattern VARCHAR, destination_hostgroup INT NOT NULL DEFAULT 0, audit_log INT NOT NULL DEFAULT 0, performance_log INT NOT NULL DEFAULT 0, caching_ttl INT NOT NULL DEFAULT 0)"
//#define ADMIN_SQLITE_TABLE_QUERY_RULES "CREATE TABLE query_rules (rule_id INT NOT NULL PRIMARY KEY, username VARCHAR, schemaname VARCHAR, flagIN INT NOT NULL DEFAULT 0, match_pattern VARCHAR NOT NULL, negate_match_pattern INT NOT NULL DEFAULT 0, flagOUT INT NOT NULL DEFAULT 0, replace_pattern VARCHAR, destination_hostgroup INT NOT NULL DEFAULT 0 REFERENCES hostgroups(hostgroup_id), audit_log INT NOT NULL DEFAULT 0, performance_log INT NOT NULL DEFAULT 0, cache_tag INT NOT NULL DEFAULT 0, invalidate_cache_tag INT NOT NULL DEFAULT 0, invalidate_cache_pattern VARCHAR, cache_ttl INT NOT NULL DEFAULT 0)"

#define STATSDB_QUERY_STATS "CREATE TABLE query_stats (timestamp INT NOT NULL, query_digest_md5 TEXT NOT NULL, query_digest_text TEXT NOT NULL, username TEXT NOT NULL, schemaname TEXT NOT NULL, hostgroup_id INT, server_address TEXT, server_port INT, query_time INT NOT NULL, exec_cnt INT NOT NULL, PRIMARY KEY(timestamp, query_digest_md5, username, schemaname, hostgroup_id, server_address, server_port) )"

#define DEBUGDB_DEBUG_LOG "CREATE TABLE debug_log (timestamp INT NOT NULL, thread_id INT NOT NULL, module TEXT NOT NULL, filename TEXT NOT NULL, line INT NOT NULL, funct TEXT NOT NULL, level INT NOT NULL, message TEXT NOT NULL)"

#define DUMP_RUNTIME_QUERY_CACHE	"DUMP RUNTIME QUERY CACHE"
#define DUMP_RUNTIME_QUERY_RULES	"DUMP RUNTIME QUERY RULES"
#define DUMP_RUNTIME_DEFAULT_HOSTGROUPS	"DUMP RUNTIME DEFAULT HOSTGROUPS"

#define CONFIG_SYNC_MEM_TO_DISK		"CONFIG SYNC TO DISK"

struct _admin_sqlite_table_def_t {
	char *table_name;
	char *table_def;
//	char *dumpcmd;
//	GPtrArray *dumps[3];
//	GPtrArray *dump_configdb;
//	GPtrArray *dump_admindb;
//	GPtrArray *dump_monitordb;
};


void mysql_pkt_err_from_sqlite(pkt *, const char *);
int mysql_pkt_to_sqlite_exec(pkt *, mysql_session_t *);
void sqlite3_exec_exit_on_failure(sqlite3 *, const char *);
void sqlite3_flush_debug_levels_mem_to_db(sqlite3 *, int);
int sqlite3_flush_debug_levels_db_to_mem(sqlite3 *);
void sqlite3_flush_users_mem_to_db(sqlite3 *, int, int);
int sqlite3_flush_users_db_to_mem(sqlite3 *);
int sqlite3_flush_default_hostgroups_db_to_mem(sqlite3 *);
void admin_init_sqlite3();
int sqlite3_flush_servers_db_to_mem(sqlite3 *, int);
void sqlite3_flush_servers_mem_to_db(sqlite3 *, int);
int sqlite3_flush_query_rules_db_to_mem(sqlite3 *);
int sqlite3_dump_runtime_hostgroups(sqlite3 *);
int sqlite3_dump_runtime_query_rules(sqlite3 *);
int sqlite3_dump_runtime_query_cache(sqlite3 *);
int sqlite3_dump_runtime_default_hostgroups(sqlite3 *);
int sqlite3_config_sync_mem_to_disk();
void __sqlite3_statsdb__flush_query_stats(gpointer, gpointer);
void __sqlite3_debugdb__flush_debugs(sqlite3_stmt *, dbg_msg_t *);
//int sqlite3_dump_runtime_query_rules();
//int sqlite3_dump_runtime_query_cache();


struct previous_mode_data {
  int valid;        /* Is there legit data in here? */
  int mode;
  int showHeader;
  int colWidth[100];
};


struct callback_data {
  sqlite3 *db;           /* The database */
  int echoOn;            /* True to echo input commands */
  int statsOn;           /* True to display memory stats before each finalize */
  int cnt;               /* Number of records displayed so far */
  FILE *out;             /* Write results here */
  FILE *traceOut;        /* Output for sqlite3_trace() */
  int nErr;              /* Number of errors seen */
  int mode;              /* An output mode setting */
  int writableSchema;    /* True if PRAGMA writable_schema=ON */
  int showHeader;        /* True to show column names in List or Column mode */
  char *zDestTable;      /* Name of destination table when MODE_Insert */
  char separator[20];    /* Separator character for MODE_List */
  int colWidth[100];     /* Requested width of each column when in column mode*/
  int actualWidth[100];  /* Actual width of each column */
  char nullvalue[20];    /* The text to print when a NULL comes back from
                         ** the database */
  struct previous_mode_data explainPrev;
                         /* Holds the mode information just before
                         ** .explain ON */
  char outfile[FILENAME_MAX]; /* Filename for *out */
  const char *zDbFilename;    /* name of the database file */
  const char *zVfs;           /* Name of VFS to use */
  sqlite3_stmt *pStmt;   /* Current statement if any. */
  FILE *pLog;            /* Write log output here */
};


int do_meta_command(char *, struct callback_data *);

#define sqlite3_exec_exit_on_failure(__db, __str) \
	do { \
  	char *err=NULL; \
	  sqlite3_exec(__db, __str, NULL, 0, &err); \
  	if(err!=NULL) { \
    	proxy_error("SQLITE error: %s --- %s\n", err, __str); \
    	proxy_debug(PROXY_DEBUG_SQLITE, 1, "SQLITE: Error on %s : %s\n",__str, err); \
    	assert(err==NULL); \
  	} \
	} while(0)

