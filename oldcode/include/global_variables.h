
#define CONNECTION_READING_CLIENT	1
#define CONNECTION_WRITING_CLIENT	2
#define CONNECTION_READING_SERVER	4
#define CONNECTION_WRITING_SERVER	8


//#define SQLITE_ADMINDB  "proxysql.db"


#ifdef DEBUG
EXTERN glo_debug_t *glo_debug;
#endif

#ifdef PROXYMEMTRACK
EXTERN long long __mem_l_alloc_size;
EXTERN long long __mem_l_alloc_count;
EXTERN long long __mem_l_free_size;
EXTERN long long __mem_l_free_count;
EXTERN long long __mem_l_memalign_size;
EXTERN long long __mem_l_memalign_count;
#endif

//EXTERN static pthread_key_t tsd_key;
extern __thread l_sfp *__thr_sfp;
extern __thread myConnPools __thr_myconnpool;

EXTERN global_variables glovars;
EXTERN global_mysql_servers glomysrvs;

EXTERN fdb_hashes_group_t QC;
//EXTERN int QC_version;

// Added by chan -------
EXTERN qr_hash_t QR_HASH_T;
// Added by chan end.

EXTERN global_query_rules_t gloQR;
EXTERN global_default_hostgroups_t gloDefHG;

EXTERN long long glotimenew;
EXTERN long long glotimeold;
EXTERN myConnPools gloconnpool;
//EXTERN myBackendPools glomybepools;

//EXTERN mem_superblock_t conn_queue_pool;
EXTERN shared_trash_stack_t myds_pool;

EXTERN sqlite3 *sqlite3configdb;
EXTERN sqlite3 *sqlite3admindb;
EXTERN sqlite3 *sqlite3monitordb;
EXTERN sqlite3 *sqlite3statsdb;
EXTERN sqlite3 *sqlite3debugdb;

EXTERN time_t sqlite3admindb_lastupdate;
EXTERN time_t sqlite3monitordb_lastupdate;
EXTERN int sqlite3monitordb_rebuild;

EXTERN ProxyIPC proxyipc;

EXTERN int gdbg;	// global debug
EXTERN debug_level *gdbg_lvl;	// global debug levels

EXTERN pthread_t thread_qct;
EXTERN pthread_t thread_cppt;
EXTERN pthread_t thread_dbg_logger;
EXTERN pthread_t thread_qr;

//EXTERN admin_sqlite_table_def_t *table_defs;

int init_global_variables(GKeyFile *, int);
mysql_server * new_server_master();
mysql_server * new_server_slave();
void process_global_variables_from_file(GKeyFile *, int);
void main_opts(const GOptionEntry *, gint *, gchar ***, gchar **);

void init_glomysrvs(global_variable_entry_t *);
void load_mysql_users_from_file(GKeyFile *);
void load_mysql_servers_list_from_file(GKeyFile *);
void pre_variable_mysql_threads(global_variable_entry_t *);
void post_variable_core_dump_file_size(global_variable_entry_t *);
void post_variable_net_buffer_size(global_variable_entry_t *);
