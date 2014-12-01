#include "proxysql.h"


global_variables glovars;

static global_variable_entry_t glo_entries[]= {
	//{"global", "core_dump_file_size", 0, G_OPTION_ARG_INT, &glovars.core_dump_file_size, "core dump file size", 0, INT_MAX, 0, 0, 0, NULL, NULL, post_variable_core_dump_file_size},
	{"global", "stack_size", 0, G_OPTION_ARG_INT, &glovars.stack_size, "stack size", 64*1024, 32*1024*1024 , 1024, 0, 512*1024, NULL, NULL, NULL},
//	{"global", "net_buffer_size", 0, G_OPTION_ARG_INT, &glovars.net_buffer_size, "net buffer size", 1024, 16*1024*1024 , 1024, 0, 8*1024, NULL, NULL, NULL},
	{"global", "backlog", 0, G_OPTION_ARG_INT, &glovars.backlog, "backlog for listen()", 50, 10000 , 0, 0, 2000, NULL, NULL, NULL},
#ifdef DEBUG
	{"global", "debug", 1, G_OPTION_ARG_INT, &gdbg, "debugging messages", 0, 1, 0, 0, 1, NULL, NULL, NULL},
#endif /* DEBUG */
	{"global", "merge_configfile_db", 0, G_OPTION_ARG_INT, &glovars.merge_configfile_db, "merge users, hosts and debugs from config file to DB, without replacing DB content", 0, 1, 0, 0, 1, NULL, NULL, NULL},
	{"global", "datadir", 0, G_OPTION_ARG_STRING, &glovars.proxy_datadir, "Path to datadir", 0, 0, 0, 0, 0, "/var/run/proxysql", NULL, NULL},
	{"global", "pid_file", 0, G_OPTION_ARG_STRING, &glovars.proxy_pidfile, "Path to pidfile", 0, 0, 0, 0, 0, "proxysql.pid", NULL, NULL},
	{"global", "error_log", 0, G_OPTION_ARG_STRING, &glovars.proxy_errorlog, "Path to error log", 0, 0, 0, 0, 0, "proxysql.log", NULL, NULL},
	{"global", "debug_log", 0, G_OPTION_ARG_STRING, &glovars.proxy_debuglog, "Path to debug log", 0, 0, 0, 0, 0, "debug.log", NULL, NULL},
	{"global", "restart_on_error", 0, G_OPTION_ARG_INT, &glovars.proxy_restart_on_error, "Restart proxysql in case of crash or error", 0, 1 , 0, 0, 1, NULL, NULL, NULL},
	{"global", "restart_delay", 0, G_OPTION_ARG_INT, &glovars.proxy_restart_delay, "delay between restart", 0, 600 , 0, 0, 5, NULL, NULL, NULL},

	{"admin", "proxy_admin_pathdb", 0, G_OPTION_ARG_STRING, &glovars.proxy_admin_pathdb, "Path to internal DB for ProxySQL", 0, 0, 0, 0, 0, "proxysql.db", NULL, NULL},
	{"admin", "proxy_admin_bind", 0, G_OPTION_ARG_STRING, &glovars.proxy_admin_bind, "admin bind IP address", 0, 0, 0, 0, 0, "0.0.0.0", NULL, NULL},
	{"admin", "proxy_admin_port", 0, G_OPTION_ARG_INT, &glovars.proxy_admin_port, "administrative port", 0, 65535, 0, 0, 6032, NULL, NULL, NULL},
	{"admin", "proxy_admin_user", 0, G_OPTION_ARG_STRING, &glovars.proxy_admin_user, "proxy admin user", 0, 0, 0, 0, 0, "admin", NULL, NULL},
	{"admin", "proxy_admin_password", 0, G_OPTION_ARG_STRING, &glovars.proxy_admin_password, "proxy admin password", 0, 0, 0, 0, 0, "admin", NULL, NULL},
	{"admin", "proxy_admin_refresh_status_interval", 0, G_OPTION_ARG_INT, &glovars.proxy_admin_refresh_status_interval, "interval to update status variables", 0, 3600, 0, 0, 600, NULL, NULL, NULL},

	{"admin", "proxy_monitor_bind", 0, G_OPTION_ARG_STRING, &glovars.proxy_monitor_bind, "monitor bind IP address", 0, 0, 0, 0, 0, "0.0.0.0", NULL, NULL},
	{"admin", "proxy_monitor_port", 0, G_OPTION_ARG_INT, &glovars.proxy_monitor_port, "monitoring port", 0, 65535, 0, 0, 6031, NULL, NULL, NULL},
	{"admin", "proxy_monitor_user", 0, G_OPTION_ARG_STRING, &glovars.proxy_monitor_user, "proxy monitoring user", 0, 0, 0, 0, 0, "monitor", NULL, NULL},
	{"admin", "proxy_monitor_password", 0, G_OPTION_ARG_STRING, &glovars.proxy_monitor_password, "proxy monitoring password", 0, 0, 0, 0, 0, "monitor", NULL, NULL},
	{"admin", "proxy_monitor_refresh_status_interval", 0, G_OPTION_ARG_INT, &glovars.proxy_monitor_refresh_status_interval, "interval to update status variables", 0, 3600, 0, 0, 10, NULL, NULL, NULL},
	{"admin", "sync_to_disk_on_flush_command", 0, G_OPTION_ARG_INT, &glovars.admin_sync_disk_on_flush, "sync configuration to disk after every FLUSH command", 0, 1 , 0, 0, 1, NULL, NULL, NULL},
	{"admin", "sync_to_disk_on_shutdown", 0, G_OPTION_ARG_INT, &glovars.admin_sync_disk_on_shutdown, "sync configuration to disk during graceful shutdown", 0, 1 , 0, 0, 1, NULL, NULL, NULL},

	{"admin", "persistent_statistics_pathdb", 0, G_OPTION_ARG_STRING, &glovars.persistent_statistics_pathdb, "Path to internal DB used for persistent statistics", 0, 0, 0, 0, 0, "querystats.db", NULL, NULL},
	{"admin", "debug_pathdb", 0, G_OPTION_ARG_STRING, &glovars.debug_pathdb, "Path to internal DB used for debugging logging", 0, 0, 0, 0, 0, "debug.db", NULL, NULL},

	{"http", "http_start", 0, G_OPTION_ARG_INT, &glovars.http_start, "start HTTP server", 0, 1 , 0, 0, 0, NULL, NULL, NULL},

	{"mysql", "proxy_mysql_bind", 0, G_OPTION_ARG_STRING, &glovars.proxy_mysql_bind, "mysql bind IP address", 0, 0, 0, 0, 0, "0.0.0.0", NULL, NULL},
	{"mysql", "proxy_mysql_port", 0, G_OPTION_ARG_INT, &glovars.proxy_mysql_port, "mysql port", 0, 65535, 0, 0, 6033, NULL, NULL, NULL},
	{"mysql", "mysql_server_version", 0, G_OPTION_ARG_STRING, &glovars.mysql_server_version, "mysql server version", 0, 0, 0, 0, 0, "5.1.30", NULL, NULL},
	{"mysql", "mysql_socket", 0, G_OPTION_ARG_STRING, &glovars.mysql_socket, "mysql socket", 0, 0, 0, 0, 0, "/tmp/proxysql.sock", NULL, NULL},
	{"mysql", "mysql_default_schema", 0, G_OPTION_ARG_STRING, &glovars.mysql_default_schema, "mysql default schema", 0, 0, 0, 0, 0, "information_schema", NULL, NULL},
//	{"mysql", "mysql_connection_pool_enabled", 0, G_OPTION_ARG_INT, &gloconnpool.enabled, "enable/disable connection pool", 0, 1, 0, 0, 1, NULL, NULL, mysql_connpool_init},
	{"mysql", "mysql_parse_trx_cmds", 0, G_OPTION_ARG_INT, &glovars.mysql_parse_trx_cmds, "parse and filter unnecessary transaction commands", 0, 1, 0, 0, 0, NULL, NULL, NULL},
	{"mysql", "mysql_share_connections", 0, G_OPTION_ARG_INT, &glovars.mysql_share_connections, "share mysql connections among clients", 0, 1, 0, 0, 0, NULL, NULL, NULL},
	{"mysql", "mysql_query_cache_enabled", 0, G_OPTION_ARG_INT, &glovars.mysql_query_cache_enabled, "enable/disable query cache", 0, 1, 0, 0, 1, NULL, NULL, NULL},
	{"mysql", "mysql_query_cache_partitions", 0, G_OPTION_ARG_INT, &glovars.mysql_query_cache_partitions, "number of mysql query cache", 1, 128, 0, 0, 16, NULL, NULL, NULL},
	{"mysql", "mysql_query_cache_size", 1, G_OPTION_ARG_INT64, &glovars.mysql_query_cache_size, "mysql query cache size", 1024*1024, LLONG_MAX, 0, 0, 1024*1024, NULL, NULL, NULL},
	{"mysql", "mysql_query_cache_default_timeout", 0, G_OPTION_ARG_INT, &glovars.mysql_query_cache_default_timeout, "default timeout for query cache", 0, 3600*24*365*10, 0, 0, 1, NULL, NULL, NULL},
	{"mysql", "mysql_query_cache_precheck", 1, G_OPTION_ARG_INT, &glovars.mysql_query_cache_precheck, "enable/disable query cache precheck", 0, 1, 0, 0, 1, NULL, NULL, NULL},
	{"mysql", "mysql_query_statistics_enabled", 1, G_OPTION_ARG_INT, &glovars.mysql_query_statistics, "enable/disable the tracker for query statistics", 0, 1, 0, 0, 0, NULL, NULL, NULL},
	{"mysql", "mysql_query_statistics_interval", 1, G_OPTION_ARG_INT, &glovars.mysql_query_statistics_interval, "interval to update query_statistics", 5, 600, 0, 0, 10, NULL, NULL, NULL},
	{"mysql", "mysql_auto_reconnect_enabled", 0, G_OPTION_ARG_INT, &glovars.mysql_auto_reconnect_enabled, "enable/disable auto-reconnect", 0, 1, 0, 0, 0, NULL, NULL, NULL},
	{"mysql", "mysql_usage_user", 0, G_OPTION_ARG_STRING, &glovars.mysql_usage_user, "mysql usage user", 0, 0, 0, 0, 0, "proxy", NULL, NULL},
	{"mysql", "mysql_usage_password", 0, G_OPTION_ARG_STRING, &glovars.mysql_usage_password, "mysql usage password", 0, 0, 0, 0, 0, "proxy", NULL, NULL},
	{"mysql", "mysql_threads", 0, G_OPTION_ARG_INT, &glovars.mysql_threads, "number of threads to handle mysql connections", 1, 128, 0, 0, 2, NULL, NULL, NULL},
	{"mysql", "mysql_threads", 0, G_OPTION_ARG_INT, &glovars.mysql_threads, "number of threads to handle mysql connections", 1, 128, 0, 0, 2, NULL, pre_variable_mysql_threads, NULL},
	{"mysql", "mysql_max_query_size", 1, G_OPTION_ARG_INT, &glovars.mysql_max_query_size, "mysql max size of a COM_QUERY command", 0, 16777210, 0, 0, 1024*1024, NULL, NULL, NULL},
	{"mysql", "mysql_max_resultset_size", 0, G_OPTION_ARG_INT64, &glovars.mysql_max_resultset_size, "mysql max resultset size", 0, INT_MAX, 0, 0, 1024*1024, NULL, NULL, NULL},
	{"mysql", "mysql_poll_timeout", 1, G_OPTION_ARG_INT, &glovars.mysql_poll_timeout, "poll() timeout (in millisecond)", 100, INT_MAX, 0, 0, 10000, NULL, NULL, NULL},
	{"mysql", "mysql_poll_timeout_maintenance", 1, G_OPTION_ARG_INT, &glovars.mysql_poll_timeout_maintenance, "poll() timeout (in millisecond) during maintenance", 100, 1000, 0, 0, 100, NULL, NULL, NULL},
	{"mysql", "mysql_maintenance_timeout", 1, G_OPTION_ARG_INT, &glovars.mysql_maintenance_timeout, "max time to remove mysql servers (in millisecond)", 1000, 60000, 0, 0, 10000, NULL, NULL, NULL},
	{"mysql", "mysql_wait_timeout", 1, G_OPTION_ARG_INT64, &glovars.mysql_wait_timeout, "timeout to drop unused connection", 1, 3600*24*7, 0, 1000000, 3600*8, NULL, NULL, NULL},
//	{"mysql", "mysql_hostgroups", 0, G_OPTION_ARG_INT, &glovars.mysql_hostgroups, "total number of hostgroups", 2, 64, 0, 0, 8, NULL, NULL, init_glomysrvs},
	{"mysql", "mysql_hostgroups", 0, G_OPTION_ARG_INT, &glovars.mysql_hostgroups, "total number of hostgroups", 2, 64, 0, 0, 8, NULL, NULL, NULL},
//	{"fundadb", "fundadb_hash_purge_time", 1, G_OPTION_ARG_INT64, &fdb_system_var.hash_purge_time, "fundadb hash purge time (in millisecond): total time to purge a hash", 100, 600000, 0, 1000, 10000, NULL, NULL, NULL},
//	{"fundadb", "fundadb_hash_purge_loop", 1, G_OPTION_ARG_INT64, &fdb_system_var.hash_purge_loop, "fundadb hash purge loop (in millisecond): time to purge a chunk", 100, 600000, 0, 100, 100, NULL, NULL, NULL},
//	{"fundadb", "fundadb_hash_expire_default", 0, G_OPTION_ARG_INT, &fdb_system_var.hash_expire_default, "fundadb hash default expire (in second)", 1, 3600*24*365*10, 0, 0, 10, NULL, NULL, NULL},
//	{"fundadb", "fundadb_hash_purge_threshold_pct_min", 1, G_OPTION_ARG_INT, &fdb_system_var.purge_threshold_pct_min, "PCT of memory usage to trigger normal purge", 0, 90, 0, 0, 50, NULL, NULL, NULL},
//	{"fundadb", "fundadb_hash_purge_threshold_pct_max", 1, G_OPTION_ARG_INT, &fdb_system_var.purge_threshold_pct_max, "PCT of memory usage to trigger aggressive purge", 50, 100, 0, 0, 90, NULL, NULL, NULL},
};




/*
 * Process each group and key defined in glo_entries[]
 * input variable "dyn" defines if this function is called at startup (dyn==0) or during runtime (dyn==1)
 * 
 */
void process_global_variables_from_file(GKeyFile *gkf, int dyn) {
	unsigned int i;
	GError *error;
	for (i=0;i<sizeof(glo_entries)/sizeof(global_variable_entry_t);i++) {
		global_variable_entry_t *gve=glo_entries+i;
		if (dyn > gve->dynamic) {
			continue;
		}
		proxy_debug(PROXY_DEBUG_GENERIC, 4, "Parsing variable %s in [%s] : %s\n", gve->key_name, gve->group_name, gve->description);

		if (gve->func_pre) {
		// initialize the function via a call to func_pre
			proxy_debug(PROXY_DEBUG_GENERIC, 5, "Variable %s is initialized via function\n", gve->key_name);
			gve->func_pre(gve);
		}
		if (g_key_file_has_key(gkf, gve->group_name, gve->key_name, NULL)) {
			if (gve->arg == G_OPTION_ARG_STRING) {
				*(char **)gve->arg_data=g_key_file_get_string(gkf, gve->group_name, gve->key_name,  &error);
			}
			if (gve->arg == G_OPTION_ARG_INT || gve->arg == G_OPTION_ARG_INT64) {
				*(int *)gve->arg_data=gve->int_default;
				gint r=g_key_file_get_integer(gkf, gve->group_name, gve->key_name, &error);
        		if (r < gve->value_min ) { r=gve->value_min; }
        		if (r > gve->value_max ) { r=gve->value_max; }
				if ( gve->value_round ) { r=r/gve->value_round; r=r*gve->value_round; }
				if (gve->arg == G_OPTION_ARG_INT) {
					*(int *)gve->arg_data=r*(gve->value_multiplier > 0 ? gve->value_multiplier :  1 );
				} else {
					long long nr=(long long) r*(gve->value_multiplier > 0 ? gve->value_multiplier :  1 );
					memcpy(gve->arg_data,&nr,sizeof(long long));
				}
            }
		} else {
			if (gve->func_pre == NULL) {
					// set defaults
				if (gve->arg == G_OPTION_ARG_STRING) {
					*(char **)gve->arg_data=strdup(gve->char_default);
				}
				if (gve->arg == G_OPTION_ARG_INT) {
					*(int *)gve->arg_data=gve->int_default*(gve->value_multiplier > 0 ? gve->value_multiplier :  1 );	
				}
				if (gve->arg == G_OPTION_ARG_INT64) {
					// *(long long *)gve->arg_data= (long long) gve->int_default*(gve->value_multiplier > 0 ? gve->value_multiplier :  1 );	
					long long r=(long long) gve->int_default*(gve->value_multiplier > 0 ? gve->value_multiplier :  1 );	
					memcpy(gve->arg_data,&r,sizeof(long long));
				}
			}
		}

		// after setting the variable, a post function is executed
		if (gve->func_post) {
			proxy_debug(PROXY_DEBUG_GENERIC, 5, "Variable %s has post function\n", gve->key_name);
			gve->func_post(gve);
		}
	}
}

/*
void init_signal_handlers() {
	signal(SIGSEGV, crash_handler);
	signal(SIGABRT, crash_handler);
	signal(SIGTERM, term_handler);
//	signal(SIGHUP, sighup_handler);
}
*/

int config_file_is_readable(char *config_file) {
	// check if file exists and is readable
	if (!g_file_test(config_file,G_FILE_TEST_EXISTS|G_FILE_TEST_IS_REGULAR)) {
		g_print("Config file %s does not exist\n", config_file);
		return 0;
	}
	if (access(config_file, R_OK)) {
		g_print("Config file %s is not readable\n", config_file);
		return 0;
	}
	return 1;
}
	
void main_opts(gint *argc, gchar ***argv) {


	// Prepare the processing of config file
	GKeyFile *keyfile;
	int rc;
	GError *error = NULL;
	GOptionContext *context;

	// TODO NEW: init_signal_handlers();

	context = g_option_context_new ("- High Performance Advanced Proxy for MySQL");
	g_option_context_add_main_entries (context, cmd_option_entries, NULL);
//  g_option_context_add_group (context, gtk_get_option_group (TRUE));
	//if (!g_option_context_parse (context, &argc, &argv, &error))
	if (!g_option_context_parse (context, argc, argv, &error))
	{
		g_print ("option parsing failed: %s\n", error->message);
		exit (1);
	}

	// TODO NEW: init_debug_struct();

	proxy_debug(PROXY_DEBUG_GENERIC, 4, "processing opts\n");

	//gchar *config_file=*config_file_ptr;
	gchar *config_file=cmd_proxysql_config_file;

	if (config_file==NULL) {
		config_file="proxysql.cnf";
		if (!g_file_test(config_file,G_FILE_TEST_EXISTS|G_FILE_TEST_IS_REGULAR)) {
			config_file="/etc/proxysql.cnf";
		}
	}

	rc=config_file_is_readable(config_file);
	if (rc==0) {
		exit(EXIT_FAILURE);	
	}

	keyfile = g_key_file_new();
	if (!g_key_file_load_from_file(keyfile, config_file, G_KEY_FILE_NONE, &error)) {
		g_print ("Error loading config file %s: %s\n", config_file, error->message);
		exit(EXIT_FAILURE);
	}

	// initialize variables and process config file
	//init_global_variables(keyfile, 0);

	g_key_file_free(keyfile);
	glovars.proxy_configfile=config_file;

	g_option_context_free(context);
}

/*
int init_global_variables(GKeyFile *gkf, int runtime) {
	//int i;
	GError *error=NULL;

	// open the file and verify it has [global] section
	proxy_debug(PROXY_DEBUG_GENERIC, 1, "Checking [global]\n");
	if (g_key_file_has_group(gkf,"global")==FALSE) {
		g_print("[global] section not found\n");
		if (runtime==0) {
			exit(EXIT_FAILURE);
		} else {
			return -1;
		}
	}

	// open the file and verify it has [mysql users] section
	proxy_debug(PROXY_DEBUG_GENERIC, 1, "Checking [mysql users]\n");
	if (g_key_file_has_group(gkf,"mysql users")==FALSE) {
		g_print("[mysql users] section not found\n");
		if (runtime==0) {
			exit(EXIT_FAILURE);
		} else {
			return -1;
		}
	}

	// processing [debug] section
	proxy_debug(PROXY_DEBUG_GENERIC, 1, "Processing [debug]\n");
	if (g_key_file_has_group(gkf,"debug")==FALSE) {
		proxy_debug(PROXY_DEBUG_GENERIC, 1, "[debug] missing\n");	
		memset(gdbg_lvl,0,sizeof(int)*PROXY_DEBUG_UNKNOWN);
	} else {
		int i;
		for (i=0; i<PROXY_DEBUG_UNKNOWN; i++) {
			gdbg_lvl[i].verbosity=0;
			if (g_key_file_has_key(gkf, "debug", gdbg_lvl[i].name, NULL)) {
				gint r=g_key_file_get_integer(gkf, "debug", gdbg_lvl[i].name, &error);
				if (r >= 0 ) { gdbg_lvl[i].verbosity=r; }
			}	
		}
	}

	
	if (runtime==0) {
		//pthread_rwlock_init(&glovars.rwlock_global, NULL);
		pthread_rwlock_init(&glovars.rwlock_usernames, NULL);
		glovars.protocol_version=10;
	//glovars.server_version="5.0.15";
		glovars.server_capabilities= CLIENT_FOUND_ROWS | CLIENT_PROTOCOL_41 | CLIENT_IGNORE_SIGPIPE | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB;
//	glovars.server_capabilities=0xffff;
		glovars.server_language=33;
		glovars.server_status=2;
		glovars.thread_id=1;
		glovars.shutdown=0;
		fdb_system_var.hash_expire_max=3600*24*365*10;
	}
	
	
	// init gloQR
	if (runtime==0) {
		init_gloQR();
	}
	
	//pthread_rwlock_wrlock(&glovars.rwlock_global);



	// create the connection pool
	//mysql_connpool_init();


	


	//pthread_rwlock_unlock(&glovars.rwlock_global);
	process_global_variables_from_file(gkf, 0);
	
	if (runtime==0) {
		load_mysql_servers_list_from_file(gkf);
		load_mysql_users_from_file(gkf);
	}

	if (fdb_system_var.hash_purge_loop > fdb_system_var.hash_purge_time) {
		fdb_system_var.hash_purge_loop=fdb_system_var.hash_purge_time;
	}

	return 0;
}

mysql_server * new_server_master() {
	pthread_rwlock_wrlock(&glomysrvs.rwlock);
	if ( glomysrvs.count_masters==0 ) return NULL;
	int i=rand()%glomysrvs.count_masters;
	mysql_server *ms=l_ptr_array_index(glomysrvs.servers_masters,i);
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 4, "Using master %s port %d , index %d from a pool of %d servers\n", ms->address, ms->port, i, glomysrvs.count_masters);
	pthread_rwlock_unlock(&glomysrvs.rwlock);
	return ms;
}

mysql_server * new_server_slave() {
	pthread_rwlock_wrlock(&glomysrvs.rwlock);
	if ( glomysrvs.count_slaves==0 ) return NULL;
	int i=rand()%glomysrvs.count_slaves;
	mysql_server *ms=l_ptr_array_index(glomysrvs.servers_slaves,i);
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 4, "Using slave %s port %d , index %d from a pool of %d servers\n", ms->address, ms->port, i, glomysrvs.count_slaves);
	pthread_rwlock_unlock(&glomysrvs.rwlock);
	return ms;
}


void init_glomysrvs(global_variable_entry_t *gve) {
	pthread_rwlock_init(&glomysrvs.rwlock, NULL);
	glomysrvs.mysql_connections_max=10000; // hardcoded for now , theorically no limit : NOT USED YET
	glomysrvs.mysql_connections_cur=0; // hardcoded for now
	glomysrvs.mysql_connections=g_ptr_array_sized_new(glomysrvs.mysql_connections_max/10+4);
	glomysrvs.servers=g_ptr_array_new();
	glomysrvs.servers_masters=g_ptr_array_new();
	glomysrvs.servers_slaves=g_ptr_array_new();	
	glomysrvs.servers_count=0;
	glomysrvs.count_masters=0;
	glomysrvs.count_slaves=0;
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 5, "Creating %d hostgroups for MySQL\n", glovars.mysql_hostgroups);
	glomysrvs.mysql_hostgroups=g_ptr_array_sized_new(glovars.mysql_hostgroups);
	int i;
	for(i=0;i<glovars.mysql_hostgroups;i++) {
		GPtrArray *sl=g_ptr_array_new();
		g_ptr_array_add(glomysrvs.mysql_hostgroups,sl);
	}
}

void load_mysql_users_from_file(GKeyFile *gkf) {
	GError *error;
	// load usernames and password
	pthread_rwlock_wrlock(&glovars.rwlock_usernames);
	glovars.mysql_users_name=g_ptr_array_new();
	glovars.mysql_users_pass=g_ptr_array_new();
	glovars.usernames = g_hash_table_new(g_str_hash, g_str_equal);
	//gchar **users_keys=NULL;
	gsize l=0;
	gchar **mysql_users_name=NULL;
	gchar **mysql_users_pass=NULL;
	mysql_users_name=g_key_file_get_keys(gkf, "mysql users", &l, &error);
	if (l==0) {
		g_print("No mysql users defined in [mysql users]\n"); exit(EXIT_FAILURE);
	} else {
		mysql_users_pass=g_strdupv(mysql_users_name);
		int i;
		for (i=0; i<l; i++) {
			g_free(mysql_users_pass[i]);
			mysql_users_pass[i]=g_key_file_get_string(gkf, "mysql users", mysql_users_name[i], &error);
			if (mysql_users_pass[i]==NULL) {
				g_print("Error in password for user %s\n", mysql_users_name[i]); exit(EXIT_FAILURE);
			}
			proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 4, "Adding user %s password _OMITTED_ (%d)\n", mysql_users_name[i], strlen(mysql_users_pass[i]));
			g_ptr_array_add(glovars.mysql_users_name,g_strdup(mysql_users_name[i]));
			g_ptr_array_add(glovars.mysql_users_pass,g_strdup(mysql_users_pass[i]));
			g_hash_table_insert(glovars.usernames, l_ptr_array_index(glovars.mysql_users_name,i), l_ptr_array_index(glovars.mysql_users_pass,i));

		}
	}
	g_strfreev(mysql_users_name);
	g_strfreev(mysql_users_pass);
	pthread_rwlock_unlock(&glovars.rwlock_usernames);
}

void load_mysql_servers_list_from_file(GKeyFile *gkf) {
	GError *error;
	// this needs to be deprecated 
	glomysrvs.mysql_use_masters_for_reads=1;
	if (g_key_file_has_key(gkf, "mysql", "mysql_use_masters_for_reads", NULL)) {
		gint r=g_key_file_get_integer(gkf, "mysql", "mysql_use_masters_for_reads", &error);
		if (r == 0 ) {
			glomysrvs.mysql_use_masters_for_reads=0;
		}
	}

	
	pthread_rwlock_wrlock(&glomysrvs.rwlock);
	// load all servers
	if (g_key_file_has_key(gkf, "mysql", "mysql_servers", NULL)) {
		gsize l=0;
		glomysrvs.mysql_servers_name=g_key_file_get_string_list(gkf, "mysql", "mysql_servers", &l, &error);
		int i;
		for (i=0; i<l; i++) {
			char *c;
			c=index(glomysrvs.mysql_servers_name[i],':');
			mysql_server *ms=g_slice_alloc0(sizeof(mysql_server));
			if (ms==NULL) { exit(EXIT_FAILURE); }
			if (c) {
				int sl=strlen(glomysrvs.mysql_servers_name[i]);
				char *s=g_malloc0(sl);
//				if ((s=malloc(sl))==NULL) { exit(EXIT_FAILURE); }
				char *p=g_malloc0(sl);
//				if ((p=malloc(sl))==NULL) { exit(EXIT_FAILURE); }
				*c=' ';
				sscanf(glomysrvs.mysql_servers_name[i],"%s %s",s,p);
				ms->address=g_strdup(s);
				ms->port=atoi(p);
				g_free(s);
				g_free(p);
			} else {
				ms->address=g_strdup(glomysrvs.mysql_servers_name[i]);
				ms->port=3306;
			}
			//char *buff=g_malloc0(strlen(ms->address)+10);
			//sprintf(buff,"%s_%d",ms->address,ms->port);
			//ms->name=g_strdup(buff);
			//g_free(buff);
			proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 3, "Configuring server %s:%d from config file\n", ms->address, ms->port);
			mysql_server *mst=find_server_ptr(ms->address,ms->port);
			if (mst==NULL) {
				int ro=mysql_check_alive_and_read_only(ms->address,  ms->port);
				if ( ro>=0 ) ms->read_only=ro;
				if ( ro>=0 ) {
					ms->status=MYSQL_SERVER_STATUS_ONLINE;
				} else {
					ms->status=MYSQL_SERVER_STATUS_OFFLINE_HARD;
				}
				mysql_server_entry_add(ms);
			} else {
				g_free(ms->address);
				g_slice_free1(sizeof(mysql_server),ms);
			}
		}
	} else {
		// This needs to go away. Servers can be configured in sqlite, or added alter on
		g_print("mysql_servers not defined in [mysql]\n"); exit(EXIT_FAILURE);
	}
	pthread_rwlock_unlock(&glomysrvs.rwlock);
}
*/

// configure the number of threads as number of cores times 2
void pre_variable_mysql_threads(global_variable_entry_t *gve) {
	int rc=sysconf(_SC_NPROCESSORS_ONLN)*2;
	assert(rc>0);
	*(int *)gve->arg_data=rc;
}


/*
void post_variable_core_dump_file_size(global_variable_entry_t *gve) {
	int r=*(int *)gve->arg_data;
	struct rlimit rlim;
	rlim.rlim_cur=r;
	rlim.rlim_max=r;
	int rc;
	rc=setrlimit(RLIMIT_CORE,&rlim);
	assert(rc==0);
}
*/
