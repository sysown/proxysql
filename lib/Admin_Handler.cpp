#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include <iostream>     // std::cout
#include <sstream>      // std::stringstream
#include <fstream>
#include <algorithm>    // std::sort
#include <memory>
#include <vector>       // std::vector
#include <unordered_set>
#include "prometheus/exposer.h"
#include "prometheus/counter.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "Base_Thread.h"

#include "MySQL_HostGroups_Manager.h"
#include "PgSQL_HostGroups_Manager.h"
#include "mysql.h"
#include "proxysql_admin.h"
#include "re2/re2.h"
#include "re2/regexp.h"
#include "proxysql.h"
#include "proxysql_config.h"
#include "proxysql_restapi.h"
#include "proxysql_utils.h"
#include "prometheus_helpers.h"
#include "cpp.h"

#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"
#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"
#include "ProxySQL_HTTP_Server.hpp" // HTTP server
#include "MySQL_Authentication.hpp"
#include "PgSQL_Authentication.h"
#include "MySQL_LDAP_Authentication.hpp"
#include "MySQL_PreparedStatement.h"
#include "ProxySQL_Cluster.hpp"
#include "ProxySQL_Statistics.hpp"
#include "MySQL_Logger.hpp"
#include "PgSQL_Logger.hpp"
#include "SQLite3_Server.h"
#include "Web_Interface.hpp"

#include <dirent.h>
#include <search.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <pthread.h>
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#include <fcntl.h>
#include <sys/utsname.h>

#include "platform.h"
#include "microhttpd.h"

#if (defined(__i386__) || defined(__x86_64__) || defined(__ARM_ARCH_3__) || defined(__mips__)) && defined(__linux)
// currently only support x86-32, x86-64, ARM, and MIPS on Linux
#include "coredumper/coredumper.h"
#endif

#include <uuid/uuid.h>

#include "PgSQL_Protocol.h"
#include "MySQL_Query_Cache.h"
#include "PgSQL_Query_Cache.h"
//#include "usual/time.h"

using std::string;
using std::unique_ptr;

#ifdef WITHGCOV
extern "C" void __gcov_dump();
extern "C" void __gcov_reset();
#endif


#ifdef DEBUG
//#define BENCHMARK_FASTROUTING_LOAD
#endif // DEBUG

//#define MYSQL_THREAD_IMPLEMENTATION

#define SELECT_VERSION_COMMENT "select @@version_comment limit 1"
#define SELECT_VERSION_COMMENT_LEN 32
#define SELECT_DB_USER "select DATABASE(), USER() limit 1"
#define SELECT_DB_USER_LEN 33
#define SELECT_CHARSET_VARIOUS "select @@character_set_client, @@character_set_connection, @@character_set_server, @@character_set_database limit 1"
#define SELECT_CHARSET_VARIOUS_LEN 115

#define READ_ONLY_OFF "\x01\x00\x00\x01\x02\x23\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x1b\x00\x00\x03\x03\x64\x65\x66\x00\x00\x00\x05\x56\x61\x6c\x75\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x02\x00\x0e\x00\x00\x05\x09\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x03\x4f\x46\x46\x05\x00\x00\x06\xfe\x00\x00\x02\x00"
#define READ_ONLY_ON "\x01\x00\x00\x01\x02\x23\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x1b\x00\x00\x03\x03\x64\x65\x66\x00\x00\x00\x05\x56\x61\x6c\x75\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x02\x00\x0d\x00\x00\x05\x09\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x02\x4f\x4e\x05\x00\x00\x06\xfe\x00\x00\x02\x00"

#define READ_ONLY_0 "\x01\x00\x00\x01\x01\x28\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x12\x40\x40\x67\x6c\x6f\x62\x61\x6c\x2e\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x00\x0c\x3f\x00\x01\x00\x00\x00\x08\x80\x00\x00\x00\x00\x05\x00\x00\x03\xfe\x00\x00\x02\x00\x02\x00\x00\x04\x01\x30\x05\x00\x00\x05\xfe\x00\x00\x02\x00"

#define READ_ONLY_1 "\x01\x00\x00\x01\x01\x28\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x12\x40\x40\x67\x6c\x6f\x62\x61\x6c\x2e\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x00\x0c\x3f\x00\x01\x00\x00\x00\x08\x80\x00\x00\x00\x00\x05\x00\x00\x03\xfe\x00\x00\x02\x00\x02\x00\x00\x04\x01\x31\x05\x00\x00\x05\xfe\x00\x00\x02\x00"

extern struct MHD_Daemon *Admin_HTTP_Server;

extern ProxySQL_Statistics *GloProxyStats;

template<enum SERVER_TYPE>
int ProxySQL_Test___PurgeDigestTable(bool async_purge, bool parallel, char **msg);

extern char *ssl_key_fp;
extern char *ssl_cert_fp;
extern char *ssl_ca_fp;

// ProxySQL_Admin shared variables
extern int admin___web_verbosity;
extern char * proxysql_version;

#include "proxysql_find_charset.h"

extern int admin_load_main_;
extern bool admin_nostart_;

extern int __admin_refresh_interval;

extern bool admin_proxysql_mysql_paused;
extern bool admin_proxysql_pgsql_paused;
extern int admin_old_wait_timeout;


extern MySQL_Query_Cache *GloMyQC;
extern PgSQL_Query_Cache* GloPgQC;
extern MySQL_Authentication *GloMyAuth;
extern PgSQL_Authentication *GloPgAuth;
extern MySQL_LDAP_Authentication *GloMyLdapAuth;
extern ProxySQL_Admin *GloAdmin;
extern MySQL_Query_Processor* GloMyQPro;
extern PgSQL_Query_Processor* GloPgQPro;
extern MySQL_Threads_Handler *GloMTH;
extern MySQL_Logger *GloMyLogger;
extern PgSQL_Logger* GloPgSQL_Logger;
extern MySQL_STMT_Manager_v14 *GloMyStmt;
extern MySQL_Monitor *GloMyMon;
extern PgSQL_Threads_Handler* GloPTH;

extern void (*flush_logs_function)();

extern Web_Interface *GloWebInterface;

extern ProxySQL_Cluster *GloProxyCluster;
#ifdef PROXYSQLCLICKHOUSE
extern ClickHouse_Authentication *GloClickHouseAuth;
extern ClickHouse_Server *GloClickHouseServer;
#endif /* PROXYSQLCLICKHOUSE */

extern SQLite3_Server *GloSQLite3Server;

extern char * binary_sha1;

extern int ProxySQL_create_or_load_TLS(bool bootstrap, std::string& msg);


#define PANIC(msg)  { perror(msg); exit(EXIT_FAILURE); }

extern pthread_mutex_t users_mutex;

extern ProxySQL_Admin *SPA;

const std::vector<std::string> LOAD_ADMIN_VARIABLES_TO_MEMORY = {
	"LOAD ADMIN VARIABLES TO MEMORY" ,
	"LOAD ADMIN VARIABLES TO MEM" ,
	"LOAD ADMIN VARIABLES FROM DISK" };

const std::vector<std::string> SAVE_ADMIN_VARIABLES_FROM_MEMORY = {
	"SAVE ADMIN VARIABLES FROM MEMORY" ,
	"SAVE ADMIN VARIABLES FROM MEM" ,
	"SAVE ADMIN VARIABLES TO DISK" };

const std::vector<std::string> LOAD_ADMIN_VARIABLES_FROM_MEMORY = {
	"LOAD ADMIN VARIABLES FROM MEMORY" ,
	"LOAD ADMIN VARIABLES FROM MEM" ,
	"LOAD ADMIN VARIABLES TO RUNTIME" ,
	"LOAD ADMIN VARIABLES TO RUN" };

const std::vector<std::string> SAVE_ADMIN_VARIABLES_TO_MEMORY = {
	"SAVE ADMIN VARIABLES TO MEMORY" ,
	"SAVE ADMIN VARIABLES TO MEM" ,
	"SAVE ADMIN VARIABLES FROM RUNTIME" ,
	"SAVE ADMIN VARIABLES FROM RUN" };

const std::vector<std::string> LOAD_MYSQL_SERVERS_FROM_MEMORY = {
	"LOAD MYSQL SERVERS FROM MEMORY" ,
	"LOAD MYSQL SERVERS FROM MEM" ,
	"LOAD MYSQL SERVERS TO RUNTIME" ,
	"LOAD MYSQL SERVERS TO RUN" };

const std::vector<std::string> SAVE_MYSQL_SERVERS_TO_MEMORY = {
	"SAVE MYSQL SERVERS TO MEMORY" ,
	"SAVE MYSQL SERVERS TO MEM" ,
	"SAVE MYSQL SERVERS FROM RUNTIME" ,
	"SAVE MYSQL SERVERS FROM RUN" };

const std::vector<std::string> LOAD_MYSQL_USERS_FROM_MEMORY = {
	"LOAD MYSQL USERS FROM MEMORY" ,
	"LOAD MYSQL USERS FROM MEM" ,
	"LOAD MYSQL USERS TO RUNTIME" ,
	"LOAD MYSQL USERS TO RUN" };

const std::vector<std::string> SAVE_MYSQL_USERS_TO_MEMORY = {
	"SAVE MYSQL USERS TO MEMORY" ,
	"SAVE MYSQL USERS TO MEM" ,
	"SAVE MYSQL USERS FROM RUNTIME" ,
	"SAVE MYSQL USERS FROM RUN" };

const std::vector<std::string> LOAD_MYSQL_VARIABLES_FROM_MEMORY = {
	"LOAD MYSQL VARIABLES FROM MEMORY" ,
	"LOAD MYSQL VARIABLES FROM MEM" ,
	"LOAD MYSQL VARIABLES TO RUNTIME" ,
	"LOAD MYSQL VARIABLES TO RUN" };

const std::vector<std::string> SAVE_MYSQL_VARIABLES_TO_MEMORY = {
	"SAVE MYSQL VARIABLES TO MEMORY" ,
	"SAVE MYSQL VARIABLES TO MEM" ,
	"SAVE MYSQL VARIABLES FROM RUNTIME" ,
	"SAVE MYSQL VARIABLES FROM RUN" };

// PgSQL
const std::vector<std::string> LOAD_PGSQL_SERVERS_FROM_MEMORY = {
	"LOAD PGSQL SERVERS FROM MEMORY" ,
	"LOAD PGSQL SERVERS FROM MEM" ,
	"LOAD PGSQL SERVERS TO RUNTIME" ,
	"LOAD PGSQL SERVERS TO RUN" };

const std::vector<std::string> SAVE_PGSQL_SERVERS_TO_MEMORY = {
	"SAVE PGSQL SERVERS TO MEMORY" ,
	"SAVE PGSQL SERVERS TO MEM" ,
	"SAVE PGSQL SERVERS FROM RUNTIME" ,
	"SAVE PGSQL SERVERS FROM RUN" };

const std::vector<std::string> LOAD_PGSQL_USERS_FROM_MEMORY = {
	"LOAD PGSQL USERS FROM MEMORY" ,
	"LOAD PGSQL USERS FROM MEM" ,
	"LOAD PGSQL USERS TO RUNTIME" ,
	"LOAD PGSQL USERS TO RUN" };

const std::vector<std::string> SAVE_PGSQL_USERS_TO_MEMORY = {
	"SAVE PGSQL USERS TO MEMORY" ,
	"SAVE PGSQL USERS TO MEM" ,
	"SAVE PGSQL USERS FROM RUNTIME" ,
	"SAVE PGSQL USERS FROM RUN" };

const std::vector<std::string> LOAD_PGSQL_VARIABLES_FROM_MEMORY = {
	"LOAD PGSQL VARIABLES FROM MEMORY" ,
	"LOAD PGSQL VARIABLES FROM MEM" ,
	"LOAD PGSQL VARIABLES TO RUNTIME" ,
	"LOAD PGSQL VARIABLES TO RUN" };

const std::vector<std::string> SAVE_PGSQL_VARIABLES_TO_MEMORY = {
	"SAVE PGSQL VARIABLES TO MEMORY" ,
	"SAVE PGSQL VARIABLES TO MEM" ,
	"SAVE PGSQL VARIABLES FROM RUNTIME" ,
	"SAVE PGSQL VARIABLES FROM RUN" };
//
const std::vector<std::string> LOAD_COREDUMP_FROM_MEMORY = {
	"LOAD COREDUMP FROM MEMORY" ,
	"LOAD COREDUMP FROM MEM" ,
	"LOAD COREDUMP TO RUNTIME" ,
	"LOAD COREDUMP TO RUN" };

extern unordered_map<string,std::tuple<string, vector<string>, vector<string>>> load_save_disk_commands;

bool is_admin_command_or_alias(const std::vector<std::string>& cmds, char *query_no_space, int query_no_space_length) {
	for (std::vector<std::string>::const_iterator it=cmds.begin(); it!=cmds.end(); ++it) {
		if ((unsigned int)query_no_space_length==it->length() && !strncasecmp(it->c_str(), query_no_space, query_no_space_length)) {
			proxy_info("Received %s command\n", query_no_space);
			return true;
		}
	}
	return false;
}


template <typename S>
bool FlushCommandWrapper(S* sess, const std::vector<std::string>& cmds, char *query_no_space, int query_no_space_length, const string& name, const string& direction) {
	if ( is_admin_command_or_alias(cmds, query_no_space, query_no_space_length) ) {
		ProxySQL_Admin *SPA = GloAdmin;
		SPA->flush_GENERIC__from_to(name, direction);
#ifdef DEBUG
		string msg = "Loaded " + name + " ";
		if (direction == "memory_to_disk")
			msg += "from MEMORY to DISK";
		else if (direction == "disk_to_memory")
			msg += "from DISK to MEMORY";
		else
			assert(0);
		msg += "\n";
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s", msg.c_str());
#endif // DEBUG
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		return true;
	}
	return false;
}

template <typename S>
bool FlushCommandWrapper(S* sess, const string& modname, char *query_no_space, int query_no_space_length) {
	assert(load_save_disk_commands.find(modname) != load_save_disk_commands.end());
	tuple<string, vector<string>, vector<string>>& t = load_save_disk_commands[modname];
	if (FlushCommandWrapper(sess, get<1>(t), query_no_space, query_no_space_length, modname, "disk_to_memory") == true)
		return true;
	if (FlushCommandWrapper(sess, get<2>(t), query_no_space, query_no_space_length, modname, "memory_to_disk") == true)
		return true;
	return false;
}

template <typename S>
bool admin_handler_command_kill_connection(char *query_no_space, unsigned int query_no_space_length, S* sess, ProxySQL_Admin *pa) {
	uint32_t id=atoi(query_no_space+16);
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "Trying to kill session %u\n", id);
	bool rc=GloMTH->kill_session(id);
	ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
	if (rc) {
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
	} else {
		char buf[1024];
		sprintf(buf,"Unknown thread id: %u", id);
		SPA->send_error_msg_to_client(sess, buf);
	}
	return false;
}

template <typename S>
bool admin_handler_command_proxysql(char *query_no_space, unsigned int query_no_space_length, S* sess, ProxySQL_Admin *pa) {

#if (defined(__i386__) || defined(__x86_64__) || defined(__ARM_ARCH_3__) || defined(__mips__)) && defined(__linux)
	// currently only support x86-32, x86-64, ARM, and MIPS on Linux
	if (!(strncasecmp("PROXYSQL COREDUMP", query_no_space, strlen("PROXYSQL COREDUMP")))) {
		string filename = "core";
		if (query_no_space_length > strlen("PROXYSQL COREDUMP")) {
			if (query_no_space[strlen("PROXYSQL COREDUMP")] == ' ') {
				filename = string(query_no_space+strlen("PROXYSQL COREDUMP "));
			} else {
				filename = "";
			}
		}
		if (filename == "") {
			proxy_error("Received incorrect PROXYSQL COREDUMP command: %s\n", query_no_space);
		} else {
			proxy_info("Received PROXYSQL COREDUMP command: %s\n", query_no_space);
			// generates a core dump
			WriteCoreDump(filename.c_str());
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			string msg = "Coredump: " + filename;
			SPA->send_ok_msg_to_client(sess, (char *)msg.c_str(), 0, query_no_space);
			return false;
		}
	}
	if (!(strncasecmp("PROXYSQL COMPRESSEDCOREDUMP", query_no_space, strlen("PROXYSQL COMPRESSEDCOREDUMP")))) {
		string filename = "core";
		if (query_no_space_length > strlen("PROXYSQL COMPRESSEDCOREDUMP")) {
			if (query_no_space[strlen("PROXYSQL COMPRESSEDCOREDUMP")] == ' ') {
				filename = string(query_no_space+strlen("PROXYSQL COMPRESSEDCOREDUMP "));
			} else {
				filename = "";
			}
		}
		if (filename == "") {
			proxy_error("Received incorrect PROXYSQL COMPRESSEDCOREDUMP command: %s\n", query_no_space);
		} else {
			proxy_info("Received PROXYSQL COMPRESSEDCOREDUMP command: %s\n", query_no_space);
			// generates a compressed core dump
			WriteCompressedCoreDump(filename.c_str(), SIZE_MAX, COREDUMPER_COMPRESSED, NULL);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			string msg = "Coredump: " + filename;
			SPA->send_ok_msg_to_client(sess, (char *)msg.c_str(), 0, query_no_space);
			return false;
		}
	}
#endif

	if (!(strncasecmp("PROXYSQL CLUSTER_NODE_UUID ", query_no_space, strlen("PROXYSQL CLUSTER_NODE_UUID ")))) {
		int l = strlen("PROXYSQL CLUSTER_NODE_UUID ");
		if (sess->client_myds->addr.port == 0) {
			proxy_warning("Received PROXYSQL CLUSTER_NODE_UUID not from TCP socket. Exiting client\n");
			SPA->send_error_msg_to_client(sess, (char *)"Received PROXYSQL CLUSTER_NODE_UUID not from TCP socket");
			sess->client_myds->shut_soft();
			return false;
		}
		if (query_no_space_length >= (unsigned int)l+36+2) {
			uuid_t uu;
			char *A_uuid = NULL;
			char *B_interface = NULL;
			c_split_2(query_no_space+l, " ", &A_uuid, &B_interface); // we split the value
			if (uuid_parse(A_uuid, uu)==0 && B_interface && strlen(B_interface)) {
				proxy_info("Received PROXYSQL CLUSTER_NODE_UUID from %s:%d : %s\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, query_no_space+l);
				if (sess->proxysql_node_address==NULL) {
					sess->proxysql_node_address = new ProxySQL_Node_Address(sess->client_myds->addr.addr, sess->client_myds->addr.port);
					sess->proxysql_node_address->uuid = strdup(A_uuid);
					if (sess->proxysql_node_address->admin_mysql_ifaces) {
						free(sess->proxysql_node_address->admin_mysql_ifaces);
					}
					sess->proxysql_node_address->admin_mysql_ifaces = strdup(B_interface);
					proxy_info("Created new link with Cluster node %s:%d : %s at interface %s\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, A_uuid, B_interface);
					SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
					free(A_uuid);
					free(B_interface);
					return false;
				} else {
					if (strcmp(A_uuid, sess->proxysql_node_address->uuid)) {
						proxy_error("Cluster node %s:%d is sending a new UUID : %s . Former UUID : %s . Exiting client\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, A_uuid, sess->proxysql_node_address->uuid);
						SPA->send_error_msg_to_client(sess, (char *)"Received PROXYSQL CLUSTER_NODE_UUID with a new UUID not matching the previous one");
						sess->client_myds->shut_soft();
						free(A_uuid);
						free(B_interface);
						return false;
					} else {
						proxy_info("Cluster node %s:%d is sending again its UUID : %s\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, A_uuid);
						SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
						free(A_uuid);
						free(B_interface);
						return false;
					}
				}
				free(A_uuid);
				free(B_interface);
				return false;
			} else {
				proxy_warning("Received PROXYSQL CLUSTER_NODE_UUID from %s:%d with invalid format: %s . Exiting client\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, query_no_space+l);
				SPA->send_error_msg_to_client(sess, (char *)"Received PROXYSQL CLUSTER_NODE_UUID with invalid format");
				sess->client_myds->shut_soft();
				return false;
			}
		} else {
			proxy_warning("Received PROXYSQL CLUSTER_NODE_UUID from %s:%d with invalid format: %s . Exiting client\n", sess->client_myds->addr.addr, sess->client_myds->addr.port, query_no_space+l);
			SPA->send_error_msg_to_client(sess, (char *)"Received PROXYSQL CLUSTER_NODE_UUID with invalid format");
			sess->client_myds->shut_soft();
			return false;
		}
	}
	if (query_no_space_length==strlen("PROXYSQL READONLY") && !strncasecmp("PROXYSQL READONLY",query_no_space, query_no_space_length)) {
		// this command enables admin_read_only , so the admin module is in read_only mode
		proxy_info("Received PROXYSQL READONLY command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		SPA->set_read_only(true);
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		return false;
	}
	if (query_no_space_length==strlen("PROXYSQL READWRITE") && !strncasecmp("PROXYSQL READWRITE",query_no_space, query_no_space_length)) {
		// this command disables admin_read_only , so the admin module won't be in read_only mode
		proxy_info("Received PROXYSQL WRITE command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		SPA->set_read_only(false);
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		return false;
	}
	if (query_no_space_length==strlen("PROXYSQL START") && !strncasecmp("PROXYSQL START",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL START command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		bool rc=false;
		if (admin_nostart_) {
			rc=__sync_bool_compare_and_swap(&GloVars.global.nostart,1,0);
		}
		if (rc) {
			// Set the status variable 'threads_initialized' to 0 because it's initialized back
			// in main 'init_phase3'. After GloMTH have been initialized again.
			__sync_bool_compare_and_swap(&GloMTH->status_variables.threads_initialized, 1, 0);
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Starting ProxySQL following PROXYSQL START command\n");
			while(__sync_fetch_and_add(&GloMTH->status_variables.threads_initialized, 0) == 1) {
				usleep(1000);
			}
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		} else {
			proxy_warning("ProxySQL was already started when received PROXYSQL START command\n");
			SPA->send_error_msg_to_client(sess, (char *)"ProxySQL already started");
		}
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL RESTART") && !strncasecmp("PROXYSQL RESTART",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL RESTART command\n");
		// This function was introduced into 'prometheus::Registry' for being
		// able to do a complete reset of all the 'prometheus counters'. It
		// shall only be used during ProxySQL shutdown phases.
		GloVars.prometheus_registry->ResetCounters();
		__sync_bool_compare_and_swap(&glovars.shutdown,0,1);
		glovars.reload=1;
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL STOP") && !strncasecmp("PROXYSQL STOP",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL STOP command\n");
		// to speed up this process we first change wait_timeout to 0
		// MySQL_thread will call poll() with a maximum timeout of 100ms
		admin_old_wait_timeout=GloMTH->get_variable_int((char *)"wait_timeout");
		GloMTH->set_variable((char *)"wait_timeout",(char *)"0");
		GloMTH->commit();
		GloMTH->signal_all_threads(0);
		GloMTH->stop_listeners();
		char buf[32];
		sprintf(buf,"%d",admin_old_wait_timeout);
		GloMTH->set_variable((char *)"wait_timeout",buf);
		GloMTH->commit();
		glovars.reload=2;
		// This function was introduced into 'prometheus::Registry' for being
		// able to do a complete reset of all the 'prometheus counters'. It
		// shall only be used during ProxySQL shutdown phases.
		GloVars.prometheus_registry->ResetCounters();
		__sync_bool_compare_and_swap(&glovars.shutdown,0,1);
		// After setting the shutdown flag, we should wake all threads and wait for
		// the shutdown phase to complete.
		GloMTH->signal_all_threads(0);
		while (__sync_fetch_and_add(&glovars.shutdown,0)==1) {
			usleep(1000);
		}
		// After shutdown phase is completed, we must to send a 'OK' to the
		// mysql client, otherwise, since this session might not be drop due
		// to the waiting condition, the client wont disconnect and will
		// keep forever waiting for acknowledgement.
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL PAUSE") && !strncasecmp("PROXYSQL PAUSE",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL PAUSE command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (admin_nostart_) {
			if (__sync_fetch_and_add((uint8_t *)(&GloVars.global.nostart),0)) {
				SPA->send_error_msg_to_client(sess, (char *)"ProxySQL MySQL module not running, impossible to pause");
				return false;
			}
		}
		if (admin_proxysql_mysql_paused==false) {
			// to speed up this process we first change poll_timeout to 10
			// MySQL_thread will call poll() with a maximum timeout of 10ms
			admin_old_wait_timeout=GloMTH->get_variable_int((char *)"poll_timeout");
			GloMTH->set_variable((char *)"poll_timeout",(char *)"10");
			GloMTH->commit();
			GloMTH->signal_all_threads(0);
			GloMTH->stop_listeners();
			admin_proxysql_mysql_paused=true;
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			// we now rollback poll_timeout
			char buf[32];
			sprintf(buf,"%d",admin_old_wait_timeout);
			GloMTH->set_variable((char *)"poll_timeout",buf);
			GloMTH->commit();
		} else {
			SPA->send_error_msg_to_client(sess, (char *)"ProxySQL MySQL module is already paused, impossible to pause");
		}

		if (admin_proxysql_pgsql_paused == false) {
			// to speed up this process we first change poll_timeout to 10
			// PgSQL_thread will call poll() with a maximum timeout of 10ms
			admin_old_wait_timeout = GloPTH->get_variable_int((char*)"poll_timeout");
			GloPTH->set_variable((char*)"poll_timeout", (char*)"10");
			GloPTH->commit();
			GloPTH->signal_all_threads(0);
			GloPTH->stop_listeners();
			admin_proxysql_pgsql_paused = true;
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			// we now rollback poll_timeout
			char buf[32];
			sprintf(buf, "%d", admin_old_wait_timeout);
			GloPTH->set_variable((char*)"poll_timeout", buf);
			GloPTH->commit();
		}
		else {
			SPA->send_error_msg_to_client(sess, (char*)"ProxySQL PgSQL module is already paused, impossible to pause");
		}
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL RESUME") && !strncasecmp("PROXYSQL RESUME",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL RESUME command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (admin_nostart_) {
			if (__sync_fetch_and_add((uint8_t *)(&GloVars.global.nostart),0)) {
				SPA->send_error_msg_to_client(sess, (char *)"ProxySQL MySQL module not running, impossible to resume");
				return false;
			}
		}
		if (admin_proxysql_mysql_paused==true) {
			// to speed up this process we first change poll_timeout to 10
			// MySQL_thread will call poll() with a maximum timeout of 10ms
			admin_old_wait_timeout=GloMTH->get_variable_int((char *)"poll_timeout");
			GloMTH->set_variable((char *)"poll_timeout",(char *)"10");
			GloMTH->commit();
			GloMTH->signal_all_threads(0);
			GloMTH->start_listeners();
			//char buf[32];
			//sprintf(buf,"%d",old_wait_timeout);
			//GloMTH->set_variable((char *)"poll_timeout",buf);
			//GloMTH->commit();
			admin_proxysql_mysql_paused=false;
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			// we now rollback poll_timeout
			char buf[32];
			sprintf(buf,"%d",admin_old_wait_timeout);
			GloMTH->set_variable((char *)"poll_timeout",buf);
			GloMTH->commit();
		} else {
			SPA->send_error_msg_to_client(sess, (char *)"ProxySQL MySQL module is not paused, impossible to resume");
		}

		if (admin_proxysql_pgsql_paused == true) {
			// to speed up this process we first change poll_timeout to 10
			// MySQL_thread will call poll() with a maximum timeout of 10ms
			admin_old_wait_timeout = GloPTH->get_variable_int((char*)"poll_timeout");
			GloPTH->set_variable((char*)"poll_timeout", (char*)"10");
			GloPTH->commit();
			GloPTH->signal_all_threads(0);
			GloPTH->start_listeners();
			//char buf[32];
			//sprintf(buf,"%d",old_wait_timeout);
			//GloPTH->set_variable((char *)"poll_timeout",buf);
			//GloPTH->commit();
			admin_proxysql_pgsql_paused = false;
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			// we now rollback poll_timeout
			char buf[32];
			sprintf(buf, "%d", admin_old_wait_timeout);
			GloPTH->set_variable((char*)"poll_timeout", buf);
			GloPTH->commit();
		}
		else {
			SPA->send_error_msg_to_client(sess, (char*)"ProxySQL MySQL module is not paused, impossible to resume");
		}
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL SHUTDOWN SLOW") && !strncasecmp("PROXYSQL SHUTDOWN SLOW",query_no_space, query_no_space_length)) {
		glovars.proxy_restart_on_error=false;
		glovars.reload=0;
		proxy_info("Received PROXYSQL SHUTDOWN SLOW command\n");
		__sync_bool_compare_and_swap(&glovars.shutdown,0,1);
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL FLUSH LOGS") && !strncasecmp("PROXYSQL FLUSH LOGS",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL FLUSH LOGS command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		SPA->flush_logs();
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		return false;
	}

	if (query_no_space_length==strlen("PROXYSQL FLUSH QUERY CACHE") && !strncasecmp("PROXYSQL FLUSH QUERY CACHE",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL FLUSH QUERY CACHE command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (GloMyQC) {
			GloMyQC->flush();
		}
		//if (GloPgQC) {
		//	GloPgQC->flush();
		//}
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		return false;
	}

	if (query_no_space_length == strlen("PROXYSQL FLUSH MYSQL QUERY CACHE") && !strncasecmp("PROXYSQL FLUSH MYSQL QUERY CACHE", query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL FLUSH MYSQL QUERY CACHE command\n");
		ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
		if (GloMyQC) {
			GloMyQC->flush();
		}
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		return false;
	}

	if (query_no_space_length == strlen("PROXYSQL FLUSH PGSQL QUERY CACHE") && !strncasecmp("PROXYSQL FLUSH PGSQL QUERY CACHE", query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL FLUSH PGSQL QUERY CACHE command\n");
		ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
		uint64_t count = 0;
		if (GloPgQC) {
			count = GloPgQC->flush();
		}
		SPA->send_ok_msg_to_client(sess, NULL, (int)count, "DELETE ");
		return false;
	}

	if (!strcasecmp("PROXYSQL FLUSH MYSQL CLIENT HOSTS", query_no_space)) {
		proxy_info("Received PROXYSQL FLUSH MYSQL CLIENT HOSTS command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (GloMTH) {
			GloMTH->flush_client_host_cache();
		}
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		return false;
	}

	if (
		(query_no_space_length==strlen("PROXYSQL FLUSH CONFIGDB") && !strncasecmp("PROXYSQL FLUSH CONFIGDB",query_no_space, query_no_space_length)) // see #923
	) {
		proxy_info("Received %s command\n", query_no_space);
		proxy_warning("A misconfigured configdb will cause undefined behaviors\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		SPA->flush_configdb();
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		return false;
	}

	if (strcasecmp("PROXYSQL RELOAD TLS",query_no_space) == 0) {
		proxy_info("Received %s command\n", query_no_space);
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		std::string s;
		int rc = ProxySQL_create_or_load_TLS(false, s);
		if (rc == 0) {
			SPA->send_ok_msg_to_client(sess, s.length() ? (char*)s.c_str() : NULL, 0, query_no_space);
		} else {
			SPA->send_error_msg_to_client(sess, s.length() ? (char *)s.c_str() : (char *)"RELOAD TLS failed");
		}
		return false;
	}

#ifndef NOJEM
	if (query_no_space_length==strlen("PROXYSQL MEMPROFILE START") && !strncasecmp("PROXYSQL MEMPROFILE START",query_no_space, query_no_space_length)) {
		bool en=true;
		mallctl("prof.active", NULL, NULL, &en, sizeof(bool));
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		return false;
	}
	if (query_no_space_length==strlen("PROXYSQL MEMPROFILE STOP") && !strncasecmp("PROXYSQL MEMPROFILE STOP",query_no_space, query_no_space_length)) {
		bool en=false;
		mallctl("prof.active", NULL, NULL, &en, sizeof(bool));
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		return false;
	}
#endif

#ifdef WITHGCOV
	if (query_no_space_length==strlen("PROXYSQL GCOV DUMP") && !strncasecmp("PROXYSQL GCOV DUMP",query_no_space, query_no_space_length)) {
		proxy_info("Received %s command\n", query_no_space);
		__gcov_dump();
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		return false;
	}
	if (query_no_space_length==strlen("PROXYSQL GCOV RESET") && !strncasecmp("PROXYSQL GCOV RESET",query_no_space, query_no_space_length)) {
		proxy_info("Received %s command\n", query_no_space);
		__gcov_reset();
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		return false;
	}
#endif

	if (query_no_space_length==strlen("PROXYSQL KILL") && !strncasecmp("PROXYSQL KILL",query_no_space, query_no_space_length)) {
		proxy_info("Received PROXYSQL KILL command\n");
		exit(EXIT_SUCCESS);
	}

	if (query_no_space_length==strlen("PROXYSQL SHUTDOWN") && !strncasecmp("PROXYSQL SHUTDOWN",query_no_space, query_no_space_length)) {
		// in 2.1 , PROXYSQL SHUTDOWN behaves like PROXYSQL KILL : quick exit
		// the former PROXYQL SHUTDOWN is now replaced with PROXYSQL SHUTDOWN SLOW
		proxy_info("Received PROXYSQL SHUTDOWN command\n");
		exit(EXIT_SUCCESS);
	}

	return true;
}

// Returns true if the given name is either a know mysql or admin global variable.
bool is_valid_global_variable(const char *var_name) {
	if (strlen(var_name) > 6 && !strncmp(var_name, "mysql-", 6) && GloMTH->has_variable(var_name + 6)) {
		return true;
	} else if (strlen(var_name) > 6 && !strncmp(var_name, "pgsql-", 6) && GloPTH->has_variable(var_name + 6)) {
		return true;
	} else if (strlen(var_name) > 6 && !strncmp(var_name, "admin-", 6) && SPA->has_variable(var_name + 6)) {
		return true;
	} else if (strlen(var_name) > 5 && !strncmp(var_name, "ldap-", 5) && GloMyLdapAuth && GloMyLdapAuth->has_variable(var_name + 5)) {
		return true;
	} else if (strlen(var_name) > 13 && !strncmp(var_name, "sqliteserver-", 13) && GloSQLite3Server && GloSQLite3Server->has_variable(var_name + 13)) {
		return true;
#ifdef PROXYSQLCLICKHOUSE
	} else if (strlen(var_name) > 11 && !strncmp(var_name, "clickhouse-", 11) && GloClickHouseServer && GloClickHouseServer->has_variable(var_name + 11)) {
		return true;
#endif /* PROXYSQLCLICKHOUSE */
	} else {
		return false;
	}
}


// This method translates a 'SET variable=value' command into an equivalent UPDATE. It doesn't yes support setting
// multiple variables at once.
//
// It modifies the original query.
template <typename S>
bool admin_handler_command_set(char *query_no_space, unsigned int query_no_space_length, S* sess, ProxySQL_Admin *pa, char **q, unsigned int *ql) {
	if (!strstr(query_no_space,(char *)"password")) { // issue #599
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received command %s\n", query_no_space);
		if (strncasecmp(query_no_space,(char *)"set autocommit",strlen((char *)"set autocommit"))) {
			if (strncasecmp(query_no_space,(char *)"SET @@session.autocommit",strlen((char *)"SET @@session.autocommit"))) {
				proxy_info("Received command %s\n", query_no_space);
			}
		}
	}
	// Get a pointer to the beginnig of var=value entry and split to get var name and value
	char *set_entry = query_no_space + strlen("SET ");
	char *untrimmed_var_name=NULL;
	char *var_value=NULL;
	c_split_2(set_entry, "=", &untrimmed_var_name, &var_value);

	// Trim spaces from var name to allow writing like 'var = value'
	char *var_name = trim_spaces_in_place(untrimmed_var_name);

	if (strstr(var_name,(char *)"password") || strcmp(var_name,(char *)"mysql-default_authentication_plugin")==0) {
		proxy_info("Received SET command for %s\n", var_name);
	}

	bool run_query = false;
	// Check if the command tries to set a non-existing variable.
	if (strcmp(var_name,"mysql-init_connect")==0) {
		char *err_msg_fmt = (char *) "ERROR: Global variable '%s' is not configurable using SET command. You must run UPDATE global_variables";
		size_t buff_len = strlen(err_msg_fmt) + strlen(var_name) + 1;
		char *buff = (char *) malloc(buff_len);
		snprintf(buff, buff_len, err_msg_fmt, var_name);
		SPA->send_error_msg_to_client(sess, buff);
		free(buff);
		run_query = false;
	} else {
		if (!is_valid_global_variable(var_name)) {
			char *err_msg_fmt = (char *) "ERROR: Unknown global variable: '%s'.";
			size_t buff_len = strlen(err_msg_fmt) + strlen(var_name) + 1;
			char *buff = (char *) malloc(buff_len);
			snprintf(buff, buff_len, err_msg_fmt, var_name);
			SPA->send_ok_msg_to_client(sess, buff, 0, query_no_space);
			free(buff);
			run_query = false;
		} else {
			const char *update_format = (char *)"UPDATE global_variables SET variable_value=%s WHERE variable_name='%s'";
			// Computed length is more than needed since it also counts the format modifiers (%s).
			size_t query_len = strlen(update_format) + strlen(var_name) + strlen(var_value) + 1;
			char *query = (char *)l_alloc(query_len);
			snprintf(query, query_len, update_format, var_value, var_name);

			run_query = true;
			l_free(*ql,*q);
			*q = query;
			*ql = strlen(*q) + 1;
		}
	}
	free(untrimmed_var_name);
	free(var_value);
	return run_query;
}

/* Note:
 * This function can modify the original query
 */
template <typename S>
bool admin_handler_command_load_or_save(char *query_no_space, unsigned int query_no_space_length, S* sess, ProxySQL_Admin *pa, char **q, unsigned int *ql) {
	proxy_debug(PROXY_DEBUG_ADMIN, 5, "Received command %s\n", query_no_space);

#ifdef DEBUG
	if ((query_no_space_length>11) && ( (!strncasecmp("SAVE DEBUG ", query_no_space, 11)) || (!strncasecmp("LOAD DEBUG ", query_no_space, 11))) ) {
		if (
			(query_no_space_length==strlen("LOAD DEBUG TO MEMORY") && !strncasecmp("LOAD DEBUG TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD DEBUG TO MEM") && !strncasecmp("LOAD DEBUG TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD DEBUG FROM DISK") && !strncasecmp("LOAD DEBUG FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			// we are now copying the data from memory to disk
			// tables involved are:
			// * debug_levels
			// * debug_filters
			// We only delete from filters and not from levels because the
			// levels are hardcoded and fixed in number, while filters can
			// be arbitrary
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->admindb->execute("DELETE FROM main.debug_filters");
			SPA->admindb->execute("INSERT OR REPLACE INTO main.debug_levels SELECT * FROM disk.debug_levels");
			SPA->admindb->execute("INSERT INTO main.debug_filters SELECT * FROM disk.debug_filters");
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded debug levels/filters to MEMORY\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE DEBUG FROM MEMORY") && !strncasecmp("SAVE DEBUG FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE DEBUG FROM MEM") && !strncasecmp("SAVE DEBUG FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE DEBUG TO DISK") && !strncasecmp("SAVE DEBUG TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			// we are now copying the data from disk to memory
			// tables involved are:
			// * debug_levels
			// * debug_filters
			// We only delete from filters and not from levels because the
			// levels are hardcoded and fixed in number, while filters can
			// be arbitrary
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->admindb->execute("DELETE FROM disk.debug_filters");
			SPA->admindb->execute("INSERT OR REPLACE INTO disk.debug_levels SELECT * FROM main.debug_levels");
			SPA->admindb->execute("INSERT INTO disk.debug_filters SELECT * FROM main.debug_filters");
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved debug levels/filters to DISK\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD DEBUG FROM MEMORY") && !strncasecmp("LOAD DEBUG FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD DEBUG FROM MEM") && !strncasecmp("LOAD DEBUG FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD DEBUG TO RUNTIME") && !strncasecmp("LOAD DEBUG TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD DEBUG TO RUN") && !strncasecmp("LOAD DEBUG TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			int rc=SPA->load_debug_to_runtime();
			if (rc) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded debug levels/filters to RUNTIME\n");
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 1, "Error while loading debug levels/filters to RUNTIME\n");
				SPA->send_error_msg_to_client(sess, (char *)"Error while loading debug levels/filters to RUNTIME");
			}
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE DEBUG TO MEMORY") && !strncasecmp("SAVE DEBUG TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE DEBUG TO MEM") && !strncasecmp("SAVE DEBUG TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE DEBUG FROM RUNTIME") && !strncasecmp("SAVE DEBUG FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE DEBUG FROM RUN") && !strncasecmp("SAVE DEBUG FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_debug_from_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved debug levels/filters from RUNTIME\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

	}
#endif /* DEBUG */

	if ((query_no_space_length>13) && ( (!strncasecmp("SAVE RESTAPI ", query_no_space, 13)) || (!strncasecmp("LOAD RESTAPI ", query_no_space, 13))) ) {

		if (FlushCommandWrapper(sess, "restapi", query_no_space, query_no_space_length) == true)
			return false;

		if (
			(query_no_space_length==strlen("LOAD RESTAPI FROM MEMORY") && !strncasecmp("LOAD RESTAPI FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD RESTAPI FROM MEM") && !strncasecmp("LOAD RESTAPI FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD RESTAPI TO RUNTIME") && !strncasecmp("LOAD RESTAPI TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD RESTAPI TO RUN") && !strncasecmp("LOAD RESTAPI TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->proxysql_restapi().load_restapi_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded restapito RUNTIME\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD RESTAPI FROM CONFIG") && !strncasecmp("LOAD RESTAPI FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					int rows=0;
					rows=SPA->proxysql_config().Read_Restapi_from_configfile();
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded restapi from CONFIG\n");
					SPA->send_ok_msg_to_client(sess, NULL, rows, query_no_space);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_error_msg_to_client(sess, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_error_msg_to_client(sess, (char *)"Config file unknown");
			}
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE RESTAPI TO MEMORY") && !strncasecmp("SAVE RESTAPI TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE RESTAPI TO MEM") && !strncasecmp("SAVE RESTAPI TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE RESTAPI FROM RUNTIME") && !strncasecmp("SAVE RESTAPI FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE RESTAPI FROM RUN") && !strncasecmp("SAVE RESTAPI FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_scheduler_runtime_to_database(false);
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved scheduler from RUNTIME\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}
	}

	if ((query_no_space_length>15) && ( (!strncasecmp("SAVE SCHEDULER ", query_no_space, 15)) || (!strncasecmp("LOAD SCHEDULER ", query_no_space, 15))) ) {

		if (FlushCommandWrapper(sess, "scheduler", query_no_space, query_no_space_length) == true)
			return false;

		if (
			(query_no_space_length==strlen("LOAD SCHEDULER FROM MEMORY") && !strncasecmp("LOAD SCHEDULER FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SCHEDULER FROM MEM") && !strncasecmp("LOAD SCHEDULER FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SCHEDULER TO RUNTIME") && !strncasecmp("LOAD SCHEDULER TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SCHEDULER TO RUN") && !strncasecmp("LOAD SCHEDULER TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->load_scheduler_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded scheduler to RUNTIME\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD SCHEDULER FROM CONFIG") && !strncasecmp("LOAD SCHEDULER FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					int rows=0;
					rows=SPA->proxysql_config().Read_Scheduler_from_configfile();
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded scheduler from CONFIG\n");
					SPA->send_ok_msg_to_client(sess, NULL, rows, query_no_space);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_error_msg_to_client(sess, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_error_msg_to_client(sess, (char *)"Config file unknown");
			}
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE SCHEDULER TO MEMORY") && !strncasecmp("SAVE SCHEDULER TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SCHEDULER TO MEM") && !strncasecmp("SAVE SCHEDULER TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SCHEDULER FROM RUNTIME") && !strncasecmp("SAVE SCHEDULER FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SCHEDULER FROM RUN") && !strncasecmp("SAVE SCHEDULER FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_scheduler_runtime_to_database(false);
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved scheduler from RUNTIME\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

	}
	if ((query_no_space_length>16) && (!strncasecmp("LOAD MYSQL USER ", query_no_space, 16)) ) {
		if (query_no_space_length>27) {
			if (!strncasecmp(" TO RUNTIME", query_no_space+query_no_space_length-11, 11)) {
				char *name=(char *)malloc(query_no_space_length-27+1);
				strncpy(name,query_no_space+16,query_no_space_length-27);
				name[query_no_space_length-27]=0;
				int i=0;
				int s=strlen(name);
				bool legitname=true;
				for (i=0; i<s; i++) {
					char c=name[i];
					bool v=false;
					if (
						(c >= 'a' && c <= 'z') ||
						(c >= 'A' && c <= 'Z') ||
						(c >= '0' && c <= '9') ||
						( (c == '-') || (c == '+') || (c == '_'))
					) {
						v=true;
					}
					if (v==false) {
						legitname=false;
					}
				}
				if (legitname) {
					proxy_info("Loading user %s\n", name);
					pthread_mutex_lock(&users_mutex);

					if (query_no_space[5] == 'P' || query_no_space[5] == 'p') {
						SPA->public_add_active_users<SERVER_TYPE_PGSQL>(USERNAME_BACKEND, name);
						SPA->public_add_active_users<SERVER_TYPE_PGSQL>(USERNAME_FRONTEND, name);
					} else {
						SPA->public_add_active_users<SERVER_TYPE_MYSQL>(USERNAME_BACKEND, name);
						SPA->public_add_active_users<SERVER_TYPE_MYSQL>(USERNAME_FRONTEND, name);
					}

					pthread_mutex_unlock(&users_mutex);
					SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
				} else {
					proxy_info("Tried to load invalid user %s\n", name);
					char *s=(char *)"Invalid name %s";
					char *m=(char *)malloc(strlen(s)+strlen(name)+1);
					sprintf(m,s,name);
					SPA->send_error_msg_to_client(sess, m);
					free(m);
				}
				free(name);
				return false;
			}
		}
	}
#ifdef PROXYSQLCLICKHOUSE
	if ( ( GloVars.global.clickhouse_server == true ) && (query_no_space_length>22) && ( (!strncasecmp("SAVE CLICKHOUSE USERS ", query_no_space, 22)) || (!strncasecmp("LOAD CLICKHOUSE USERS ", query_no_space, 22))) ) {
		if (
			(query_no_space_length==strlen("LOAD CLICKHOUSE USERS TO MEMORY") && !strncasecmp("LOAD CLICKHOUSE USERS TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE USERS TO MEM") && !strncasecmp("LOAD CLICKHOUSE USERS TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE USERS FROM DISK") && !strncasecmp("LOAD CLICKHOUSE USERS FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_clickhouse_users__from_disk_to_memory();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading clickhouse users to MEMORY\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE CLICKHOUSE USERS FROM MEMORY") && !strncasecmp("SAVE CLICKHOUSE USERS FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE USERS FROM MEM") && !strncasecmp("SAVE CLICKHOUSE USERS FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE USERS TO DISK") && !strncasecmp("SAVE CLICKHOUSE USERS TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->flush_clickhouse_users__from_memory_to_disk();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saving clickhouse users to DISK\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD CLICKHOUSE USERS FROM MEMORY") && !strncasecmp("LOAD CLICKHOUSE USERS FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE USERS FROM MEM") && !strncasecmp("LOAD CLICKHOUSE USERS FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE USERS TO RUNTIME") && !strncasecmp("LOAD CLICKHOUSE USERS TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE USERS TO RUN") && !strncasecmp("LOAD CLICKHOUSE USERS TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->init_clickhouse_users();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded clickhouse users to RUNTIME\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE CLICKHOUSE USERS TO MEMORY") && !strncasecmp("SAVE CLICKHOUSE USERS TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE USERS TO MEM") && !strncasecmp("SAVE CLICKHOUSE USERS TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE USERS FROM RUNTIME") && !strncasecmp("SAVE CLICKHOUSE USERS FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE USERS FROM RUN") && !strncasecmp("SAVE CLICKHOUSE USERS FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_clickhouse_users_runtime_to_database(false);
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved clickhouse users from RUNTIME\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

	}
#endif /* PROXYSQLCLICKHOUSE */

	if ((query_no_space_length>17) && ( (!strcasecmp("SAVE MYSQL DIGEST TO DISK", query_no_space) ) )) {
		proxy_info("Received %s command\n", query_no_space);
        unsigned long long curtime1=monotonic_time();
		int r1 = SPA->FlushDigestTableToDisk<SERVER_TYPE_MYSQL>(SPA->statsdb_disk);
        unsigned long long curtime2=monotonic_time();
        curtime1 = curtime1/1000;
        curtime2 = curtime2/1000;
		proxy_info("Saved stats_mysql_query_digest to disk: %llums to write %u entries\n", curtime2-curtime1, r1);
		SPA->send_ok_msg_to_client(sess,  NULL, r1, query_no_space);
		return false;
	}

	if ((query_no_space_length > 17) && ((!strcasecmp("SAVE PGSQL DIGEST TO DISK", query_no_space)))) {
		proxy_info("Received %s command\n", query_no_space);
		unsigned long long curtime1 = monotonic_time();
		int r1 = SPA->FlushDigestTableToDisk<SERVER_TYPE_PGSQL>(SPA->statsdb_disk);
		unsigned long long curtime2 = monotonic_time();
		curtime1 = curtime1 / 1000;
		curtime2 = curtime2 / 1000;
		proxy_info("Saved stats_pgsql_query_digest to disk: %llums to write %u entries\n", curtime2 - curtime1, r1);
		SPA->send_ok_msg_to_client(sess, NULL, r1, query_no_space);
		return false;
	}

	if ((query_no_space_length>17) && 
		((!strncasecmp("SAVE MYSQL USERS ", query_no_space, 17)) || (!strncasecmp("LOAD MYSQL USERS ", query_no_space, 17)) ||
		((!strncasecmp("SAVE PGSQL USERS ", query_no_space, 17)) || (!strncasecmp("LOAD PGSQL USERS ", query_no_space, 17))))) {

		const bool is_pgsql = (query_no_space[5] == 'P' || query_no_space[5] == 'p') ? true : false;
		const std::string modname = is_pgsql ? "pgsql_users" : "mysql_users";

		tuple<string, vector<string>, vector<string>>& t = load_save_disk_commands[modname];
		if ( is_admin_command_or_alias(get<1>(t), query_no_space, query_no_space_length) ) {
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			
			if (is_pgsql)
				SPA->flush_pgsql_users__from_disk_to_memory();
			else
				SPA->flush_mysql_users__from_disk_to_memory();

			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading %s to MEMORY\n", modname.c_str());
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}
		if ( is_admin_command_or_alias(get<2>(t), query_no_space, query_no_space_length) ) {
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;

			if (is_pgsql)
				SPA->flush_pgsql_users__from_memory_to_disk();
			else
				SPA->flush_mysql_users__from_memory_to_disk();
			
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saving %s to DISK\n", modname.c_str());
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

		if (is_pgsql) {
			if (is_admin_command_or_alias(LOAD_PGSQL_USERS_FROM_MEMORY, query_no_space, query_no_space_length)) {
				ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
				SPA->init_pgsql_users();
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded pgsql users to RUNTIME\n");
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
				return false;
			}
		} else {
			if (is_admin_command_or_alias(LOAD_MYSQL_USERS_FROM_MEMORY, query_no_space, query_no_space_length)) {
				ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
				SPA->init_users();
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql users to RUNTIME\n");
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
				return false;
			}
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL USERS FROM CONFIG") && (!strncasecmp("LOAD MYSQL USERS FROM CONFIG",query_no_space, query_no_space_length) || 
				!strncasecmp("LOAD PGSQL USERS FROM CONFIG", query_no_space, query_no_space_length)))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					int rows=0;
					if (query_no_space[5] == 'P' || query_no_space[5] == 'p') {
						rows=SPA->proxysql_config().Read_PgSQL_Users_from_configfile();
						proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded pgsql users from CONFIG\n");
					} else {
						rows=SPA->proxysql_config().Read_MySQL_Users_from_configfile();
						proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql users from CONFIG\n");
					}
					SPA->send_ok_msg_to_client(sess, NULL, rows, query_no_space);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_error_msg_to_client(sess, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_error_msg_to_client(sess, (char *)"Config file unknown");
			}
			return false;
		}

		if (is_pgsql) {
			if (is_admin_command_or_alias(SAVE_PGSQL_USERS_TO_MEMORY, query_no_space, query_no_space_length)) {
				ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
				SPA->save_pgsql_users_runtime_to_database(false);
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved pgsql users from RUNTIME\n");
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
				return false;
			}
		} else {
			if (is_admin_command_or_alias(SAVE_MYSQL_USERS_TO_MEMORY, query_no_space, query_no_space_length)) {
				ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
				SPA->save_mysql_users_runtime_to_database(false);
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql users from RUNTIME\n");
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
				return false;
			}
		}
	}
	if ((query_no_space_length>28) && ( (!strncasecmp("SAVE SQLITESERVER VARIABLES ", query_no_space, 28)) || (!strncasecmp("LOAD SQLITESERVER VARIABLES ", query_no_space, 28))) ) {

		if (
			(query_no_space_length==strlen("LOAD SQLITESERVER VARIABLES TO MEMORY") && !strncasecmp("LOAD SQLITESERVER VARIABLES TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SQLITESERVER VARIABLES TO MEM") && !strncasecmp("LOAD SQLITESERVER VARIABLES TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SQLITESERVER VARIABLES FROM DISK") && !strncasecmp("LOAD SQLITESERVER VARIABLES FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'sqliteserver-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if (
			(query_no_space_length==strlen("SAVE SQLITESERVER VARIABLES FROM MEMORY") && !strncasecmp("SAVE SQLITESERVER VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SQLITESERVER VARIABLES FROM MEM") && !strncasecmp("SAVE SQLITESERVER VARIABLES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SQLITESERVER VARIABLES TO DISK") && !strncasecmp("SAVE SQLITESERVER VARIABLES TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'sqliteserver-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if (
			(query_no_space_length==strlen("LOAD SQLITESERVER VARIABLES FROM MEMORY") && !strncasecmp("LOAD SQLITESERVER VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SQLITESERVER VARIABLES FROM MEM") && !strncasecmp("LOAD SQLITESERVER VARIABLES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SQLITESERVER VARIABLES TO RUNTIME") && !strncasecmp("LOAD SQLITESERVER VARIABLES TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD SQLITESERVER VARIABLES TO RUN") && !strncasecmp("LOAD SQLITESERVER VARIABLES TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->load_sqliteserver_variables_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded SQLiteServer variables to RUNTIME\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE SQLITESERVER VARIABLES TO MEMORY") && !strncasecmp("SAVE SQLITESERVER VARIABLES TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SQLITESERVER VARIABLES TO MEM") && !strncasecmp("SAVE SQLITESERVER VARIABLES TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SQLITESERVER VARIABLES FROM RUNTIME") && !strncasecmp("SAVE SQLITESERVER VARIABLES FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE SQLITESERVER VARIABLES FROM RUN") && !strncasecmp("SAVE SQLITESERVER VARIABLES FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_sqliteserver_variables_from_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved SQLiteServer variables from RUNTIME\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}
	}
#ifdef PROXYSQLCLICKHOUSE
	if ((query_no_space_length>26) && ( (!strncasecmp("SAVE CLICKHOUSE VARIABLES ", query_no_space, 26)) || (!strncasecmp("LOAD CLICKHOUSE VARIABLES ", query_no_space, 26))) ) {

		if (
			(query_no_space_length==strlen("LOAD CLICKHOUSE VARIABLES TO MEMORY") && !strncasecmp("LOAD CLICKHOUSE VARIABLES TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE VARIABLES TO MEM") && !strncasecmp("LOAD CLICKHOUSE VARIABLES TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE VARIABLES FROM DISK") && !strncasecmp("LOAD CLICKHOUSE VARIABLES FROM DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'clickhouse-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if (
			(query_no_space_length==strlen("SAVE CLICKHOUSE VARIABLES FROM MEMORY") && !strncasecmp("SAVE CLICKHOUSE VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE VARIABLES FROM MEM") && !strncasecmp("SAVE CLICKHOUSE VARIABLES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE VARIABLES TO DISK") && !strncasecmp("SAVE CLICKHOUSE VARIABLES TO DISK",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'clickhouse-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if (
			(query_no_space_length==strlen("LOAD CLICKHOUSE VARIABLES FROM MEMORY") && !strncasecmp("LOAD CLICKHOUSE VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE VARIABLES FROM MEM") && !strncasecmp("LOAD CLICKHOUSE VARIABLES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE VARIABLES TO RUNTIME") && !strncasecmp("LOAD CLICKHOUSE VARIABLES TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD CLICKHOUSE VARIABLES TO RUN") && !strncasecmp("LOAD CLICKHOUSE VARIABLES TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->load_clickhouse_variables_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded clickhouse variables to RUNTIME\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE CLICKHOUSE VARIABLES TO MEMORY") && !strncasecmp("SAVE CLICKHOUSE VARIABLES TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE VARIABLES TO MEM") && !strncasecmp("SAVE CLICKHOUSE VARIABLES TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE VARIABLES FROM RUNTIME") && !strncasecmp("SAVE CLICKHOUSE VARIABLES FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE CLICKHOUSE VARIABLES FROM RUN") && !strncasecmp("SAVE CLICKHOUSE VARIABLES FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_clickhouse_variables_from_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved clickhouse variables from RUNTIME\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}
	}
#endif /* PROXYSQLCLICKHOUSE */

		if (GloMyLdapAuth) {
		if ((query_no_space_length>20) && ( (!strncasecmp("SAVE LDAP VARIABLES ", query_no_space, 20)) || (!strncasecmp("LOAD LDAP VARIABLES ", query_no_space, 20))) ) {
	
			if (
				(query_no_space_length==strlen("LOAD LDAP VARIABLES TO MEMORY") && !strncasecmp("LOAD LDAP VARIABLES TO MEMORY",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("LOAD LDAP VARIABLES TO MEM") && !strncasecmp("LOAD LDAP VARIABLES TO MEM",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("LOAD LDAP VARIABLES FROM DISK") && !strncasecmp("LOAD LDAP VARIABLES FROM DISK",query_no_space, query_no_space_length))
			) {
				proxy_info("Received %s command\n", query_no_space);
				l_free(*ql,*q);
				*q=l_strdup("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'ldap-%'");
				*ql=strlen(*q)+1;
				return true;
			}
	
			if (
				(query_no_space_length==strlen("SAVE LDAP VARIABLES FROM MEMORY") && !strncasecmp("SAVE LDAP VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SAVE LDAP VARIABLES FROM MEM") && !strncasecmp("SAVE LDAP VARIABLES FROM MEM",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SAVE LDAP VARIABLES TO DISK") && !strncasecmp("SAVE LDAP VARIABLES TO DISK",query_no_space, query_no_space_length))
			) {
				proxy_info("Received %s command\n", query_no_space);
				l_free(*ql,*q);
				*q=l_strdup("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'ldap-%'");
				*ql=strlen(*q)+1;
				return true;
			}
	
			if (
				(query_no_space_length==strlen("LOAD LDAP VARIABLES FROM MEMORY") && !strncasecmp("LOAD LDAP VARIABLES FROM MEMORY",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("LOAD LDAP VARIABLES FROM MEM") && !strncasecmp("LOAD LDAP VARIABLES FROM MEM",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("LOAD LDAP VARIABLES TO RUNTIME") && !strncasecmp("LOAD LDAP VARIABLES TO RUNTIME",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("LOAD LDAP VARIABLES TO RUN") && !strncasecmp("LOAD LDAP VARIABLES TO RUN",query_no_space, query_no_space_length))
			) {
				proxy_info("Received %s command\n", query_no_space);
				ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
				SPA->load_ldap_variables_to_runtime();
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded ldap variables to RUNTIME\n");
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
				return false;
			}
	
			if (
				(query_no_space_length==strlen("SAVE LDAP VARIABLES TO MEMORY") && !strncasecmp("SAVE LDAP VARIABLES TO MEMORY",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SAVE LDAP VARIABLES TO MEM") && !strncasecmp("SAVE LDAP VARIABLES TO MEM",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SAVE LDAP VARIABLES FROM RUNTIME") && !strncasecmp("SAVE LDAP VARIABLES FROM RUNTIME",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SAVE LDAP VARIABLES FROM RUN") && !strncasecmp("SAVE LDAP VARIABLES FROM RUN",query_no_space, query_no_space_length))
			) {
				proxy_info("Received %s command\n", query_no_space);
				ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
				SPA->save_ldap_variables_from_runtime();
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved ldap variables from RUNTIME\n");
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
				return false;
			}
		}
	}

		if ((query_no_space_length > 21) && ((!strncasecmp("SAVE MYSQL VARIABLES ", query_no_space, 21)) || (!strncasecmp("LOAD MYSQL VARIABLES ", query_no_space, 21)) ||
			(!strncasecmp("SAVE PGSQL VARIABLES ", query_no_space, 21)) || (!strncasecmp("LOAD PGSQL VARIABLES ", query_no_space, 21)))) {

			const bool is_pgsql = (query_no_space[5] == 'P' || query_no_space[5] == 'p') ? true : false;
			const std::string modname = is_pgsql ? "pgsql_variables" : "mysql_variables";

			tuple<string, vector<string>, vector<string>>& t = load_save_disk_commands[modname];
			if (is_admin_command_or_alias(get<1>(t), query_no_space, query_no_space_length)) {
				l_free(*ql, *q);
				if (is_pgsql) {
					*q = l_strdup("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'pgsql-%'");
				}
				else {
					*q = l_strdup("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'mysql-%'");
				}
				*ql = strlen(*q) + 1;
				return true;
			}

			if (is_admin_command_or_alias(get<2>(t), query_no_space, query_no_space_length)) {
				l_free(*ql, *q);
				if (is_pgsql) {
					*q = l_strdup("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'pgsql-%'");
				}
				else {
					*q = l_strdup("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'mysql-%'");
				}
				*ql = strlen(*q) + 1;
				return true;
			}

			if (is_pgsql) {
				if (is_admin_command_or_alias(LOAD_PGSQL_VARIABLES_FROM_MEMORY, query_no_space, query_no_space_length)) {
					ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
					SPA->load_pgsql_variables_to_runtime();
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded pgsql variables to RUNTIME\n");
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql variables to RUNTIME\n");
					SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
					return false;
				}
			} else {
				if (is_admin_command_or_alias(LOAD_MYSQL_VARIABLES_FROM_MEMORY, query_no_space, query_no_space_length)) {
					ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
					SPA->load_mysql_variables_to_runtime();
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql variables to RUNTIME\n");
					SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
					return false;
			}
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL VARIABLES FROM CONFIG") && (!strncasecmp("LOAD MYSQL VARIABLES FROM CONFIG",query_no_space, query_no_space_length) ||
				!strncasecmp("LOAD PGSQL VARIABLES FROM CONFIG", query_no_space, query_no_space_length)))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					int rows=0;
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					if (query_no_space[5] == 'P' || query_no_space[5] == 'p') {
						rows=SPA->proxysql_config().Read_Global_Variables_from_configfile("pgsql");
						proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded pgsql global variables from CONFIG\n");
					} else {
						rows = SPA->proxysql_config().Read_Global_Variables_from_configfile("mysql");
						proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql global variables from CONFIG\n");
					}
					SPA->send_ok_msg_to_client(sess, NULL, rows, query_no_space);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_error_msg_to_client(sess, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_error_msg_to_client(sess, (char *)"Config file unknown");
			}
			return false;
		}

		if (is_pgsql) {
			if (is_admin_command_or_alias(SAVE_PGSQL_VARIABLES_TO_MEMORY, query_no_space, query_no_space_length)) {
				ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
				SPA->save_pgsql_variables_from_runtime();
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved pgsql variables from RUNTIME\n");
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
				return false;
			}
		} else {
			if (is_admin_command_or_alias(SAVE_MYSQL_VARIABLES_TO_MEMORY, query_no_space, query_no_space_length)) {
				ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
				SPA->save_mysql_variables_from_runtime();
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql variables from RUNTIME\n");
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
				return false;
			}
		}
	}

	if ((query_no_space_length > 14) && (!strncasecmp("LOAD COREDUMP ", query_no_space, 14))) {

		if ( is_admin_command_or_alias(LOAD_COREDUMP_FROM_MEMORY, query_no_space, query_no_space_length) ) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
			bool rc = SPA->load_coredump_to_runtime();
			if (rc) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded coredump filters to RUNTIME\n");
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 1, "Error while loading coredump filters to RUNTIME\n");
				SPA->send_error_msg_to_client(sess, (char*)"Error while loading coredump filters to RUNTIME");
			}
			return false;
		}
	}

	if ((query_no_space_length>19) && ( (!strncasecmp("SAVE MYSQL SERVERS ", query_no_space, 19)) || (!strncasecmp("LOAD MYSQL SERVERS ", query_no_space, 19)) ||
		(!strncasecmp("SAVE PGSQL SERVERS ", query_no_space, 19)) || (!strncasecmp("LOAD PGSQL SERVERS ", query_no_space, 19)))) {

		const bool is_pgsql = (query_no_space[5] == 'P' || query_no_space[5] == 'p') ? true : false;
		const std::string modname = is_pgsql ? "pgsql_servers" : "mysql_servers";

		if (FlushCommandWrapper(sess, modname, query_no_space, query_no_space_length) == true)
			return false;

		if (is_pgsql) {
			if (is_admin_command_or_alias(LOAD_PGSQL_SERVERS_FROM_MEMORY, query_no_space, query_no_space_length)) {
				ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
				SPA->pgsql_servers_wrlock();
				SPA->load_pgsql_servers_to_runtime();
				SPA->pgsql_servers_wrunlock();
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded pgsql servers to RUNTIME\n");
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
				return false;
			}
		} else {
			if (is_admin_command_or_alias(LOAD_MYSQL_SERVERS_FROM_MEMORY, query_no_space, query_no_space_length)) {
				ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
				SPA->mysql_servers_wrlock();
				SPA->load_mysql_servers_to_runtime();
				SPA->mysql_servers_wrunlock();
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql servers to RUNTIME\n");
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
				return false;
			}
		}
		
		if (
			(query_no_space_length==strlen("LOAD MYSQL SERVERS FROM CONFIG") && (!strncasecmp("LOAD MYSQL SERVERS FROM CONFIG",query_no_space, query_no_space_length) ||
				!strncasecmp("LOAD PGSQL SERVERS FROM CONFIG", query_no_space, query_no_space_length) ))) {

			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					int rows=0;
					if (is_pgsql) {
						rows=SPA->proxysql_config().Read_PgSQL_Servers_from_configfile();
						proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded pgsql servers from CONFIG\n");
					} else {
						rows=SPA->proxysql_config().Read_MySQL_Servers_from_configfile();
						proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql servers from CONFIG\n");
					}
					SPA->send_ok_msg_to_client(sess, NULL, rows, query_no_space);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_error_msg_to_client(sess, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_error_msg_to_client(sess, (char *)"Config file unknown");
			}
			return false;
		}

		if (is_pgsql) {
			if (is_admin_command_or_alias(SAVE_PGSQL_SERVERS_TO_MEMORY, query_no_space, query_no_space_length)) {
				ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
				SPA->pgsql_servers_wrlock();
				SPA->save_pgsql_servers_runtime_to_database(false);
				SPA->pgsql_servers_wrunlock();
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved pgsql servers from RUNTIME\n");
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
				return false;
			}
		} else {
			if (is_admin_command_or_alias(SAVE_MYSQL_SERVERS_TO_MEMORY, query_no_space, query_no_space_length)) {
				ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
				SPA->mysql_servers_wrlock();
				SPA->save_mysql_servers_runtime_to_database(false);
				SPA->mysql_servers_wrunlock();
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql servers from RUNTIME\n");
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
				return false;
			}
		}
	}

	if ((query_no_space_length>22) && ( (!strncasecmp("SAVE PROXYSQL SERVERS ", query_no_space, 22)) || (!strncasecmp("LOAD PROXYSQL SERVERS ", query_no_space, 22))) ) {

		if (FlushCommandWrapper(sess, "proxysql_servers", query_no_space, query_no_space_length) == true)
			return false;
/*
		string modname = "proxysql_servers";
		tuple<string, vector<string>, vector<string>>& t = load_save_disk_commands[modname];
		if (FlushCommandWrapper(sess, get<1>(t), query_no_space, query_no_space_length, modname, "disk_to_memory") == true)
			return false;

		if (FlushCommandWrapper(sess, get<2>(t), query_no_space, query_no_space_length, modname, "memory_to_disk") == true)
			return false;
*/
		if (
			(query_no_space_length==strlen("LOAD PROXYSQL SERVERS FROM MEMORY") && !strncasecmp("LOAD PROXYSQL SERVERS FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD PROXYSQL SERVERS FROM MEM") && !strncasecmp("LOAD PROXYSQL SERVERS FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD PROXYSQL SERVERS TO RUNTIME") && !strncasecmp("LOAD PROXYSQL SERVERS TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD PROXYSQL SERVERS TO RUN") && !strncasecmp("LOAD PROXYSQL SERVERS TO RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			//SPA->mysql_servers_wrlock();
			// before calling load_proxysql_servers_to_runtime() we release
			// sql_query_global_mutex to prevent a possible deadlock due to
			// a race condition
			// load_proxysql_servers_to_runtime() calls ProxySQL_Cluster::load_servers_list()
			// that then calls ProxySQL_Cluster_Nodes::load_servers_list(), holding a mutex
			pthread_mutex_unlock(&SPA->sql_query_global_mutex);
			SPA->load_proxysql_servers_to_runtime(true);
			// we re-acquired the mutex because it will be released by the calling function
			pthread_mutex_lock(&SPA->sql_query_global_mutex);
			//SPA->mysql_servers_wrunlock();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded ProxySQL servers to RUNTIME\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}
		if (
			(query_no_space_length==strlen("SAVE PROXYSQL SERVERS TO MEMORY") && !strncasecmp("SAVE PROXYSQL SERVERS TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE PROXYSQL SERVERS TO MEM") && !strncasecmp("SAVE PROXYSQL SERVERS TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE PROXYSQL SERVERS FROM RUNTIME") && !strncasecmp("SAVE PROXYSQL SERVERS FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE PROXYSQL SERVERS FROM RUN") && !strncasecmp("SAVE PROXYSQL SERVERS FROM RUN",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			//SPA->mysql_servers_wrlock();
			// before save_proxysql_servers_runtime_to_database() we release
			// sql_query_global_mutex to prevent a possible deadlock due to
			// a race condition
			// save_proxysql_servers_runtime_to_database() calls ProxySQL_Cluster::dump_table_proxysql_servers()
			// that then holds a mutex
			pthread_mutex_unlock(&SPA->sql_query_global_mutex);
			SPA->save_proxysql_servers_runtime_to_database(false);
			// we re-acquired the mutex because it will be released by the calling function
			pthread_mutex_lock(&SPA->sql_query_global_mutex);
			//SPA->mysql_servers_wrunlock();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved ProxySQL servers from RUNTIME\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD PROXYSQL SERVERS FROM CONFIG") && !strncasecmp("LOAD PROXYSQL SERVERS FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					int rows=0;
					rows=SPA->proxysql_config().Read_ProxySQL_Servers_from_configfile();
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded ProxySQL servers from CONFIG\n");
					SPA->send_ok_msg_to_client(sess, NULL, rows, query_no_space);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_error_msg_to_client(sess, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_error_msg_to_client(sess, (char *)"Config file unknown");
			}
			return false;
		}

	}

	if ((query_no_space_length>20) && (( (!strncasecmp("SAVE MYSQL FIREWALL ", query_no_space, 20)) || (!strncasecmp("LOAD MYSQL FIREWALL ", query_no_space, 20))) ||
		(!strncasecmp("SAVE PGSQL FIREWALL ", query_no_space, 20) || (!strncasecmp("LOAD PGSQL FIREWALL ", query_no_space, 20)))) ) {

		const std::string modname = (query_no_space[5] == 'P' || query_no_space[5] == 'p') ? "pgsql_firewall" : "mysql_firewall";

		if (FlushCommandWrapper(sess, modname, query_no_space, query_no_space_length) == true)
			return false;

		if (
			(query_no_space_length==strlen("LOAD MYSQL FIREWALL FROM CONFIG") && (!strncasecmp("LOAD MYSQL FIREWALL FROM CONFIG",query_no_space, query_no_space_length) ||
				!strncasecmp("LOAD PGSQL FIREWALL FROM CONFIG", query_no_space, query_no_space_length)))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					int rows=0;
					// FIXME: not implemented yet
					if (query_no_space[5] == 'P' || query_no_space[5] == 'p') {
					//	rows=SPA->proxysql_config().Read_PgSQL_Firewall_from_configfile();
						proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded pgsql firewall from CONFIG\n");
					} else {
					//	rows=SPA->proxysql_config().Read_MySQL_Firewall_from_configfile();
						proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql firewall from CONFIG\n");
					}
					SPA->send_ok_msg_to_client(sess, NULL, rows, query_no_space);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_error_msg_to_client(sess, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_error_msg_to_client(sess, (char *)"Config file unknown");
			}
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL FIREWALL FROM MEMORY") && !strncasecmp("LOAD MYSQL FIREWALL FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL FIREWALL FROM MEM") && !strncasecmp("LOAD MYSQL FIREWALL FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL FIREWALL TO RUNTIME") && !strncasecmp("LOAD MYSQL FIREWALL TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL FIREWALL TO RUN") && !strncasecmp("LOAD MYSQL FIREWALL TO RUN",query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("LOAD PGSQL FIREWALL FROM MEMORY") && !strncasecmp("LOAD PGSQL FIREWALL FROM MEMORY", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("LOAD PGSQL FIREWALL FROM MEM") && !strncasecmp("LOAD PGSQL FIREWALL FROM MEM", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("LOAD PGSQL FIREWALL TO RUNTIME") && !strncasecmp("LOAD PGSQL FIREWALL TO RUNTIME", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("LOAD PGSQL FIREWALL TO RUN") && !strncasecmp("LOAD PGSQL FIREWALL TO RUN", query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			const char* err = (query_no_space[5] == 'P' || query_no_space[5] == 'p') ? SPA->load_pgsql_firewall_to_runtime() : SPA->load_mysql_firewall_to_runtime();
			if (err==NULL) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql firewall to RUNTIME\n");
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			} else {
				SPA->send_error_msg_to_client(sess, err);
			}
			return false;
		}

		if (
			(query_no_space_length==strlen("SAVE MYSQL FIREWALL TO MEMORY") && !strncasecmp("SAVE MYSQL FIREWALL TO MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL FIREWALL TO MEM") && !strncasecmp("SAVE MYSQL FIREWALL TO MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL FIREWALL FROM RUNTIME") && !strncasecmp("SAVE MYSQL FIREWALL FROM RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("SAVE MYSQL FIREWALL FROM RUN") && !strncasecmp("SAVE MYSQL FIREWALL FROM RUN",query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("SAVE PGSQL FIREWALL TO MEMORY") && !strncasecmp("SAVE PGSQL FIREWALL TO MEMORY", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("SAVE PGSQL FIREWALL TO MEM") && !strncasecmp("SAVE PGSQL FIREWALL TO MEM", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("SAVE PGSQL FIREWALL FROM RUNTIME") && !strncasecmp("SAVE PGSQL FIREWALL FROM RUNTIME", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("SAVE PGSQL FIREWALL FROM RUN") && !strncasecmp("SAVE PGSQL FIREWALL FROM RUN", query_no_space, query_no_space_length))

		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			if (query_no_space[5] == 'P' || query_no_space[5] == 'p') {
				SPA->save_pgsql_firewall_from_runtime(false);
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved pgsql firewall from RUNTIME\n");
			} else {
				SPA->save_mysql_firewall_from_runtime(false);
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql firewall from RUNTIME\n");
			}
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}
	}

	if ((query_no_space_length>23) && ( (!strncasecmp("SAVE MYSQL QUERY RULES ", query_no_space, 23)) || (!strncasecmp("LOAD MYSQL QUERY RULES ", query_no_space, 23)) ||
		(!strncasecmp("SAVE PGSQL QUERY RULES ", query_no_space, 23)) || (!strncasecmp("LOAD PGSQL QUERY RULES ", query_no_space, 23))
		) ) {

		const std::string modname = (query_no_space[5] == 'P' || query_no_space[5] == 'p') ? "pgsql_query_rules" : "mysql_query_rules";
		if (FlushCommandWrapper(sess, modname, query_no_space, query_no_space_length) == true)
			return false;

		if (
			(query_no_space_length==strlen("LOAD MYSQL QUERY RULES FROM CONFIG") && (!strncasecmp("LOAD MYSQL QUERY RULES FROM CONFIG",query_no_space, query_no_space_length) ||
				!strncasecmp("LOAD PGSQL QUERY RULES FROM CONFIG", query_no_space, query_no_space_length)))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					int rows=0;
					if (query_no_space[5] == 'P' || query_no_space[5] == 'p') {
						rows = SPA->proxysql_config().Read_PgSQL_Query_Rules_from_configfile();
						proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded pgsql query rules from CONFIG\n");
					} else {
						rows = SPA->proxysql_config().Read_MySQL_Query_Rules_from_configfile();
						proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql query rules from CONFIG\n");
					}
					SPA->send_ok_msg_to_client(sess, NULL, rows, query_no_space);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_error_msg_to_client(sess, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_error_msg_to_client(sess, (char *)"Config file unknown");
			}
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD MYSQL QUERY RULES FROM MEMORY") && !strncasecmp("LOAD MYSQL QUERY RULES FROM MEMORY",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL QUERY RULES FROM MEM") && !strncasecmp("LOAD MYSQL QUERY RULES FROM MEM",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL QUERY RULES TO RUNTIME") && !strncasecmp("LOAD MYSQL QUERY RULES TO RUNTIME",query_no_space, query_no_space_length))
			||
			(query_no_space_length==strlen("LOAD MYSQL QUERY RULES TO RUN") && !strncasecmp("LOAD MYSQL QUERY RULES TO RUN",query_no_space, query_no_space_length)) 
			||
			(query_no_space_length == strlen("LOAD PGSQL QUERY RULES FROM MEMORY") && !strncasecmp("LOAD PGSQL QUERY RULES FROM MEMORY", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("LOAD PGSQL QUERY RULES FROM MEM") && !strncasecmp("LOAD PGSQL QUERY RULES FROM MEM", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("LOAD PGSQL QUERY RULES TO RUNTIME") && !strncasecmp("LOAD PGSQL QUERY RULES TO RUNTIME", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("LOAD PGSQL QUERY RULES TO RUN") && !strncasecmp("LOAD PGSQL QUERY RULES TO RUN", query_no_space, query_no_space_length))

		) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			char* err = NULL;
			
			if (query_no_space[5] == 'P' || query_no_space[5] == 'p')
				err = SPA->load_pgsql_query_rules_to_runtime();
			else
				err = SPA->load_mysql_query_rules_to_runtime();

			if (err==NULL) {
				if (query_no_space[5] == 'P' || query_no_space[5] == 'p')
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded pgsql query rules to RUNTIME\n");
				else
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded mysql query rules to RUNTIME\n");
				
				SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			} else {
				SPA->send_error_msg_to_client(sess, err);
			}
			return false;
		}

		if (
			(query_no_space_length == strlen("SAVE MYSQL QUERY RULES TO MEMORY") && !strncasecmp("SAVE MYSQL QUERY RULES TO MEMORY", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("SAVE MYSQL QUERY RULES TO MEM") && !strncasecmp("SAVE MYSQL QUERY RULES TO MEM", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("SAVE MYSQL QUERY RULES FROM RUNTIME") && !strncasecmp("SAVE MYSQL QUERY RULES FROM RUNTIME", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("SAVE MYSQL QUERY RULES FROM RUN") && !strncasecmp("SAVE MYSQL QUERY RULES FROM RUN", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("SAVE PGSQL QUERY RULES TO MEMORY") && !strncasecmp("SAVE PGSQL QUERY RULES TO MEMORY", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("SAVE PGSQL QUERY RULES TO MEM") && !strncasecmp("SAVE PGSQL QUERY RULES TO MEM", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("SAVE PGSQL QUERY RULES FROM RUNTIME") && !strncasecmp("SAVE PGSQL QUERY RULES FROM RUNTIME", query_no_space, query_no_space_length))
			||
			(query_no_space_length == strlen("SAVE PGSQL QUERY RULES FROM RUN") && !strncasecmp("SAVE PGSQL QUERY RULES FROM RUN", query_no_space, query_no_space_length))

			) {
			proxy_info("Received %s command\n", query_no_space);
			ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
			if (query_no_space[5] == 'P' || query_no_space[5] == 'p') {
				SPA->save_pgsql_query_rules_from_runtime(false);
				SPA->save_pgsql_query_rules_fast_routing_from_runtime(false);
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved pgsql query rules from RUNTIME\n");
			} else {
				SPA->save_mysql_query_rules_from_runtime(false);
				SPA->save_mysql_query_rules_fast_routing_from_runtime(false);
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved mysql query rules from RUNTIME\n");
			}
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}
	}

	if ((query_no_space_length>21) && ( (!strncasecmp("SAVE ADMIN VARIABLES ", query_no_space, 21)) || (!strncasecmp("LOAD ADMIN VARIABLES ", query_no_space, 21))) ) {

		if ( is_admin_command_or_alias(LOAD_ADMIN_VARIABLES_TO_MEMORY, query_no_space, query_no_space_length) ) {
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO main.global_variables SELECT * FROM disk.global_variables WHERE variable_name LIKE 'admin-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if ( is_admin_command_or_alias(SAVE_ADMIN_VARIABLES_FROM_MEMORY, query_no_space, query_no_space_length) ) {
			l_free(*ql,*q);
			*q=l_strdup("INSERT OR REPLACE INTO disk.global_variables SELECT * FROM main.global_variables WHERE variable_name LIKE 'admin-%'");
			*ql=strlen(*q)+1;
			return true;
		}

		if ( is_admin_command_or_alias(LOAD_ADMIN_VARIABLES_FROM_MEMORY, query_no_space, query_no_space_length) ) {
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->load_admin_variables_to_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded admin variables to RUNTIME\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

		if (
			(query_no_space_length==strlen("LOAD ADMIN VARIABLES FROM CONFIG") && !strncasecmp("LOAD ADMIN VARIABLES FROM CONFIG",query_no_space, query_no_space_length))
		) {
			proxy_info("Received %s command\n", query_no_space);
			if (GloVars.configfile_open) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loading from file %s\n", GloVars.config_file);
				if (GloVars.confFile->OpenFile(NULL)==true) {
					int rows=0;
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					rows=SPA->proxysql_config().Read_Global_Variables_from_configfile("admin");
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Loaded admin variables from CONFIG\n");
					SPA->send_ok_msg_to_client(sess, NULL, rows, query_no_space);
					GloVars.confFile->CloseFile();
				} else {
					proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unable to open or parse config file %s\n", GloVars.config_file);
					char *s=(char *)"Unable to open or parse config file %s";
					char *m=(char *)malloc(strlen(s)+strlen(GloVars.config_file)+1);
					sprintf(m,s,GloVars.config_file);
					SPA->send_error_msg_to_client(sess, m);
					free(m);
				}
			} else {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Unknown config file\n");
				SPA->send_error_msg_to_client(sess, (char *)"Config file unknown");
			}
			return false;
		}

		if ( is_admin_command_or_alias(SAVE_ADMIN_VARIABLES_TO_MEMORY, query_no_space, query_no_space_length) ) {
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->save_admin_variables_from_runtime();
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Saved admin variables from RUNTIME\n");
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			return false;
		}

	}

	if (!strncasecmp("SAVE CONFIG TO FILE", query_no_space, strlen("SAVE CONFIG TO FILE"))) {
		std::string fileName = query_no_space + strlen("SAVE CONFIG TO FILE");

		fileName.erase(0, fileName.find_first_not_of("\t\n\v\f\r "));
		fileName.erase(fileName.find_last_not_of("\t\n\v\f\r ") + 1);
		if (fileName.size() == 0) {
			proxy_error("ProxySQL Admin Error: empty file name\n");
			SPA->send_error_msg_to_client(sess, (char *)"ProxySQL Admin Error: empty file name");
			return false;
		}
		std::string data;
		data.reserve(100000);
		data += config_header;
		int rc = pa->proxysql_config().Write_Global_Variables_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Users_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Query_Rules_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Servers_to_configfile(data);
		rc = pa->proxysql_config().Write_PgSQL_Users_to_configfile(data);
		rc = pa->proxysql_config().Write_PgSQL_Query_Rules_to_configfile(data);
		rc = pa->proxysql_config().Write_PgSQL_Servers_to_configfile(data);
		rc = pa->proxysql_config().Write_Scheduler_to_configfile(data);
		rc = pa->proxysql_config().Write_ProxySQL_Servers_to_configfile(data);
		if (rc) {
			std::stringstream ss;
			proxy_error("ProxySQL Admin Error: Cannot extract configuration\n");
			SPA->send_error_msg_to_client(sess, (char *)"ProxySQL Admin Error: Cannot extract configuration");
			return false;
		} else {
			std::ofstream out;
			out.open(fileName);
			if (out.is_open()) {
				out << data;
				out.close();
				if (!out) {
					std::stringstream ss;
					ss << "ProxySQL Admin Error: Error writing file " << fileName;
					proxy_error("%s\n", ss.str().c_str());
					SPA->send_error_msg_to_client(sess, (char*)ss.str().c_str());
					return false;
				} else {
					std::stringstream ss;
					ss << "File " << fileName << " is saved.";
					SPA->send_ok_msg_to_client(sess, (char*)ss.str().c_str(), 0, query_no_space);
					return false;
				}
			} else {
				std::stringstream ss;
				ss << "ProxySQL Admin Error: Cannot open file " << fileName;
				proxy_error("%s\n", ss.str().c_str());
				SPA->send_error_msg_to_client(sess, (char*)ss.str().c_str());
				return false;
			}
		}
	}

	return true;
}

/**
 * @brief Helper function that converts the current timezone
 *   expressed in seconds into a string of the format:
 *     - '[-]HH:MM:00'.
 *   Following the same pattern as the possible values returned by the SQL query
 *   'SELECT TIMEDIFF(NOW(), UTC_TIMESTAMP())' in a MySQL server.
 * @return A string holding the specified representation of the
 *   supplied timezone.
 */
std::string timediff_timezone_offset() {
    std::string time_zone_offset {};
    char result[8];
    time_t rawtime;
    struct tm *info;
    int offset;

    time(&rawtime);
    info = localtime(&rawtime);
    strftime(result, 8, "%z", info);
    offset = (result[0] == '+') ? 1 : 0; 
    time_zone_offset = ((std::string)(result)).substr(offset, 3-offset) + ":" + ((std::string)(result)).substr(3, 2) + ":00";

    return time_zone_offset;
}



template<typename S>
void admin_session_handler(S* sess, void *_pa, PtrSize_t *pkt) {

	ProxySQL_Admin *pa=(ProxySQL_Admin *)_pa;
	bool needs_vacuum = false;
	char *error=NULL;
	int cols;
	int affected_rows = 0;
	bool run_query=true;
	SQLite3_result *resultset=NULL;
	char *strA=NULL;
	char *strB=NULL;
	int strAl, strBl;
	char *query=NULL;
	unsigned int query_length = 0;
	char* query_no_space = NULL;
	unsigned int query_no_space_length = 0;

	if constexpr (std::is_same_v<S,MySQL_Session>) {
		query_length = pkt->size - sizeof(mysql_hdr);
		query = (char*)l_alloc(query_length);
		memcpy(query, (char*)pkt->ptr + sizeof(mysql_hdr) + 1, query_length - 1);
	} else if constexpr (std::is_same_v<S,PgSQL_Session>) {
		assert(sess->client_myds);

		pgsql_hdr hdr{};
		if (sess->client_myds->myprot.get_header((unsigned char*)pkt->ptr, pkt->size, &hdr) == false) {
			//error
			proxy_warning("Malformed packet\n");
			SPA->send_error_msg_to_client(sess, "Malformed packet");
			run_query = false;
			goto __run_query;
		}
		
		switch (hdr.type) {
		case PG_PKT_STARTUP_V2:
		case PG_PKT_STARTUP:
		case PG_PKT_CANCEL:
		case PG_PKT_SSLREQ:
		case PG_PKT_GSSENCREQ:
			//error
			proxy_warning("Unsupported query type %d\n", hdr.type);
			SPA->send_error_msg_to_client(sess, "Unsupported query type");
			run_query = false;
			goto __run_query;
		}

		query_length = hdr.data.size;
		query = (char*)l_alloc(query_length);
		memcpy(query, (char*)hdr.data.ptr, query_length - 1);
	} else {
		assert(0);
	}

	query[query_length-1]=0;

	query_no_space=(char *)l_alloc(query_length);
	memcpy(query_no_space,query,query_length);

	query_no_space_length=remove_spaces(query_no_space);
	//fprintf(stderr,"%s----\n",query_no_space);

	if (query_no_space_length) {
		// fix bug #925
		while (query_no_space_length && 
			(query_no_space[query_no_space_length-1]==';' || query_no_space[query_no_space_length-1]==' ')) {
			query_no_space_length--;
			query_no_space[query_no_space_length]=0;
		}
	}

	if (query_no_space_length == 0) {
		proxy_warning("Empty query\n");
		SPA->send_error_msg_to_client(sess, "Empty query");
		run_query = false;
		goto __run_query;
	}

	// add global mutex, see bug #1188
	pthread_mutex_lock(&pa->sql_query_global_mutex);

	if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
		if (!strncasecmp("LOGENTRY ", query_no_space, strlen("LOGENTRY "))) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received command LOGENTRY: %s\n", query_no_space + strlen("LOGENTRY "));
			proxy_info("Received command LOGENTRY: %s\n", query_no_space + strlen("LOGENTRY "));
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			run_query=false;
			goto __run_query;
		 }
	 }

	// handle special queries from Cluster
	// for bug #1188 , ProxySQL Admin needs to know the exact query

	if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
		string tn = "";
		if (!strncasecmp(CLUSTER_QUERY_RUNTIME_MYSQL_SERVERS, query_no_space, strlen(CLUSTER_QUERY_RUNTIME_MYSQL_SERVERS))) {
			tn = "cluster_mysql_servers";
		} else if (!strncasecmp(CLUSTER_QUERY_MYSQL_REPLICATION_HOSTGROUPS, query_no_space, strlen(CLUSTER_QUERY_MYSQL_REPLICATION_HOSTGROUPS))) {
			tn = "mysql_replication_hostgroups";
		} else if (!strncasecmp(CLUSTER_QUERY_MYSQL_GROUP_REPLICATION_HOSTGROUPS, query_no_space, strlen(CLUSTER_QUERY_MYSQL_GROUP_REPLICATION_HOSTGROUPS))) {
			tn = "mysql_group_replication_hostgroups";
		} else if (!strncasecmp(CLUSTER_QUERY_MYSQL_GALERA, query_no_space, strlen(CLUSTER_QUERY_MYSQL_GALERA))) {
			tn = "mysql_galera_hostgroups";
		} else if (!strncasecmp(CLUSTER_QUERY_MYSQL_AWS_AURORA, query_no_space, strlen(CLUSTER_QUERY_MYSQL_AWS_AURORA))) {
			tn = "mysql_aws_aurora_hostgroups";
		} else if (!strncasecmp(CLUSTER_QUERY_MYSQL_HOSTGROUP_ATTRIBUTES, query_no_space, strlen(CLUSTER_QUERY_MYSQL_HOSTGROUP_ATTRIBUTES))) {
			tn = "mysql_hostgroup_attributes";
		} else if (!strncasecmp(CLUSTER_QUERY_MYSQL_SERVERS_SSL_PARAMS, query_no_space, strlen(CLUSTER_QUERY_MYSQL_SERVERS_SSL_PARAMS))) {
			tn = "mysql_servers_ssl_params";
		} else if (!strncasecmp(CLUSTER_QUERY_MYSQL_SERVERS_V2, query_no_space, strlen(CLUSTER_QUERY_MYSQL_SERVERS_V2))) {
			tn = "mysql_servers_v2";
		}
		if (tn != "") {
			GloAdmin->mysql_servers_wrlock();
			resultset = MyHGM->get_current_mysql_table(tn);
			GloAdmin->mysql_servers_wrunlock();

			if (resultset == nullptr) {
				// 'mysql_servers_v2' is a virtual table that represents the latest 'main.mysql_servers'
				// records promoted by the user. This section shouldn't be reached, since the initial resulset
				// for this table ('MySQL_HostGroups_Manager::incoming_mysql_servers') is generated during
				// initialization, and it's only updated in subsequent user config promotions. In case we
				// reach here, an empty resultset should be replied, as it would mean that no user
				// config has ever been promoted to runtime, and thus, this virtual table should remain empty.
				if (tn == "mysql_servers_v2") {
					const string query_empty_resultset {
						string { MYHGM_GEN_CLUSTER_ADMIN_RUNTIME_SERVERS } + " LIMIT 0"
					};

					char *error=NULL;
					int cols=0;
					int affected_rows=0;
					proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "%s\n", query);
					GloAdmin->mysql_servers_wrlock();
					GloAdmin->admindb->execute_statement(query_empty_resultset.c_str(), &error, &cols, &affected_rows, &resultset);
					GloAdmin->mysql_servers_wrunlock();
				} else {
					resultset = MyHGM->dump_table_mysql(tn);
				}

				if (resultset) {
					sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
					delete resultset;
					run_query=false;
					goto __run_query;
				}
			} else {
				sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
				run_query=false;
				goto __run_query;
			}
			
		}
	}

	if (!strncasecmp(CLUSTER_QUERY_MYSQL_USERS, query_no_space, strlen(CLUSTER_QUERY_MYSQL_USERS))) {
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) {
			pthread_mutex_lock(&users_mutex);
			resultset = GloMyAuth->get_current_mysql_users();
			pthread_mutex_unlock(&users_mutex);
			if (resultset != nullptr) {
				sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
				run_query=false;
				goto __run_query;
			}
		}
	}

	if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
		if (!strncasecmp(CLUSTER_QUERY_MYSQL_QUERY_RULES, query_no_space, strlen(CLUSTER_QUERY_MYSQL_QUERY_RULES))) {
			GloMyQPro->wrlock();
			resultset = GloMyQPro->get_current_query_rules_inner();
			if (resultset == NULL) {
				GloMyQPro->wrunlock(); // unlock first
				resultset = GloMyQPro->get_current_query_rules();
				if (resultset) {
					sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
					delete resultset;
					run_query=false;
					goto __run_query;
				}
			} else {
				sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
				//delete resultset; // DO NOT DELETE . This is the inner resultset of Query_Processor
				GloMyQPro->wrunlock();
				run_query=false;
				goto __run_query;
			}
		}
		if (!strncasecmp(CLUSTER_QUERY_MYSQL_QUERY_RULES_FAST_ROUTING, query_no_space, strlen(CLUSTER_QUERY_MYSQL_QUERY_RULES_FAST_ROUTING))) {
			GloMyQPro->wrlock();
			resultset = GloMyQPro->get_current_query_rules_fast_routing_inner();
			if (resultset == NULL) {
				GloMyQPro->wrunlock(); // unlock first
				resultset = GloMyQPro->get_current_query_rules_fast_routing();
				if (resultset) {
					sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
					delete resultset;
					run_query=false;
					goto __run_query;
				}
			} else {
				sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
				//delete resultset; // DO NOT DELETE . This is the inner resultset of Query_Processor
				GloMyQPro->wrunlock();
				run_query=false;
				goto __run_query;
			}
		}
	}

	// if the client simply executes:
	// SELECT COUNT(*) FROM runtime_mysql_query_rules_fast_routing
	// we just return the count
	if (strcmp("SELECT COUNT(*) FROM runtime_mysql_query_rules_fast_routing", query_no_space)==0) {
		int cnt = GloMyQPro->get_current_query_rules_fast_routing_count();
		l_free(query_length,query);
		char buf[256];
		sprintf(buf,"SELECT %d AS 'COUNT(*)'", cnt);
		query=l_strdup(buf);
		query_length=strlen(query)+1;
		goto __run_query;
	}

	// if the client simply executes:
	// SELECT COUNT(*) FROM runtime_pgsql_query_rules_fast_routing
	// we just return the count
	if (strcmp("SELECT COUNT(*) FROM runtime_pgsql_query_rules_fast_routing", query_no_space) == 0) {
		int cnt = GloPgQPro->get_current_query_rules_fast_routing_count();
		l_free(query_length, query);
		char buf[256];
		sprintf(buf, "SELECT %d AS 'COUNT(*)'", cnt);
		query = l_strdup(buf);
		query_length = strlen(query) + 1;
		goto __run_query;
	}

	if (!strncasecmp("TRUNCATE ", query_no_space, strlen("TRUNCATE "))) {
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
			if (strstr(query_no_space,"stats_mysql_query_digest")) {
				bool truncate_digest_table = false;
				static char * truncate_digest_table_queries[] = {
					(char *)"TRUNCATE TABLE stats.stats_mysql_query_digest",
					(char *)"TRUNCATE TABLE stats.stats_mysql_query_digest_reset",
					(char *)"TRUNCATE TABLE stats_mysql_query_digest",
					(char *)"TRUNCATE TABLE stats_mysql_query_digest_reset",
					(char *)"TRUNCATE stats.stats_mysql_query_digest",
					(char *)"TRUNCATE stats.stats_mysql_query_digest_reset",
					(char *)"TRUNCATE stats_mysql_query_digest",
					(char *)"TRUNCATE stats_mysql_query_digest_reset"
				};
				size_t l=sizeof(truncate_digest_table_queries)/sizeof(char *);
				unsigned int i;
				for (i=0;i<l;i++) {
					if (truncate_digest_table == false) {
						if (strcasecmp(truncate_digest_table_queries[i], query_no_space)==0) {
							truncate_digest_table = true;
						}
					}
				}
				if (truncate_digest_table==true) {
					ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
					SPA->admindb->execute("DELETE FROM stats.stats_mysql_query_digest");
					SPA->admindb->execute("DELETE FROM stats.stats_mysql_query_digest_reset");
					SPA->vacuum_stats(true);
					// purge the digest map, asynchronously, in single thread
					char *msg = NULL;
					int r1 = ProxySQL_Test___PurgeDigestTable<SERVER_TYPE_MYSQL>(true, false, &msg);
					SPA->send_ok_msg_to_client(sess, msg, r1, query_no_space);
					free(msg);
					run_query=false;
					goto __run_query;
				}
			}

			if (strstr(query_no_space, "stats_pgsql_query_digest")) {
				bool truncate_digest_table = false;
				static char* truncate_digest_table_queries[] = {
					(char*)"TRUNCATE TABLE stats.stats_pgsql_query_digest",
					(char*)"TRUNCATE TABLE stats.stats_pgsql_query_digest_reset",
					(char*)"TRUNCATE TABLE stats_pgsql_query_digest",
					(char*)"TRUNCATE TABLE stats_pgsql_query_digest_reset",
					(char*)"TRUNCATE stats.stats_pgsql_query_digest",
					(char*)"TRUNCATE stats.stats_pgsql_query_digest_reset",
					(char*)"TRUNCATE stats_pgsql_query_digest",
					(char*)"TRUNCATE stats_pgsql_query_digest_reset"
				};
				size_t l = sizeof(truncate_digest_table_queries) / sizeof(char*);
				unsigned int i;
				for (i = 0; i < l; i++) {
					if (truncate_digest_table == false) {
						if (strcasecmp(truncate_digest_table_queries[i], query_no_space) == 0) {
							truncate_digest_table = true;
						}
					}
				}
				if (truncate_digest_table == true) {
					ProxySQL_Admin* SPA = (ProxySQL_Admin*)pa;
					SPA->admindb->execute("DELETE FROM stats.stats_pgsql_query_digest");
					SPA->admindb->execute("DELETE FROM stats.stats_pgsql_query_digest_reset");
					SPA->vacuum_stats(true);
					// purge the digest map, asynchronously, in single thread
					char* msg = NULL;
					int r1 = ProxySQL_Test___PurgeDigestTable<SERVER_TYPE_PGSQL>(true, false, &msg);
					SPA->send_ok_msg_to_client(sess, msg, r1, query_no_space);
					free(msg);
					run_query = false;
					goto __run_query;
				}
			}
		}
	}
#ifdef DEBUG
	/**
	 * @brief Handles the 'PROXYSQL_SIMULATOR' command. Performing the operation specified in the payload
	 *   format.
	 * @details The 'PROXYSQL_SIMULATOR' command is specified the following format. Allowing to perform a
	 *   certain internal state changing operation. Payload spec:
	 *   ```
	 *   PROXYSQL_SIMULATOR ${operation} ${hg} ${address}:${port} ${operation_params}
	 *   ```
	 *
	 *   Supported operations include:
	 *     - mysql_error: Find the server specified by 'hostname:port' in the specified hostgroup and calls
	 *       'MySrvC::connect_error()' with the provider 'error_code'.
	 *
	 *   Payload example:
	 *   ```
	 *   PROXYSQL_SIMULATOR mysql_error 1 127.0.0.1 3306 1234
	 *   ```
	 */
	if (!strncasecmp("PROXYSQL_SIMULATOR ", query_no_space, strlen("PROXYSQL_SIMULATOR "))) {
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
			proxy_warning("Received PROXYSQL_SIMULATOR command: %s\n", query_no_space);

			re2::RE2::Options opts = re2::RE2::Options(RE2::Quiet);
			re2::RE2 pattern("\\s*(\\w+) (\\d+) (\\d+\\.\\d+\\.\\d+\\.\\d+):(\\d+) (\\d+)\\s*\\;*", opts);
			re2::StringPiece input(query_no_space + strlen("PROXYSQL_SIMULATOR"));

			std::string command, s_hg, srv_addr, s_port, s_errcode {};
			bool c_res = re2::RE2::Consume(&input, pattern, &command, &s_hg, &srv_addr, &s_port, &s_errcode);

			long i_hg = 0;
			long i_port = 0;
			long i_errcode = 0;

			if (c_res == true) {
				char* endptr = nullptr;
				i_hg = std::strtol(s_hg.c_str(), &endptr, 10);
				if (errno == ERANGE || errno == EINVAL) i_hg = LONG_MIN;
				i_port = std::strtol(s_port.c_str(), &endptr, 10);
				if (errno == ERANGE || errno == EINVAL) i_port = LONG_MIN;
				i_errcode = std::strtol(s_errcode.c_str(), &endptr, 10);
				if (errno == ERANGE || errno == EINVAL) i_errcode = LONG_MIN;
			}

			if (c_res == true && i_hg != LONG_MIN && i_port != LONG_MIN && i_errcode != LONG_MIN) {
				if constexpr (std::is_same_v<S, MySQL_Session>) {
					MyHGM->wrlock();

					MySrvC* mysrvc = MyHGM->find_server_in_hg(i_hg, srv_addr, i_port);
					if (mysrvc != nullptr) {
						int backup_shun_on_failures;			
						backup_shun_on_failures = mysql_thread___shun_on_failures;
						mysql_thread___shun_on_failures = 1;
						// Set the error twice to surpass 'mysql_thread___shun_on_failures' value.
						mysrvc->connect_error(i_errcode, false);
						mysrvc->connect_error(i_errcode, false);
						mysql_thread___shun_on_failures = backup_shun_on_failures;
						SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
					} else {
						std::string t_err_msg{ "Supplied server '%s:%d' wasn't found in hg '%d'" };
						std::string err_msg{};
						string_format(t_err_msg, err_msg, srv_addr.c_str(), i_port, i_hg);

						proxy_info("%s\n", err_msg.c_str());
						SPA->send_error_msg_to_client(sess, const_cast<char*>(err_msg.c_str()));
					}
					MyHGM->wrunlock();
				} else if constexpr (std::is_same_v<S, PgSQL_Session>) {
					PgHGM->wrlock();

					PgSQL_SrvC* pgsrvc = PgHGM->find_server_in_hg(i_hg, srv_addr, i_port);

					if (pgsrvc != nullptr) {
						int backup_shun_on_failures;
						backup_shun_on_failures = pgsql_thread___shun_on_failures;
						pgsql_thread___shun_on_failures = 1;
						// Set the error twice to surpass 'pgsql_thread___shun_on_failures' value.
						pgsrvc->connect_error(i_errcode, false);
						pgsrvc->connect_error(i_errcode, false);
						pgsql_thread___shun_on_failures = backup_shun_on_failures;
						SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
					} else {
						std::string t_err_msg{ "Supplied server '%s:%d' wasn't found in hg '%d'" };
						std::string err_msg{};
						string_format(t_err_msg, err_msg, srv_addr.c_str(), i_port, i_hg);

						proxy_info("%s\n", err_msg.c_str());
						SPA->send_error_msg_to_client(sess, const_cast<char*>(err_msg.c_str()));
					}
					PgHGM->wrunlock();
				} else {
					assert(0);
				}
			} else {
				SPA->send_error_msg_to_client(sess, (char*)"Invalid arguments supplied with query 'PROXYSQL_SIMULATOR'");
			}

			run_query=false;
			goto __run_query;
		}
	}
#endif // DEBUG
	if (!strncasecmp("PROXYSQLTEST ", query_no_space, strlen("PROXYSQLTEST "))) {
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
			ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
			SPA->ProxySQL_Test_Handler(SPA, sess, query_no_space, run_query);
			goto __run_query;
		}
	}
	{
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		needs_vacuum = SPA->GenericRefreshStatistics(query_no_space,query_no_space_length, ( sess->session_type == PROXYSQL_SESSION_ADMIN ? true : false )  );
	}


	if (!strncasecmp("SHOW GLOBAL VARIABLES LIKE 'read_only'", query_no_space, strlen("SHOW GLOBAL VARIABLES LIKE 'read_only'"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT 'read_only' Variable_name, '%s' Value FROM global_variables WHERE Variable_name='admin-read_only'";
		query_length=strlen(q)+5;
		query=(char *)l_alloc(query_length);
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		bool ro=SPA->get_read_only();
		//sprintf(query,q,( ro ? "ON" : "OFF"));
		PtrSize_t pkt_2;
		if (ro) {
			pkt_2.size=110;
			pkt_2.ptr=l_alloc(pkt_2.size);
			memcpy(pkt_2.ptr,READ_ONLY_ON,pkt_2.size);
		} else {
			pkt_2.size=111;
			pkt_2.ptr=l_alloc(pkt_2.size);
			memcpy(pkt_2.ptr,READ_ONLY_OFF,pkt_2.size);
		}
		sess->status=WAITING_CLIENT_DATA;
		sess->client_myds->DSS=STATE_SLEEP;
		sess->client_myds->PSarrayOUT->add(pkt_2.ptr,pkt_2.size);
		run_query=false;
		goto __run_query;
	}

	if (!strncasecmp("SELECT @@global.read_only", query_no_space, strlen("SELECT @@global.read_only"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT 'read_only' Variable_name, '%s' Value FROM global_variables WHERE Variable_name='admin-read_only'";
		query_length=strlen(q)+5;
		query=(char *)l_alloc(query_length);
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		bool ro=SPA->get_read_only();
		//sprintf(query,q,( ro ? "ON" : "OFF"));
		PtrSize_t pkt_2;
		if (ro) {
			pkt_2.size=73;
			pkt_2.ptr=l_alloc(pkt_2.size);
			memcpy(pkt_2.ptr,READ_ONLY_1,pkt_2.size);
		} else {
			pkt_2.size=73;
			pkt_2.ptr=l_alloc(pkt_2.size);
			memcpy(pkt_2.ptr,READ_ONLY_0,pkt_2.size);
		}
		sess->status=WAITING_CLIENT_DATA;
		sess->client_myds->DSS=STATE_SLEEP;
		sess->client_myds->PSarrayOUT->add(pkt_2.ptr,pkt_2.size);
		run_query=false;
		goto __run_query;
	}

	if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
		if ((query_no_space_length>13) && (!strncasecmp("PULL VERSION ", query_no_space, 13))) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received PULL command\n");
			if ((query_no_space_length>27) && (!strncasecmp("PULL VERSION MYSQL SERVERS ", query_no_space, 27))) {
				proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received PULL VERSION MYSQL SERVERS command\n");
				unsigned int wait_mysql_servers_version = 0;
				unsigned int wait_timeout = 0;
				int rc = sscanf(query_no_space+27,"%u %u",&wait_mysql_servers_version, &wait_timeout);
				if (rc < 2) {
					SPA->send_error_msg_to_client(sess, (char *)"Invalid argument");
					run_query=false;
					goto __run_query;
				} else {
					MyHGM->wait_servers_table_version(wait_mysql_servers_version, wait_timeout);
					l_free(query_length,query);
					unsigned int curver = MyHGM->get_servers_table_version();
					char buf[256];
					sprintf(buf,"SELECT %u AS 'version'", curver);
					query=l_strdup(buf);
					query_length=strlen(query)+1;
					//SPA->send_ok_msg_to_client(sess,  , NULL);
					//run_query=false;
					goto __run_query;
				}
			}
		}


		if ((query_no_space_length == strlen("SELECT GLOBAL_CHECKSUM()")) && (!strncasecmp("SELECT GLOBAL_CHECKSUM()", query_no_space, strlen("SELECT GLOBAL_CHECKSUM()")))) {
			char buf[32];
			pthread_mutex_lock(&GloVars.checksum_mutex);
			sprintf(buf,"%lu",GloVars.checksums_values.global_checksum);
			pthread_mutex_unlock(&GloVars.checksum_mutex);
			uint16_t setStatus = 0;
			auto *myds=sess->client_myds;
			auto *myprot=&sess->client_myds->myprot;
			myds->DSS=STATE_QUERY_SENT_DS;
			int sid=1;
			myprot->generate_pkt_column_count(true,NULL,NULL,sid,1); sid++;
			myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",(char *)"CHECKSUM",(char *)"",63,31,MYSQL_TYPE_LONGLONG,161,0,false,0,NULL); sid++;
			myds->DSS=STATE_COLUMN_DEFINITION;
			myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
			char **p=(char **)malloc(sizeof(char*)*1);
			unsigned long *l=(unsigned long *)malloc(sizeof(unsigned long *)*1);
			l[0]=strlen(buf);;
			p[0]=buf;
			myprot->generate_pkt_row(true,NULL,NULL,sid,1,l,p); sid++;
			myds->DSS=STATE_ROW;
			myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
			myds->DSS=STATE_SLEEP;
			run_query=false;
			free(l);
			free(p);
			goto __run_query;
		}


		if ((query_no_space_length>8) && (!strncasecmp("PROXYSQL ", query_no_space, 8))) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received PROXYSQL command\n");
			//pthread_mutex_lock(&admin_mutex);
			run_query=admin_handler_command_proxysql(query_no_space, query_no_space_length, sess, pa);
			//pthread_mutex_unlock(&admin_mutex);
			goto __run_query;
		}
		if ((query_no_space_length>5) && ( (!strncasecmp("SAVE ", query_no_space, 5)) || (!strncasecmp("LOAD ", query_no_space, 5))) ) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received LOAD or SAVE command\n");
			run_query=admin_handler_command_load_or_save(query_no_space, query_no_space_length, sess, pa, &query, &query_length);
			goto __run_query;
		}
		if ((query_no_space_length>16) && ( (!strncasecmp("KILL CONNECTION ", query_no_space, 16)) || (!strncasecmp("KILL CONNECTION ", query_no_space, 16))) ) {
			proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received KILL CONNECTION command\n");
			run_query=admin_handler_command_kill_connection(query_no_space, query_no_space_length, sess, pa);
			goto __run_query;
		}


	// queries generated by mysqldump
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (
			!strncmp("/*!40014 SET ", query_no_space, 13) ||
			!strncmp("/*!40101 SET ", query_no_space, 13) ||
			!strncmp("/*!40103 SET ", query_no_space, 13) ||
			!strncmp("/*!40111 SET ", query_no_space, 13) ||
			!strncmp("/*!80000 SET ", query_no_space, 13) ||
			!strncmp("/*!50503 SET ", query_no_space, 13) ||
			!strncmp("/*!50717 SET ", query_no_space, 13) ||
			!strncmp("/*!50717 SELECT ", query_no_space, strlen("/*!50717 SELECT ")) ||
			!strncmp("/*!50717 PREPARE ", query_no_space, strlen("/*!50717 PREPARE ")) ||
			!strncmp("/*!50717 EXECUTE ", query_no_space, strlen("/*!50717 EXECUTE ")) ||
			!strncmp("/*!50717 DEALLOCATE ", query_no_space, strlen("/*!50717 DEALLOCATE ")) ||
			!strncmp("/*!50112 SET ", query_no_space, strlen("/*!50112 SET ")) ||
			!strncmp("/*!50112 PREPARE ", query_no_space, strlen("/*!50112 PREPARE ")) ||
			!strncmp("/*!50112 EXECUTE ", query_no_space, strlen("/*!50112 EXECUTE ")) ||
			!strncmp("/*!50112 DEALLOCATE ", query_no_space, strlen("/*!50112 DEALLOCATE ")) ||
			!strncmp("/*!40000 ALTER TABLE", query_no_space, strlen("/*!40000 ALTER TABLE"))
				||
			!strncmp("/*!40100 SET @@SQL_MODE='' */", query_no_space, strlen("/*!40100 SET @@SQL_MODE='' */"))
				||
			!strncmp("/*!40103 SET TIME_ZONE=", query_no_space, strlen("/*!40103 SET TIME_ZONE="))
				||
			!strncmp("LOCK TABLES", query_no_space, strlen("LOCK TABLES"))
				||
			!strncmp("UNLOCK TABLES", query_no_space, strlen("UNLOCK TABLES"))
				||
			!strncmp("SET SQL_QUOTE_SHOW_CREATE=1", query_no_space, strlen("SET SQL_QUOTE_SHOW_CREATE=1"))
				||
			!strncmp("SET SESSION character_set_results", query_no_space, strlen("SET SESSION character_set_results"))
				||
			!strncasecmp("USE ", query_no_space, strlen("USE ")) // this applies to all clients, not only mysqldump
		) {
			SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
			run_query=false;
			goto __run_query;
		}

		if (!strncmp("SHOW STATUS LIKE 'binlog_snapshot_gtid_executed'", query_no_space, strlen("SHOW STATUS LIKE 'binlog_snapshot_gtid_executed'"))) {
			l_free(query_length, query);
			query = l_strdup("SELECT variable_name AS Variable_name, Variable_value AS Value FROM global_variables WHERE 1=0");
			query_length = strlen(query)+1;
			goto __run_query;
		}
		if (!strncmp("SELECT COLUMN_NAME, JSON_EXTRACT(HISTOGRAM, '$.\"number-of-buckets-specified\"') FROM information_schema.COLUMN_STATISTICS", query_no_space, strlen("SELECT COLUMN_NAME, JSON_EXTRACT(HISTOGRAM, '$.\"number-of-buckets-specified\"') FROM information_schema.COLUMN_STATISTICS"))) {
			l_free(query_length, query);
			query = l_strdup("SELECT variable_name AS COLUMN_NAME, Variable_value AS 'JSON_EXTRACT(HISTOGRAM, ''$.\"number-of-buckets-specified\"'')' FROM global_variables WHERE 1=0");
			query_length = strlen(query)+1;
			goto __run_query;
		}
		if (!strncmp("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = 'performance_schema' AND table_name = 'session_variables'", query_no_space, strlen("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema = 'performance_schema' AND table_name = 'session_variables'")))  {
			l_free(query_length,query);
			query=l_strdup("SELECT 0 as 'COUNT(*)'");
			query_length=strlen(query)+1;
			goto __run_query;
		}
		if (!strncmp("SHOW VARIABLES LIKE 'gtid\\_mode'", query_no_space, strlen("SHOW VARIABLES LIKE 'gtid\\_mode'"))) {
			l_free(query_length,query);
			query=l_strdup("SELECT variable_name Variable_name, Variable_value Value FROM global_variables WHERE Variable_name='gtid_mode'");
			query_length=strlen(query)+1;
			goto __run_query;
		}
		if (!strncmp("select @@collation_database", query_no_space, strlen("select @@collation_database"))) {
			l_free(query_length,query);
			query=l_strdup("SELECT Collation '@@collation_database' FROM mysql_collations WHERE Collation='utf8_general_ci' LIMIT 1");
			query_length=strlen(query)+1;
			goto __run_query;
		}
		if (!strncmp("SHOW VARIABLES LIKE 'ndbinfo\\_version'", query_no_space, strlen("SHOW VARIABLES LIKE 'ndbinfo\\_version'"))) {
			l_free(query_length,query);
			query=l_strdup("SELECT variable_name Variable_name, Variable_value Value FROM global_variables WHERE Variable_name='ndbinfo_version'");
			query_length=strlen(query)+1;
			goto __run_query;
		}
		if (!strncasecmp("show table status like '", query_no_space, strlen("show table status like '"))) {
			char *strA=query_no_space+24;
			int strAl=strlen(strA);
			if (strAl<2) { // error
				goto __run_query;
			}
			char *err=NULL;
			SQLite3_result *resultset=SPA->generate_show_table_status(strA, &err);
			sess->SQLite3_to_MySQL(resultset, err, 0, &sess->client_myds->myprot);
			if (resultset) delete resultset;
			if (err) free(err);
			run_query=false;
			goto __run_query;
		}
		if (!strncasecmp("show fields from ", query_no_space, strlen("show fields from "))) {
			char *strA=query_no_space+17;
			int strAl=strlen(strA);
			if (strAl==0) { // error
				goto __run_query;
			}
			if (strA[0]=='`') {
				strA++;
				strAl--;
			}
			if (strAl<2) { // error
				goto __run_query;
			}
			char *err=NULL;
			SQLite3_result *resultset=SPA->generate_show_fields_from(strA, &err);
			sess->SQLite3_to_MySQL(resultset, err, 0, &sess->client_myds->myprot);
			if (resultset) delete resultset;
			if (err) free(err);
			run_query=false;
			goto __run_query;
		}
	}

	// FIXME: this should be removed, it is just a POC for issue #253 . What is important is the call to GloMTH->signal_all_threads();
	if (!strncasecmp("SIGNAL MYSQL THREADS", query_no_space, strlen("SIGNAL MYSQL THREADS"))) {
		GloMTH->signal_all_threads();
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received %s command\n", query_no_space);
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		SPA->save_admin_variables_from_runtime();
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Sent signal to all mysql threads\n");
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		run_query=false;
		goto __run_query;
	}

	// fix bug #442
	if (!strncmp("SET SQL_SAFE_UPDATES=1", query_no_space, strlen("SET SQL_SAFE_UPDATES=1"))) {
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		run_query=false;
		goto __run_query;
	}

	// fix bug #1047
	if (
		(!strncasecmp("BEGIN", query_no_space, strlen("BEGIN")))
		||
		(!strncasecmp("START TRANSACTION", query_no_space, strlen("START TRANSACTION")))
		||
		(!strncasecmp("COMMIT", query_no_space, strlen("COMMIT")))
		||
		(!strncasecmp("ROLLBACK", query_no_space, strlen("ROLLBACK")))
		||
		(!strncasecmp("SET character_set_results", query_no_space, strlen("SET character_set_results")))
		||
		(!strncasecmp("SET SQL_AUTO_IS_NULL", query_no_space, strlen("SET SQL_AUTO_IS_NULL")))
		||
		(!strncasecmp("SET NAMES", query_no_space, strlen("SET NAMES")))
		||
		(!strncasecmp("SET AUTOCOMMIT", query_no_space, strlen("SET AUTOCOMMIT")))
	) {
		SPA->send_ok_msg_to_client(sess, NULL, 0, query_no_space);
		run_query=false;
		goto __run_query;
	}

	// MySQL client check command for dollars quote support, starting at version '8.1.0'. See #4300.
	if (!strncasecmp("SELECT $$", query_no_space, strlen("SELECT $$"))) {
		pair<int,const char*> err_info { get_dollar_quote_error(mysql_thread___server_version) };
		SPA->send_error_msg_to_client(sess, const_cast<char*>(err_info.second), err_info.first);
		run_query=false;
		goto __run_query;
	}

	if (query_no_space_length==SELECT_VERSION_COMMENT_LEN) {
		if (!strncasecmp(SELECT_VERSION_COMMENT, query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			query=l_strdup("SELECT '(ProxySQL Admin Module)'");
			query_length=strlen(query)+1;
			goto __run_query;
		}
	}

	if (!strncasecmp("select concat(@@version, ' ', @@version_comment)", query_no_space, strlen("select concat(@@version, ' ', @@version_comment)"))) {
		l_free(query_length,query);
		char *q = const_cast<char*>("SELECT '%s Admin Module'");
		query_length = strlen(q) + strlen(PROXYSQL_VERSION) + 1;
		query = static_cast<char*>(l_alloc(query_length));
		sprintf(query, q, PROXYSQL_VERSION);
		goto __run_query;
	}

	// add support for SELECT current_user() and SELECT user()
	// see https://github.com/sysown/proxysql/issues/1105#issuecomment-990940585
	if (
		(strcasecmp("SELECT current_user()", query_no_space) == 0)
		||
		(strcasecmp("SELECT user()", query_no_space) == 0)
	) {
		bool current = false;
		if (strcasestr(query_no_space, "current") != NULL)
			current = true;
		l_free(query_length,query);
		std::string s = "SELECT '";
		s += sess->client_myds->myconn->userinfo->username ;
		if (strlen(sess->client_myds->addr.addr) > 0) {
			s += "@";
			s += sess->client_myds->addr.addr;
		}
		s += "' AS '";
		if (current == true) {
			s+= "current_";
		}
		s += "user()'";
		query=l_strdup(s.c_str());
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (!strncasecmp("select @@sql_mode", query_no_space, strlen("select @@sql_mode"))) {
		l_free(query_length,query);
		char *q = const_cast<char*>("SELECT \"\" as \"@@sql_mode\"");
		query_length = strlen(q) + strlen(PROXYSQL_VERSION) + 1;
		query = static_cast<char*>(l_alloc(query_length));
		sprintf(query, q, PROXYSQL_VERSION);
		goto __run_query;
	}

	// trivial implementation for 'connection_id()' to support 'mycli'. See #3247
	if (!strncasecmp("select connection_id()", query_no_space, strlen("select connection_id()"))) {
		l_free(query_length,query);
		// 'connection_id()' is always forced to be '0'
		query=l_strdup("SELECT 0 AS 'CONNECTION_ID()'");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	// implementation for 'SELECT TIMEDIFF(NOW(), UTC_TIMESTAMP())' in order to support'csharp' connector. See #2543
	if (!strncasecmp("SELECT TIMEDIFF(NOW(), UTC_TIMESTAMP())", query_no_space, strlen("SELECT TIMEDIFF(NOW(), UTC_TIMESTAMP())"))) {
		l_free(query_length,query);
		char *query1=(char*)"SELECT '%s' as 'TIMEDIFF(NOW(), UTC_TIMESTAMP()'";

		// compute the timezone diff
		std::string timezone_offset_str = timediff_timezone_offset();
		char *query2=(char *)malloc(strlen(query1) + strlen(timezone_offset_str.c_str()) + 1);

		// format the query
		sprintf(query2, query1, timezone_offset_str.c_str());

		// copy the resulting query
		query=l_strdup(query2);
		query_length=strlen(query2) + 1;

		// free the buffer used to format
		free(query2);
		goto __run_query;
	}

	// implementation for '"select @@max_allowed_packet, @@character_set_client, @@character_set_connection, @@license, @@sql_mode, @@lower_case_table_names"'
	// in order to support 'csharp' connector. See #2543
	if (
		!strncasecmp(
			"select @@max_allowed_packet, @@character_set_client, @@character_set_connection, @@license, @@sql_mode, @@lower_case_table_names",
			query_no_space,
			strlen("select @@max_allowed_packet, @@character_set_client, @@character_set_connection, @@license, @@sql_mode, @@lower_case_table_names")
		)
	) {
		l_free(query_length,query);
		char *query1=
			const_cast<char*>(
				"select '67108864' as '@@max_allowed_packet', 'utf8' as '@@character_set_client', 'utf8' as '@@character_set_connection', '' as '@@license', '' as '@@sql_mode', '' as '@@lower_case_table_names'"
			);
		query=l_strdup(query1);
		query_length=strlen(query1)+1;
		goto __run_query;
	}

	if (query_no_space_length==SELECT_DB_USER_LEN) {
		if (!strncasecmp(SELECT_DB_USER, query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			char *query1=(char *)"SELECT \"admin\" AS 'DATABASE()', \"%s\" AS 'USER()'";
			char *query2=(char *)malloc(strlen(query1)+strlen(sess->client_myds->myconn->userinfo->username)+10);
			sprintf(query2,query1,sess->client_myds->myconn->userinfo->username);
			query=l_strdup(query2);
			query_length=strlen(query2)+1;
			free(query2);
			goto __run_query;
		}
	}

	if (query_no_space_length==SELECT_CHARSET_VARIOUS_LEN) {
		if (!strncasecmp(SELECT_CHARSET_VARIOUS, query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			char *query1=(char *)"select 'utf8' as '@@character_set_client', 'utf8' as '@@character_set_connection', 'utf8' as '@@character_set_server', 'utf8' as '@@character_set_database' limit 1";
			query=l_strdup(query1);
			query_length=strlen(query1)+1;
			goto __run_query;
		}
	}

	if (!strncasecmp("SELECT @@version", query_no_space, strlen("SELECT @@version"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT '%s' AS '@@version'";
		if (GloMyLdapAuth == nullptr) {
			query_length=strlen(q)+20+strlen(PROXYSQL_VERSION);
		} else {
			query_length=strlen(q)+20+strlen(PROXYSQL_VERSION)+strlen("-Enterprise");
		}
		query=(char *)l_alloc(query_length);
		if (GloMyLdapAuth == nullptr) {
			sprintf(query, q, PROXYSQL_VERSION);
		} else {
			sprintf(query, q, PROXYSQL_VERSION"-Enterprise");
		}
		goto __run_query;
	}

	if (!strncasecmp("SELECT version()", query_no_space, strlen("SELECT version()"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT '%s' AS 'version()'";
		if (GloMyLdapAuth == nullptr) {
			query_length=strlen(q)+20+strlen(PROXYSQL_VERSION);
		} else {
			query_length=strlen(q)+20+strlen(PROXYSQL_VERSION)+strlen("-Enterprise");
		}
		query=(char *)l_alloc(query_length);
		if (GloMyLdapAuth == nullptr) {
			sprintf(query, q, PROXYSQL_VERSION);
		} else {
			sprintf(query, q, PROXYSQL_VERSION"-Enterprise");
		}
		goto __run_query;
	}

	if (!strncasecmp("SHOW VARIABLES WHERE Variable_name in", query_no_space, strlen("SHOW VARIABLES WHERE Variable_name in"))) {
		// Allow MariaDB ConnectorJ to connect to Admin #743
		if (!strncasecmp("SHOW VARIABLES WHERE Variable_name in ('max_allowed_packet','system_time_zone','time_zone','sql_mode')", query_no_space, strlen("SHOW VARIABLES WHERE Variable_name in ('max_allowed_packet','system_time_zone','time_zone','sql_mode')"))) {
			l_free(query_length,query);
			char *q=(char *)"SELECT 'max_allowed_packet' Variable_name,'4194304' Value UNION ALL SELECT 'sql_mode', 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' UNION ALL SELECT 'system_time_zone', 'UTC' UNION ALL SELECT 'time_zone','SYSTEM'";
			query_length=strlen(q)+20;
			query=(char *)l_alloc(query_length);
			sprintf(query,q,PROXYSQL_VERSION);
			goto __run_query;
		}
		// Allow MariaDB ConnectorJ 2.4.1 to connect to Admin #2009
		if (!strncasecmp("SHOW VARIABLES WHERE Variable_name in ('max_allowed_packet','system_time_zone','time_zone','auto_increment_increment')", query_no_space, strlen("SHOW VARIABLES WHERE Variable_name in ('max_allowed_packet','system_time_zone','time_zone','auto_increment_increment')"))) {
			l_free(query_length,query);
			char *q=(char *)"SELECT 'max_allowed_packet' Variable_name,'4194304' Value UNION ALL SELECT 'auto_increment_increment', '1' UNION ALL SELECT 'system_time_zone', 'UTC' UNION ALL SELECT 'time_zone','SYSTEM'";
			query_length=strlen(q)+20;
			query=(char *)l_alloc(query_length);
			sprintf(query,q,PROXYSQL_VERSION);
			goto __run_query;
		}
	}

	{
		bool rc;
		rc=RE2::PartialMatch(query_no_space,*(RE2 *)(pa->match_regexes.re[0]));
		if (rc) {
			string *new_query=new std::string(query_no_space);
			RE2::Replace(new_query,(char *)"^(\\w+)\\s+@@(\\w+)\\s*",(char *)"SELECT variable_value AS '@@max_allowed_packet' FROM global_variables WHERE variable_name='mysql-max_allowed_packet'");
			free(query);
			query_length=new_query->length()+1;
			query=(char *)malloc(query_length);
			memcpy(query,new_query->c_str(),query_length-1);
			query[query_length-1]='\0';
			delete new_query;
			goto __run_query;
		}
	}
	{
		bool rc;
		rc=RE2::PartialMatch(query_no_space,*(RE2 *)(pa->match_regexes.re[1]));
		if (rc) {
			string *new_query=new std::string(query_no_space);
			RE2::Replace(new_query,(char *)"^(\\w+)  *@@([0-9A-Za-z_-]+) *",(char *)"SELECT variable_value AS '@@\\2' FROM global_variables WHERE variable_name='\\2' COLLATE NOCASE UNION ALL SELECT variable_value AS '@@\\2' FROM stats.stats_mysql_global WHERE variable_name='\\2' COLLATE NOCASE");
			free(query);
			query_length=new_query->length()+1;
			query=(char *)malloc(query_length);
			memcpy(query,new_query->c_str(),query_length-1);
			query[query_length-1]='\0';
			GloAdmin->stats___mysql_global();
			delete new_query;
			goto __run_query;
		}
	}
	{
		bool rc;
		rc = RE2::PartialMatch(query_no_space, *(RE2*)(pa->match_regexes.re[1]));
		if (rc) {
			string* new_query = new std::string(query_no_space);
			RE2::Replace(new_query, (char*)"^(\\w+)  *@@([0-9A-Za-z_-]+) *", (char*)"SELECT variable_value AS '@@\\2' FROM global_variables WHERE variable_name='\\2' COLLATE NOCASE UNION ALL SELECT variable_value AS '@@\\2' FROM stats.stats_pgsql_global WHERE variable_name='\\2' COLLATE NOCASE");
			free(query);
			query_length = new_query->length() + 1;
			query = (char*)malloc(query_length);
			memcpy(query, new_query->c_str(), query_length - 1);
			query[query_length - 1] = '\0';
			GloAdmin->stats___pgsql_global();
			delete new_query;
			goto __run_query;
		}
	}
	{
		bool rc;
		rc=RE2::PartialMatch(query_no_space,*(RE2 *)(pa->match_regexes.re[2]));
		if (rc) {
			string *new_query=new std::string(query_no_space);
			RE2::Replace(new_query,(char *)"([Ss][Hh][Oo][Ww]\\s+[Vv][Aa][Rr][Ii][Aa][Bb][Ll][Ee][Ss]\\s+[Ww][Hh][Ee][Rr][Ee])",(char *)"SELECT variable_name AS Variable_name, variable_value AS Value FROM global_variables WHERE");
			free(query);
			query_length=new_query->length()+1;
			query=(char *)malloc(query_length);
			memcpy(query,new_query->c_str(),query_length-1);
			query[query_length-1]='\0';
			delete new_query;
			goto __run_query;
		}
	}
	{
		bool rc;
		rc=RE2::PartialMatch(query_no_space,*(RE2 *)(pa->match_regexes.re[3]));
		if (rc) {
			string *new_query=new std::string(query_no_space);
			RE2::Replace(new_query,(char *)"([Ss][Hh][Oo][Ww]\\s+[Vv][Aa][Rr][Ii][Aa][Bb][Ll][Ee][Ss]\\s+[Ll][Ii][Kk][Ee])",(char *)"SELECT variable_name AS Variable_name, variable_value AS Value FROM global_variables WHERE variable_name LIKE");
			free(query);
			query_length=new_query->length()+1;
			query=(char *)malloc(query_length);
			memcpy(query,new_query->c_str(),query_length-1);
			query[query_length-1]='\0';
			delete new_query;
			goto __run_query;
		}
	}

	if (!strncasecmp("SET ", query_no_space, 4)) {
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received SET\n");
		run_query = admin_handler_command_set(query_no_space, query_no_space_length, sess, pa, &query, &query_length);
		goto __run_query;
	}

	if(!strncasecmp("CHECKSUM ", query_no_space, 9)){
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "Received CHECKSUM command\n");
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		SQLite3_result *resultset=NULL;
		char *tablename=NULL;
		char *error=NULL;
		int affected_rows=0;
		int cols=0;
		if (strlen(query_no_space)==strlen("CHECKSUM DISK MYSQL SERVERS") && !strncasecmp("CHECKSUM DISK MYSQL SERVERS", query_no_space, strlen(query_no_space))){
			char *q=(char *)"SELECT * FROM mysql_servers ORDER BY hostgroup_id, hostname, port";
			tablename=(char *)"MYSQL SERVERS";
			SPA->configdb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if (strlen(query_no_space)==strlen("CHECKSUM DISK MYSQL USERS") && !strncasecmp("CHECKSUM DISK MYSQL USERS", query_no_space, strlen(query_no_space))){
			char *q=(char *)"SELECT * FROM mysql_users ORDER BY username";
			tablename=(char *)"MYSQL USERS";
			SPA->configdb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if (strlen(query_no_space)==strlen("CHECKSUM DISK MYSQL QUERY RULES") && !strncasecmp("CHECKSUM DISK MYSQL QUERY RULES", query_no_space, strlen(query_no_space))){
			char *q=(char *)"SELECT * FROM mysql_query_rules ORDER BY rule_id";
			tablename=(char *)"MYSQL QUERY RULES";
			SPA->configdb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if (strlen(query_no_space)==strlen("CHECKSUM DISK MYSQL VARIABLES") && !strncasecmp("CHECKSUM DISK MYSQL VARIABLES", query_no_space, strlen(query_no_space))){
			char *q=(char *)"SELECT * FROM global_variables WHERE variable_name LIKE 'mysql-%' ORDER BY variable_name";
			tablename=(char *)"MYSQL VARIABLES";
			SPA->configdb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if (strlen(query_no_space)==strlen("CHECKSUM DISK MYSQL REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM DISK MYSQL REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space))){
			char *q=(char *)"SELECT * FROM mysql_replication_hostgroups ORDER BY writer_hostgroup";
			tablename=(char *)"MYSQL REPLICATION HOSTGROUPS";
			SPA->configdb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL SERVERS") && !strncasecmp("CHECKSUM MEMORY MYSQL SERVERS", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL SERVERS") && !strncasecmp("CHECKSUM MEM MYSQL SERVERS", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MYSQL SERVERS") && !strncasecmp("CHECKSUM MYSQL SERVERS", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_servers ORDER BY hostgroup_id, hostname, port";
			tablename=(char *)"MYSQL SERVERS";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL USERS") && !strncasecmp("CHECKSUM MEMORY MYSQL USERS", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL USERS") && !strncasecmp("CHECKSUM MEM MYSQL USERS", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MYSQL USERS") && !strncasecmp("CHECKSUM MYSQL USERS", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_users ORDER BY username";
			tablename=(char *)"MYSQL USERS";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL QUERY RULES") && !strncasecmp("CHECKSUM MEMORY MYSQL QUERY RULES", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL QUERY RULES") && !strncasecmp("CHECKSUM MEM MYSQL QUERY RULES", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MYSQL QUERY RULES") && !strncasecmp("CHECKSUM MYSQL QUERY RULES", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_query_rules ORDER BY rule_id";
			tablename=(char *)"MYSQL QUERY RULES";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL VARIABLES") && !strncasecmp("CHECKSUM MEMORY MYSQL VARIABLES", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL VARIABLES") && !strncasecmp("CHECKSUM MEM MYSQL VARIABLES", query_no_space, strlen(query_no_space)))
		||
		(strlen(query_no_space)==strlen("CHECKSUM MYSQL VARIABLES") && !strncasecmp("CHECKSUM MYSQL VARIABLES", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM global_variables WHERE variable_name LIKE 'mysql-%' ORDER BY variable_name";
			tablename=(char *)"MYSQL VARIABLES";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM MEMORY MYSQL REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM MEM MYSQL REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MYSQL REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM MYSQL REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_replication_hostgroups ORDER BY writer_hostgroup";
			tablename=(char *)"MYSQL REPLICATION HOSTGROUPS";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL GROUP REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM MEMORY MYSQL GROUP REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL GROUP REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM MEM MYSQL GROUP REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MYSQL GROUP REPLICATION HOSTGROUPS") && !strncasecmp("CHECKSUM MYSQL GROUP REPLICATION HOSTGROUPS", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_group_replication_hostgroups ORDER BY writer_hostgroup";
			tablename=(char *)"MYSQL GROUP REPLICATION HOSTGROUPS";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL GALERA HOSTGROUPS") && !strncasecmp("CHECKSUM MEMORY MYSQL GALERA HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL GALERA HOSTGROUPS") && !strncasecmp("CHECKSUM MEM MYSQL GALERA HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MYSQL GALERA HOSTGROUPS") && !strncasecmp("CHECKSUM MYSQL GALERA HOSTGROUPS", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_galera_hostgroups ORDER BY writer_hostgroup";
			tablename=(char *)"MYSQL GALERA HOSTGROUPS";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}
		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL AURORA HOSTGROUPS") && !strncasecmp("CHECKSUM MEMORY MYSQL AURORA HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL AURORA HOSTGROUPS") && !strncasecmp("CHECKSUM MEM MYSQL AURORA HOSTGROUPS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MYSQL AURORA HOSTGROUPS") && !strncasecmp("CHECKSUM MYSQL AURORA HOSTGROUPS", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_aws_aurora_hostgroups ORDER BY writer_hostgroup";
			tablename=(char *)"MYSQL AURORA HOSTGROUPS";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}
		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL HOSTGROUP ATTRIBUTES") && !strncasecmp("CHECKSUM MEMORY MYSQL HOSTGROUP ATTRIBUTES", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL HOSTGROUP ATTRIBUTES") && !strncasecmp("CHECKSUM MEM MYSQL HOSTGROUP ATTRIBUTES", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MYSQL HOSTGROUP ATTRIBUTES") && !strncasecmp("CHECKSUM MYSQL HOSTGROUP ATTRIBUTES", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_hostgroup_attributes ORDER BY hostgroup_id";
			tablename=(char *)"MYSQL HOSTGROUP ATTRIBUTES";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}
		if ((strlen(query_no_space)==strlen("CHECKSUM MEMORY MYSQL SERVERS SSL PARAMS") && !strncasecmp("CHECKSUM MEMORY MYSQL SERVERS SSL PARAMS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MEM MYSQL SERVERS SSL PARAMS") && !strncasecmp("CHECKSUM MEM MYSQL SERVERS SSL PARAMS", query_no_space, strlen(query_no_space)))
			||
			(strlen(query_no_space)==strlen("CHECKSUM MYSQL SERVERS SSL PARAMS") && !strncasecmp("CHECKSUM MYSQL SERVERS SSL PARAMS", query_no_space, strlen(query_no_space)))){
			char *q=(char *)"SELECT * FROM mysql_servers_ssl_params ORDER BY hostname, port, username";
			tablename=(char *)"MYSQL HOSTGROUP ATTRIBUTES";
			SPA->admindb->execute_statement(q, &error, &cols, &affected_rows, &resultset);
		}

		if (error) {
			proxy_error("Error: %s\n", error);
			char buf[1024];
			sprintf(buf,"%s", error);
			SPA->send_error_msg_to_client(sess, buf);
			run_query=false;
		} else if (resultset) {
			l_free(query_length,query);
			char *q=(char *)"SELECT '%s' AS 'table', '%s' AS 'checksum'";
			char *checksum=(char *)resultset->checksum();
			query=(char *)malloc(strlen(q)+strlen(tablename)+strlen(checksum)+1);
			sprintf(query,q,tablename,checksum);
			query_length = strlen(query);
			free(checksum);
			delete resultset;
		}
		goto __run_query;
	}

	if (!strncasecmp("SELECT CONFIG INTO OUTFILE", query_no_space, strlen("SELECT CONFIG INTO OUTFILE"))) {
		std::string fileName = query_no_space + strlen("SELECT CONFIG INTO OUTFILE");
		fileName.erase(0, fileName.find_first_not_of("\t\n\v\f\r "));
		fileName.erase(fileName.find_last_not_of("\t\n\v\f\r ") + 1);
		if (fileName.size() == 0) {
			std::stringstream ss;
			ss << "ProxySQL Admin Error: empty file name";
			sess->SQLite3_to_MySQL(resultset, (char*)ss.str().c_str(), affected_rows, &sess->client_myds->myprot);
		}
		std::string data;
		data.reserve(100000);
		data += config_header;
		int rc = pa->proxysql_config().Write_Global_Variables_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Users_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Query_Rules_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Servers_to_configfile(data);
		rc = pa->proxysql_config().Write_PgSQL_Users_to_configfile(data);
		rc = pa->proxysql_config().Write_PgSQL_Query_Rules_to_configfile(data);
		rc = pa->proxysql_config().Write_PgSQL_Servers_to_configfile(data);
		rc = pa->proxysql_config().Write_Scheduler_to_configfile(data);
		rc = pa->proxysql_config().Write_Restapi_to_configfile(data);
		rc = pa->proxysql_config().Write_ProxySQL_Servers_to_configfile(data);
		if (rc) {
			std::stringstream ss;
			ss << "ProxySQL Admin Error: Cannot extract configuration";
			sess->SQLite3_to_MySQL(resultset, (char*)ss.str().c_str(), affected_rows, &sess->client_myds->myprot);
		} else {
			std::ofstream out;
			out.open(fileName);
			if (out.is_open()) {
				out << data;
				out.close();
				if (!out) {
					std::stringstream ss;
					ss << "ProxySQL Admin Error: Error writing file " << fileName;
					sess->SQLite3_to_MySQL(resultset, (char*)ss.str().c_str(), affected_rows, &sess->client_myds->myprot);
				} else {
					std::stringstream ss;
					ss << "File " << fileName << " is saved.";
					SPA->send_ok_msg_to_client(sess, (char*)ss.str().c_str(), data.size(), query_no_space);
				}
			} else {
				std::stringstream ss;
				ss << "ProxySQL Admin Error: Cannot open file " << fileName;
				sess->SQLite3_to_MySQL(resultset, (char*)ss.str().c_str(), affected_rows, &sess->client_myds->myprot);
			}
		}
		run_query = false;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SELECT CONFIG FILE") && !strncasecmp("SELECT CONFIG FILE", query_no_space, query_no_space_length)) {
		std::string data;
		data.reserve(100000);
		data += config_header;
		int rc = pa->proxysql_config().Write_Global_Variables_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Users_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Query_Rules_to_configfile(data);
		rc = pa->proxysql_config().Write_MySQL_Servers_to_configfile(data);
		rc = pa->proxysql_config().Write_PgSQL_Users_to_configfile(data);
		rc = pa->proxysql_config().Write_PgSQL_Query_Rules_to_configfile(data);
		rc = pa->proxysql_config().Write_PgSQL_Servers_to_configfile(data);
		rc = pa->proxysql_config().Write_Scheduler_to_configfile(data);
		rc = pa->proxysql_config().Write_Restapi_to_configfile(data);
		rc = pa->proxysql_config().Write_ProxySQL_Servers_to_configfile(data);
		if (rc) {
			std::stringstream ss;
			ss << "ProxySQL Admin Error: Cannot write proxysql.cnf";
			sess->SQLite3_to_MySQL(resultset, (char*)ss.str().c_str(), affected_rows, &sess->client_myds->myprot);
		} else {
			char *pta[1];
			pta[0]=NULL;
			pta[0]=(char*)data.c_str();
			SQLite3_result* resultset = new SQLite3_result(1);
			resultset->add_column_definition(SQLITE_TEXT,"Data");
			resultset->add_row(pta);
			sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
			delete resultset;
		}
		run_query = false;
		goto __run_query;
	}

	if (strncasecmp("SHOW ", query_no_space, 5)) {
		goto __end_show_commands; // in the next block there are only SHOW commands
	}

	if (!strncasecmp("SHOW PROMETHEUS METRICS", query_no_space, strlen("SHOW PROMETHEUS METRICS"))) {
		char* pta[1];
		pta[0] = NULL;
		SQLite3_result* resultset = new SQLite3_result(1);
		resultset->add_column_definition(SQLITE_TEXT,"Data");

		if (__sync_fetch_and_add(&GloMTH->status_variables.threads_initialized, 0) == 1) {
			auto result = pa->serial_exposer({});
			pta[0] = (char*)result.second.c_str();
			resultset->add_row(pta);
		} else {
			resultset->add_row(pta);
		}

		sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
		delete resultset;
		run_query = false;

		goto __run_query;
	}

	if (!strncasecmp("SHOW GLOBAL VARIABLES LIKE 'version'", query_no_space, strlen("SHOW GLOBAL VARIABLES LIKE 'version'"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT 'version' Variable_name, '%s' Value FROM global_variables WHERE Variable_name='admin-version'";
		query_length=strlen(q)+20+strlen(PROXYSQL_VERSION);
		query=(char *)l_alloc(query_length);
		sprintf(query,q,PROXYSQL_VERSION);
		goto __run_query;
	}


	if (query_no_space_length==strlen("SHOW TABLES") && !strncasecmp("SHOW TABLES",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT name AS tables FROM sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence') ORDER BY name");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW CHARSET") && !strncasecmp("SHOW CHARSET",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT Charset, Collation AS 'Default collation' FROM mysql_collations WHERE `Default`='Yes'");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW COLLATION") && !strncasecmp("SHOW COLLATION",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT * FROM mysql_collations");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if ((query_no_space_length>15) && (!strncasecmp("SHOW TABLES IN ", query_no_space, 15))) {
		strA=query_no_space+15;
		strAl=strlen(strA);
		strB=(char *)"SELECT name AS tables FROM %s.sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence') ORDER BY name";
		strBl=strlen(strB);
		int l=strBl+strAl-2;
		char *b=(char *)l_alloc(l+1);
		snprintf(b,l+1,strB,strA);
		b[l]=0;
		l_free(query_length,query);
		query=b;
		query_length=l+1;
		goto __run_query;
	}

	if ((query_no_space_length>17) && (!strncasecmp("SHOW TABLES FROM ", query_no_space, 17))) {
		strA=query_no_space+17;
		strAl=strlen(strA);
		strB=(char *)"SELECT name AS tables FROM %s.sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence') ORDER BY name";
		strBl=strlen(strB);
		int l=strBl+strAl-2;
		char *b=(char *)l_alloc(l+1);
		snprintf(b,l+1,strB,strA);
		b[l]=0;
		l_free(query_length,query);
		query=b;
		query_length=l+1;
		goto __run_query;
	}

	if ((query_no_space_length>17) && (!strncasecmp("SHOW TABLES LIKE ", query_no_space, 17))) {
		strA=query_no_space+17;
		strAl=strlen(strA);
		strB=(char *)"SELECT name AS tables FROM sqlite_master WHERE type='table' AND name LIKE '%s'";
		strBl=strlen(strB);
		char *tn=NULL; // tablename
		tn=(char *)malloc(strAl+1);
		unsigned int i=0, j=0;
		while (i<(unsigned int)strAl) {
			if (strA[i]!='\\' && strA[i]!='`' && strA[i]!='\'') {
				tn[j]=strA[i];
				j++;
			}
			i++;
		}
		tn[j]=0;
		int l=strBl+strlen(tn)-2;
		char *b=(char *)l_alloc(l+1);
		snprintf(b,l+1,strB,tn);
		b[l]=0;
		free(tn);
		l_free(query_length,query);
		query=b;
		query_length=l+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW MYSQL USERS") && !strncasecmp("SHOW MYSQL USERS",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT * FROM mysql_users ORDER BY username, active DESC, username ASC");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW MYSQL SERVERS") && !strncasecmp("SHOW MYSQL SERVERS",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT * FROM mysql_servers ORDER BY hostgroup_id, hostname, port");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (
		(query_no_space_length==strlen("SHOW GLOBAL VARIABLES") && !strncasecmp("SHOW GLOBAL VARIABLES",query_no_space, query_no_space_length))
		||
		(query_no_space_length==strlen("SHOW ALL VARIABLES") && !strncasecmp("SHOW ALL VARIABLES",query_no_space, query_no_space_length))
		||
		(query_no_space_length==strlen("SHOW VARIABLES") && !strncasecmp("SHOW VARIABLES",query_no_space, query_no_space_length))
	) {
		l_free(query_length,query);
		query=l_strdup("SELECT variable_name AS Variable_name, variable_value AS Value FROM global_variables ORDER BY variable_name");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (GloMyLdapAuth) {
		if (query_no_space_length==strlen("SHOW LDAP VARIABLES") && !strncasecmp("SHOW LDAP VARIABLES",query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			query=l_strdup("SELECT variable_name AS Variable_name, variable_value AS Value FROM global_variables WHERE variable_name LIKE 'ldap-\%' ORDER BY variable_name");
			query_length=strlen(query)+1;
			goto __run_query;
		}
	}

	if (query_no_space_length==strlen("SHOW ADMIN VARIABLES") && !strncasecmp("SHOW ADMIN VARIABLES",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT variable_name AS Variable_name, variable_value AS Value FROM global_variables WHERE variable_name LIKE 'admin-\%' ORDER BY variable_name");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW MYSQL VARIABLES") && !strncasecmp("SHOW MYSQL VARIABLES",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT variable_name AS Variable_name, variable_value AS Value FROM global_variables WHERE variable_name LIKE 'mysql-\%' ORDER BY variable_name");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW MYSQL STATUS") && !strncasecmp("SHOW MYSQL STATUS",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT Variable_Name AS Variable_name, Variable_Value AS Value FROM stats_mysql_global ORDER BY variable_name");
		query_length=strlen(query)+1;
		GloAdmin->stats___mysql_global();
		goto __run_query;
	}

	if (query_no_space_length == strlen("SHOW PGSQL VARIABLES") && !strncasecmp("SHOW PGSQL VARIABLES", query_no_space, query_no_space_length)) {
		l_free(query_length, query);
		query = l_strdup("SELECT variable_name AS Variable_name, variable_value AS Value FROM global_variables WHERE variable_name LIKE 'pgsql-\%' ORDER BY variable_name");
		query_length = strlen(query) + 1;
		goto __run_query;
	}

	if (query_no_space_length == strlen("SHOW PGSQL STATUS") && !strncasecmp("SHOW PGSQL STATUS", query_no_space, query_no_space_length)) {
		l_free(query_length, query);
		query = l_strdup("SELECT Variable_Name AS Variable_name, Variable_Value AS Value FROM stats_pgsql_global ORDER BY variable_name");
		query_length = strlen(query) + 1;
		GloAdmin->stats___pgsql_global();
		goto __run_query;
	}

	strA=(char *)"SHOW CREATE TABLE ";
	strB=(char *)"SELECT name AS 'table' , REPLACE(REPLACE(sql,' , ', X'2C0A20202020'),'CREATE TABLE %s (','CREATE TABLE %s ('||X'0A20202020') AS 'Create Table' FROM %s.sqlite_master WHERE type='table' AND name='%s'";
	strAl=strlen(strA);
  if (strncasecmp("SHOW CREATE TABLE ", query_no_space, strAl)==0) {
		strBl=strlen(strB);
		char *dbh=NULL;
		char *tbh=NULL;
		c_split_2(query_no_space+strAl,".",&dbh,&tbh);

		if (strlen(tbh)==0) {
			free(tbh);
			tbh=dbh;
			dbh=strdup("main");
		}
		if (strlen(tbh)>=3 && tbh[0]=='`' && tbh[strlen(tbh)-1]=='`') { // tablename is quoted
			char *tbh_tmp=(char *)malloc(strlen(tbh)-1);
			strncpy(tbh_tmp,tbh+1,strlen(tbh)-2);
			tbh_tmp[strlen(tbh)-2]=0;
			free(tbh);
			tbh=tbh_tmp;
		}
		int l=strBl+strlen(tbh)*3+strlen(dbh)-8;
		char *buff=(char *)l_alloc(l+1);
		snprintf(buff,l+1,strB,tbh,tbh,dbh,tbh);
		buff[l]=0;
		free(tbh);
		free(dbh);
		l_free(query_length,query);
		query=buff;
		query_length=l+1;
		goto __run_query;
	}

	if (
		(query_no_space_length==strlen("SHOW DATABASES") && !strncasecmp("SHOW DATABASES",query_no_space, query_no_space_length))
		||
		(query_no_space_length==strlen("SHOW SCHEMAS") && !strncasecmp("SHOW SCHEMAS",query_no_space, query_no_space_length))
	) {
		l_free(query_length,query);
		query=l_strdup("PRAGMA DATABASE_LIST");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW FULL PROCESSLIST") && !strncasecmp("SHOW FULL PROCESSLIST",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT * FROM stats_mysql_processlist");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (query_no_space_length==strlen("SHOW PROCESSLIST") && !strncasecmp("SHOW PROCESSLIST",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT SessionID, user, db, hostgroup, command, time_ms, SUBSTR(info,0,100) info FROM stats_mysql_processlist");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (query_no_space_length == strlen("SHOW FULL PGSQL PROCESSLIST") && !strncasecmp("SHOW FULL PGSQL PROCESSLIST", query_no_space, query_no_space_length)) {
		l_free(query_length, query);
		query = l_strdup("SELECT * FROM stats_pgsql_processlist");
		query_length = strlen(query) + 1;
		goto __run_query;
	}

	if (query_no_space_length == strlen("SHOW PGSQL PROCESSLIST") && !strncasecmp("SHOW PGSQL PROCESSLIST", query_no_space, query_no_space_length)) {
		l_free(query_length, query);
		query = l_strdup("SELECT SessionID, user, database, hostgroup, command, time_ms, SUBSTR(info,0,100) info FROM stats_pgsql_processlist");
		query_length = strlen(query) + 1;
		goto __run_query;
	}

__end_show_commands:

	if (query_no_space_length==strlen("SELECT DATABASE()") && !strncasecmp("SELECT DATABASE()",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
			query=l_strdup("SELECT \"admin\" AS 'DATABASE()'");
		} else {
			query=l_strdup("SELECT \"stats\" AS 'DATABASE()'");
		}
		query_length=strlen(query)+1;
		goto __run_query;
	}

	// see issue #1022
	if (query_no_space_length==strlen("SELECT DATABASE() AS name") && !strncasecmp("SELECT DATABASE() AS name",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
			query=l_strdup("SELECT \"admin\" AS 'name'");
		} else {
			query=l_strdup("SELECT \"stats\" AS 'name'");
		}
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (sess->session_type == PROXYSQL_SESSION_STATS) { // no admin
		if (
			(strncasecmp("PRAGMA",query_no_space,6)==0)
			||
			(strncasecmp("ATTACH",query_no_space,6)==0)
		) {
			proxy_error("[WARNING]: Commands executed from stats interface in Admin Module: \"%s\"\n", query_no_space);
			SPA->send_error_msg_to_client(sess, (char *)"Command not allowed");
			run_query=false;
		}
	}

__run_query:
	if (sess->proxysql_node_address && (__sync_fetch_and_add(&glovars.shutdown,0)==0)) {
		if (sess->client_myds->active) {
			const string uuid { sess->proxysql_node_address->uuid };
			const string hostname { sess->proxysql_node_address->hostname };
			const string port { std::to_string(sess->proxysql_node_address->port) };
			const string mysql_ifaces { sess->proxysql_node_address->admin_mysql_ifaces };

			time_t now = time(NULL);
			string q = "INSERT OR REPLACE INTO stats_proxysql_servers_clients_status (uuid, hostname, port, admin_mysql_ifaces, last_seen_at) VALUES (\"";
			q += uuid;
			q += "\",\"";
			q += hostname;
			q += "\",";
			q += port;
			q += ",\"";
			q += mysql_ifaces;
			q += "\",";
			q += std::to_string(now) + ")";
			SPA->statsdb->execute(q.c_str());

			std::map<string, string> m_labels { { "uuid", uuid }, { "hostname", hostname }, { "port", port } };
			const string m_id { uuid + ":" + hostname + ":" + port };

			p_update_map_gauge(
				SPA->metrics.p_proxysql_servers_clients_status_map,
				SPA->metrics.p_dyn_gauge_array[p_admin_dyn_gauge::proxysql_servers_clients_status_last_seen_at],
				m_id, m_labels, now
			);
		}
	}
	if (run_query) {
		ProxySQL_Admin *SPA=(ProxySQL_Admin *)pa;
		if (sess->session_type == PROXYSQL_SESSION_ADMIN) { // no stats
			if (SPA->get_read_only()) { // disable writes if the admin interface is in read_only mode
				SPA->admindb->execute("PRAGMA query_only = ON");
				SPA->admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
				SPA->admindb->execute("PRAGMA query_only = OFF");
			} else {
				SPA->admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
			}
			if (needs_vacuum) {
				SPA->vacuum_stats(true);
			}
		} else {
			SPA->statsdb->execute("PRAGMA query_only = ON");
			SPA->statsdb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
			SPA->statsdb->execute("PRAGMA query_only = OFF");
			if (needs_vacuum) {
				SPA->vacuum_stats(false);
			}
		}
		if (error == NULL) {

			if constexpr (std::is_same_v<S, MySQL_Session>) {
				sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
			} else if constexpr (std::is_same_v<S, PgSQL_Session>) {
				SQLite3_to_Postgres(sess->client_myds->PSarrayOUT, resultset, error, affected_rows, query);
			} else {
				assert(0);
			}
		} else {
			char *a = (char *)"ProxySQL Admin Error: ";
			char *new_msg = (char *)malloc(strlen(error)+strlen(a)+1);
			sprintf(new_msg, "%s%s", a, error);

			if constexpr (std::is_same_v<S, MySQL_Session>) {
				sess->SQLite3_to_MySQL(resultset, new_msg, affected_rows, &sess->client_myds->myprot);
			} else if constexpr (std::is_same_v<S, PgSQL_Session>) {
				SQLite3_to_Postgres(sess->client_myds->PSarrayOUT, resultset, new_msg, affected_rows, query);
			} else {
				assert(0);
			}

			free(new_msg);
			free(error);
		}
		delete resultset;
	}
	if (run_query == true) {
		pthread_mutex_unlock(&pa->sql_query_global_mutex);
	} else {
		// The admin module may have already been freed in case of "PROXYSQL STOP"
		if (strcasecmp("PROXYSQL STOP",query_no_space))
			pthread_mutex_unlock(&pa->sql_query_global_mutex);
	}
	l_free(pkt->size-sizeof(mysql_hdr),query_no_space); // it is always freed here
	l_free(query_length,query);
}

// Explicitly instantiate the required template class and member functions
template void admin_session_handler<MySQL_Session>(MySQL_Session* sess, void *_pa, PtrSize_t *pkt);
template void admin_session_handler<PgSQL_Session>(PgSQL_Session* sess, void *_pa, PtrSize_t *pkt);

