#ifndef PROXYSQL_CPP_H
#define PROXYSQL_CPP_H
#include "gen_utils.h"
#include "PgSQL_Thread.h"
#include "MySQL_Thread.h"
#include "Base_Session.h"
#include "MySQL_Session.h"
#include "PgSQL_Session.h"
#include "mysql_backend.h"
#include "PgSQL_Backend.h"
#include "ProxySQL_Poll.h"
//#include "MySQL_Data_Stream.h"
//#include "MySQL_Query_Cache.h"
#include "mysql_connection.h"
#include "sqlite3db.h"
//#include "StatCounters.h"
#include "MySQL_Monitor.hpp"
#include "PgSQL_Monitor.hpp"
//#include "MySQL_Protocol.h"
//#include "MySQL_Authentication.hpp"
//#include "MySQL_LDAP_Authentication.hpp"
#ifdef PROXYSQLCLICKHOUSE
#include "ClickHouse_Authentication.hpp"
#endif /* PROXYSQLCLICKHOUSE */
#include "fileutils.hpp"
#include "configfile.hpp"

//#include "SQLite3_Server.h"
#ifdef PROXYSQLCLICKHOUSE
#include "ClickHouse_Server.h"
#endif /* PROXYSQLCLICKHOUSE */

#ifdef PROXYSQLGENAI
#include "AI_Vector_Storage.h"
// Anomaly_Detector.h moved to plugins/genai/ in Step 3.
//
// Step 4.C moved MCP-related headers (Admin/Cache/Config/Observe/Stats/
// MCP_Tool/MySQL/Query tool handlers, MCP_Endpoint, MCP_Thread,
// ProxySQL_MCP_Server) into the plugin.  MySQL_FTS.h moved with them.
//
// Step 5 moved the GenAI/LLM/AI surface: GenAI_Thread, LLM_Bridge,
// LLM_Clients, AI_Features_Manager, AI_Tool_Handler, RAG_Tool_Handler.
// Their includes are removed from this aggregate header.
#include "Discovery_Schema.h"
#include "MySQL_Catalog.h"
#include "PgSQL_Static_Harvester.h"
#include "Static_Harvester.h"
#endif /* PROXYSQLGENAI */

#include "MySQL_HostGroups_Manager.h"
#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Connection.h"
#include "proxysql_admin.h"

//#include "MySQL_Logger.hpp"
//#include "MySQL_PreparedStatement.h"
//#include "ProxySQL_Cluster.hpp" // cluster
//#include "ProxySQL_Statistics.hpp" // statistics
//#include "ProxySQL_HTTP_Server.hpp" // HTTP server
#undef swap
#undef min
#undef max
#include <stdio.h>
#include <map>
#include <unordered_map>
#endif // PROXYSQL_CPP_H
