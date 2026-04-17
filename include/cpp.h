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
#include "MCP_Tool_Handler.h"
#include "AI_Features_Manager.h"
#include "AI_Tool_Handler.h"
#include "AI_Vector_Storage.h"
#include "Admin_Tool_Handler.h"
// Anomaly_Detector.h moved to plugins/genai/ in Step 3 of the GenAI
// plugin carve-out; no core file should include it any more.
#include "Cache_Tool_Handler.h"
#include "Config_Tool_Handler.h"
#include "Discovery_Schema.h"
#include "GenAI_Thread.h"
#include "LLM_Bridge.h"
#include "MCP_Endpoint.h"
#include "MCP_Thread.h"
#include "MySQL_Catalog.h"
#include "MySQL_FTS.h"
#include "MySQL_Tool_Handler.h"
#include "Stats_Tool_Handler.h"
#include "ProxySQL_MCP_Server.hpp"
#include "Query_Tool_Handler.h"
#include "RAG_Tool_Handler.h"
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
