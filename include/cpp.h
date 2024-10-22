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
