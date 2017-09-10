#include "gen_utils.h"
#include "MySQL_Thread.h"
#include "MySQL_Session.h"
#include "mysql_backend.h"
#include "MySQL_Data_Stream.h"
#include "query_cache.hpp"
#include "mysql_connection.h"
#include "sqlite3db.h"
#include "StatCounters.h"
#include "MySQL_Monitor.hpp"
#include "MySQL_Protocol.h"
#include "MySQL_Authentication.hpp"
#ifdef PROXYSQLCLICKHOUSE
#include "ClickHouse_Authentication.hpp"
#endif /* PROXYSQLCLICKHOUSE */
#include "fileutils.hpp"
#include "configfile.hpp"
#include "query_processor.h"
#include "proxysql_admin.h"
#include "SQLite3_Server.h"
#ifdef PROXYSQLCLICKHOUSE
#include "ClickHouse_Server.h"
#endif /* PROXYSQLCLICKHOUSE */
#include "MySQL_HostGroups_Manager.h"
#include "MySQL_Logger.hpp"
#include "MySQL_PreparedStatement.h"
#include "ProxySQL_Cluster.hpp" // cluster
#undef swap
#undef min
#undef max
#include <stdio.h>
#include <map>
#include <unordered_map>
