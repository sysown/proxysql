#include "MySQL_HostGroups_Manager.h"
#include "MySQL_Thread.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_utils.h"
#include "re2/re2.h"
#include "re2/regexp.h"
#include "mysqld_error.h"

#include "MySQL_Data_Stream.h"
#include "query_processor.h"
#include "MySQL_PreparedStatement.h"
#include "MySQL_Logger.hpp"
#include "StatCounters.h"
#include "MySQL_Protocol.h"
#include "SQLite3_Server.h"
#include "MySQL_Variables.h"
#include "ProxySQL_Cluster.hpp"

Session_Regex::Session_Regex(char* p) {
	s = strdup(p);
	re2::RE2::Options* opt2 = new re2::RE2::Options(RE2::Quiet);
	opt2->set_case_sensitive(false);
	opt = (void*)opt2;
	re = (RE2*)new RE2(s, *opt2);
}

Session_Regex::~Session_Regex() {
	free(s);
	delete (RE2*)re;
	delete (re2::RE2::Options*)opt;
}

bool Session_Regex::match(char* m) {
	bool rc = false;
	rc = RE2::PartialMatch(m, *(RE2*)re);
	return rc;
}


std::string proxysql_session_type_str(enum proxysql_session_type session_type) {
	if (session_type == PROXYSQL_SESSION_MYSQL) {
		return "PROXYSQL_SESSION_MYSQL";
	} else if (session_type == PROXYSQL_SESSION_ADMIN) {
		return "PROXYSQL_SESSION_ADMIN";
	} else if (session_type == PROXYSQL_SESSION_STATS) {
		return "PROXYSQL_SESSION_STATS";
	} else if (session_type == PROXYSQL_SESSION_SQLITE) {
		return "PROXYSQL_SESSION_SQLITE";
	} else if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
		return "PROXYSQL_SESSION_CLICKHOUSE";
	} else if (session_type == PROXYSQL_SESSION_MYSQL_EMU) {
		return "PROXYSQL_SESSION_MYSQL_EMU";
	} else if (session_type == PROXYSQL_SESSION_PGSQL) {
		return "PROXYSQL_SESSION_PGSQL";
	} else {
		return "PROXYSQL_SESSION_NONE";
	}
};