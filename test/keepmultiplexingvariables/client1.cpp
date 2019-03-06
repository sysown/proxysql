#include <iostream>
#include "proxysql.h"
#include "cpp.h"

Query_Cache *GloQC;
MySQL_Authentication *GloMyAuth;
Query_Processor *GloQPro;
ProxySQL_Admin *GloAdmin;
MySQL_Threads_Handler *GloMTH;

MySQL_Thread *GloMT;

MySQL_STMT_Manager_v14 *GloMyStmt;

MySQL_Monitor *GloMyMon;
std::thread *MyMon_thread = NULL;

MySQL_Logger *GloMyLogger;

SQLite3_Server *GloSQLite3Server;

ProxySQL_Cluster *GloProxyCluster = NULL;

ProxySQL_Statistics *GloProxyStats = NULL;

int main(int argc, const char * argv[]) {
    char* query_digest_text = "select @@session.tx_isolation as a,@@tx_isolation,@@tx_isolation as a,@@version";
    
    MySQL_Connection conn;
    
    mysql_thread___keep_multiplexing_variables="tx_isolation,version";
    
    std::cout << conn.IsKeepMultiplexEnabledVariables(query_digest_text);
    return 0;
}

//link and build
//c++ -c -o client1.o client1.cpp -std=c++11 -I../../include -I../../deps/jemalloc/jemalloc/include/jemalloc -I../../deps/mariadb-client-library/mariadb_client/include -I../../deps/libconfig/libconfig-1.4.9/lib -I../../deps/libdaemon/libdaemon -I../../deps/sqlite3/sqlite3 -I../../deps/clickhouse-cpp/clickhouse-cpp -I../../deps/libmicrohttpd/libmicrohttpd/src/include

//c++ -o client1 client1.o ../../src/obj/proxysql_global.o ../../lib/libproxysql.a ../../deps/libmicrohttpd/libmicrohttpd/src/microhttpd/.libs/libmicrohttpd.a ../../deps/pcre/pcre/.libs/libpcre.a ../../deps/pcre/pcre/.libs/libpcrecpp.a  ../../deps/libdaemon/libdaemon/libdaemon/.libs/libdaemon.a  ../../deps/libconfig/libconfig/lib/.libs/libconfig++.a ../../deps/libconfig/libconfig/lib/.libs/libconfig.a ../../deps/curl/curl/lib/.libs/libcurl.a ../../deps/sqlite3/sqlite3/sqlite3.o -std=c++11 -I../../include -I../../deps/jemalloc/jemalloc/include/jemalloc -I../../deps/mariadb-client-library/mariadb_client/include -I../../deps/libconfig/libconfig-1.4.9/lib -I../../deps/libdaemon/libdaemon -I../../deps/sqlite3/sqlite3 -I../../deps/clickhouse-cpp/clickhouse-cpp -I../../deps/libmicrohttpd/libmicrohttpd/src/include     -L../../lib -L../../deps/jemalloc/jemalloc/lib -L../../deps/libconfig/libconfig-1.4.9/lib/.libs -L../../deps/re2/re2/obj -L../../deps/mariadb-client-library/mariadb_client/libmariadb -L../../deps/libdaemon/libdaemon/libdaemon/.libs -L../../deps/pcre/pcre/.libs -L../../deps/libmicrohttpd/libmicrohttpd/src/microhttpd/.libs  -L/usr/local/opt/openssl/lib  -lssl -lre2 -lmariadbclient -lpthread -lm -lz -liconv -lcrypto
