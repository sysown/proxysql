DEPS_PATH=../deps


MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include

JEMALLOC_PATH=$(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR=$(JEMALLOC_PATH)/include/jemalloc

LIBCONFIG_PATH=$(DEPS_PATH)/libconfig/libconfig
LIBCONFIG_IDIR=-I$(LIBCONFIG_PATH)/lib

#INJECTION_PATH=$(DEPS_PATH)/libinjection
#INJECTION_IDIR=$(INJECTION_PATH)

RE2_PATH=$(DEPS_PATH)/re2/re2
RE2_IDIR=$(RE2_PATH)

PCRE_PATH=$(DEPS_PATH)/pcre/pcre

SQLITE3_DIR=$(DEPS_PATH)/sqlite3/sqlite3

CLICKHOUSE_CPP_DIR=$(DEPS_PATH)/clickhouse-cpp/clickhouse-cpp

LIBINJECTION_DIR=$(DEPS_PATH)/libinjection/libinjection
LIBINJECTION_IDIR=-I$(LIBINJECTION_DIR)/src

LIBHTTPSERVER_DIR=$(DEPS_PATH)/libhttpserver/libhttpserver
LIBHTTPSERVER_IDIR=-I$(LIBHTTPSERVER_DIR)/src

MICROHTTPD_DIR=$(DEPS_PATH)/libmicrohttpd/libmicrohttpd
MICROHTTPD_IDIR=-I$(MICROHTTPD_DIR) -I$(MICROHTTPD_DIR)/src/include

CURL_DIR=$(DEPS_PATH)/curl/curl
CURL_IDIR=-I$(CURL_DIR)/include

SSL_DIR=$(DEPS_PATH)/libssl/openssl/
SSL_IDIR=$(SSL_DIR)/include


EV_DIR=$(DEPS_PATH)/libev/libev/
EV_IDIR=$(EV_DIR)

IDIR=../include

IDIRS=-I$(IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) $(LIBCONFIG_IDIR) -I$(RE2_IDIR) -I$(SQLITE3_DIR) -I$(PCRE_PATH) -I/usr/local/include -I$(CLICKHOUSE_CPP_DIR) $(MICROHTTPD_IDIR) $(LIBHTTPSERVER_IDIR) $(LIBINJECTION_IDIR) $(CURL_IDIR) -I$(EV_DIR) -I$(SSL_IDIR)



sqlite_history_convert: sqlite_history_convert.cpp
	g++ -ggdb ../lib/SpookyV2.cpp ../lib/debug.cpp ../deps/sqlite3/sqlite3/sqlite3.o sqlite_history_convert.cpp ../lib/sqlite3db.cpp -o sqlite_history_convert $(IDIRS) -pthread -ldl
