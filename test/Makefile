#!/bin/make -f


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)
PROXYSQL_IDIR := $(PROXYSQL_PATH)/include

DEPS_PATH := $(PROXYSQL_PATH)/deps


MARIADB_PATH := $(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR := $(MARIADB_PATH)/include

JEMALLOC_PATH := $(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR := $(JEMALLOC_PATH)/include/jemalloc

LIBCONFIG_PATH := $(DEPS_PATH)/libconfig/libconfig
LIBCONFIG_IDIR := $(LIBCONFIG_PATH)/lib

#INJECTION_PATH := $(DEPS_PATH)/libinjection
#INJECTION_IDIR := $(INJECTION_PATH)

RE2_PATH := $(DEPS_PATH)/re2/re2
RE2_IDIR := $(RE2_PATH)

PCRE_PATH := $(DEPS_PATH)/pcre/pcre
PCRE_IDIR := $(PCRE_PATH)

SQLITE3_PATH := $(DEPS_PATH)/sqlite3/sqlite3
SQLITE3_IDIR := $(SQLITE3_PATH)

CLICKHOUSE_CPP_PATH := $(DEPS_PATH)/clickhouse-cpp/clickhouse-cpp
CLICKHOUSE_CPP_IDIR := $(CLICKHOUSE_CPP_PATH)

LIBINJECTION_PATH := $(DEPS_PATH)/libinjection/libinjection
LIBINJECTION_IDIR := -I$(LIBINJECTION_PATH)/src

LIBHTTPSERVER_PATH := $(DEPS_PATH)/libhttpserver/libhttpserver
LIBHTTPSERVER_IDIR := -I$(LIBHTTPSERVER_PATH)/src

MICROHTTPD_PATH := $(DEPS_PATH)/libmicrohttpd/libmicrohttpd
MICROHTTPD_IDIR := $(MICROHTTPD_PATH)/src/include

CURL_PATH := $(DEPS_PATH)/curl/curl
CURL_IDIR := -I$(CURL_PATH)/include

SSL_PATH := $(DEPS_PATH)/libssl/openssl/
SSL_IDIR := $(SSL_PATH)/include

EV_PATH := $(DEPS_PATH)/libev/libev/
EV_IDIR := $(EV_PATH)

LOCAL_IDIR := /usr/local/include


IDIRS := -I$(PROXYSQL_IDIR)
IDIRS += -I$(JEMALLOC_IDIR)
IDIRS += -I$(MARIADB_IDIR)
IDIRS += -I$(LIBCONFIG_IDIR)
IDIRS += -I$(RE2_IDIR)
IDIRS += -I$(SQLITE3_IDIR)
IDIRS += -I$(PCRE_IDIR)
IDIRS += -I$(LOCAL_IDIR)
IDIRS += -I$(CLICKHOUSE_CPP_DIR)
IDIRS += -I$(MICROHTTPD_PATH)
IDIRS += -I$(MICROHTTPD_IDIR)
IDIRS += -I$(LIBHTTPSERVER_IDIR)
IDIRS += -I$(LIBINJECTION_IDIR)
IDIRS += -I$(CURL_IDIR)
IDIRS += -I$(EV_DIR)
IDIRS += -I$(SSL_IDIR)


sqlite_history_convert: sqlite_history_convert.cpp
	g++ -ggdb ../lib/SpookyV2.cpp ../lib/debug.cpp ../deps/sqlite3/sqlite3/sqlite3.o sqlite_history_convert.cpp ../lib/sqlite3db.cpp -o sqlite_history_convert $(IDIRS) -pthread -ldl
