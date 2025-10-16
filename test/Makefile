#!/bin/make -f


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk


IDIRS :=	-I$(PROXYSQL_IDIR) \
			-I$(JEMALLOC_IDIR) \
			-I$(MARIADB_IDIR) \
			-I$(LIBCONFIG_IDIR) \
			-I$(RE2_IDIR) \
			-I$(SQLITE3_IDIR) \
			-I$(PCRE_IDIR) \
			-I$(SYS_LOC_IDIR) \
			-I$(CLICKHOUSE_CPP_IDIR) \
			-I$(MICROHTTPD_IDIR) \
			-I$(LIBHTTPSERVER_IDIR) \
			-I$(LIBINJECTION_IDIR) \
			-I$(CURL_IDIR) \
			-I$(EV_IDIR) \
			-I$(JSON_IDIR) \
			-I$(SSL_IDIR)


sqlite_history_convert: sqlite_history_convert.cpp
	g++ -ggdb ../lib/SpookyV2.cpp ../lib/debug.cpp ../deps/sqlite3/sqlite3/sqlite3.o sqlite_history_convert.cpp ../lib/sqlite3db.cpp -o sqlite_history_convert $(IDIRS) -pthread -ldl
