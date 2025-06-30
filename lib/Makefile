#!/bin/make -f


GIT_VERSION ?= $(shell git describe --long --abbrev=7)
ifndef GIT_VERSION
    $(error GIT_VERSION is not set)
endif

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

DISTRO := $(shell grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')

CENTOSVER := Unknown
ifneq (,$(wildcard /etc/system-release))
	CENTOSVER := $(shell rpm --eval %rhel)
endif

IS_ARM := $(if $(findstring aarch64, $(UNAME_M)),true,false)
IS_CENTOS := $(if $(findstring Unknown, $(CENTOSVER)),false,true)


PROXYSQL_PATH := ..
PROXYSQL_IDIR := $(PROXYSQL_PATH)/include
PROXYSQL_LDIR := $(PROXYSQL_PATH)/lib

DEPS_PATH := $(PROXYSQL_PATH)/deps

MARIADB_PATH := $(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR := $(MARIADB_PATH)/include
MARIADB_LDIR := $(MARIADB_PATH)/libmariadb

LIBDAEMON_PATH := $(DEPS_PATH)/libdaemon/libdaemon
LIBDAEMON_IDIR := $(LIBDAEMON_PATH)
LIBDAEMON_LDIR := $(LIBDAEMON_PATH)/libdaemon/.libs

JEMALLOC_PATH := $(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR := $(JEMALLOC_PATH)/include/jemalloc
JEMALLOC_LDIR := $(JEMALLOC_PATH)/lib

LIBCONFIG_PATH := $(DEPS_PATH)/libconfig/libconfig
LIBCONFIG_IDIR := $(LIBCONFIG_PATH)/lib
LIBCONFIG_LDIR := $(LIBCONFIG_PATH)/out

PROMETHEUS_PATH := $(DEPS_PATH)/prometheus-cpp/prometheus-cpp
PROMETHEUS_IDIR := $(PROMETHEUS_PATH)/pull/include -I$(PROMETHEUS_PATH)/core/include
PROMETHEUS_LDIR := $(PROMETHEUS_PATH)/lib

JSON_PATH := $(DEPS_PATH)/json
JSON_IDIR := $(JSON_PATH)

RE2_PATH := $(DEPS_PATH)/re2/re2
RE2_IDIR := $(RE2_PATH)
RE2_LDIR := $(RE2_PATH)/obj

PCRE_PATH := $(DEPS_PATH)/pcre/pcre
PCRE_IDIR := $(PCRE_PATH)
PCRE_LDIR := $(PCRE_PATH)/.libs

SQLITE3_PATH := $(DEPS_PATH)/sqlite3/sqlite3
SQLITE3_IDIR := $(SQLITE3_PATH)
SQLITE3_LDIR := $(SQLITE3_PATH)

CITYHASH_PATH := $(DEPS_PATH)/cityhash/cityhash
CITYHASH_LDIR := $(CITYHASH_PATH)/src/.libs

LZ4_PATH := $(DEPS_PATH)/lz4/lz4
LZ4_LDIR := $(LZ4_PATH)/lib

CLICKHOUSE_CPP_PATH := $(DEPS_PATH)/clickhouse-cpp/clickhouse-cpp
CLICKHOUSE_CPP_IDIR := $(CLICKHOUSE_CPP_PATH) -I$(CLICKHOUSE_CPP_PATH)/contrib -I$(CLICKHOUSE_CPP_PATH)/contrib/absl
CLICKHOUSE_CPP_LDIR := $(CLICKHOUSE_CPP_PATH)/clickhouse

LIBINJECTION_PATH := $(DEPS_PATH)/libinjection/libinjection
LIBINJECTION_IDIR := $(LIBINJECTION_PATH)/src
LIBINJECTION_LDIR := $(LIBINJECTION_PATH)/src

LIBHTTPSERVER_PATH := $(DEPS_PATH)/libhttpserver/libhttpserver
LIBHTTPSERVER_IDIR := $(LIBHTTPSERVER_PATH)/src
LIBHTTPSERVER_LDIR := $(LIBHTTPSERVER_PATH)/build/src/.libs

MICROHTTPD_PATH := $(DEPS_PATH)/libmicrohttpd/libmicrohttpd
MICROHTTPD_IDIR := $(MICROHTTPD_PATH) -I$(MICROHTTPD_PATH)/src/include
MICROHTTPD_LDIR := $(MICROHTTPD_PATH)/src/microhttpd/.libs

COREDUMPER_PATH := $(DEPS_PATH)/coredumper/coredumper
COREDUMPER_IDIR := $(COREDUMPER_PATH)/include
COREDUMPER_LDIR := $(COREDUMPER_PATH)/src

CURL_PATH := $(DEPS_PATH)/curl/curl
CURL_IDIR := $(CURL_PATH)/include
CURL_LDIR := $(CURL_PATH)/lib/.libs

include ../common_mk/openssl_flags.mk

EV_PATH := $(DEPS_PATH)/libev/libev
EV_IDIR := $(EV_PATH)
EV_LDIR := $(EV_PATH)/.libs

POSTGRES_PATH := $(DEPS_PATH)/postgresql/postgresql/src
POSTGRES_IDIR := $(POSTGRES_PATH)/include -I$(POSTGRES_PATH)/interfaces/libpq
POSTGRES_LDIR := $(POSTGRES_PATH)/interfaces/libpq -L$(POSTGRES_PATH)/common -L$(POSTGRES_PATH)/port

LIBUSUAL_PATH := $(DEPS_PATH)/libusual/libusual
LIBUSUAL_IDIR := $(LIBUSUAL_PATH)
LIBUSUAL_LDIR := $(LIBUSUAL_PATH)/.libs

LIBSCRAM_PATH := $(DEPS_PATH)/libscram
LIBSCRAM_IDIR := $(LIBSCRAM_PATH)/include
LIBSCRAM_LDIR := $(LIBSCRAM_PATH)/lib

IDIR := ../include

IDIRS := -I$(IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) -I$(LIBCONFIG_IDIR) -I$(RE2_IDIR) -I$(SQLITE3_IDIR) -I$(PCRE_PATH) -I/usr/local/include -I$(CLICKHOUSE_CPP_IDIR) -I$(MICROHTTPD_IDIR) -I$(LIBHTTPSERVER_IDIR) -I$(LIBINJECTION_IDIR) -I$(CURL_IDIR) -I$(EV_PATH) -I$(PROMETHEUS_IDIR) -I$(LIBUSUAL_IDIR) -I$(LIBSCRAM_IDIR) -I$(POSTGRES_IDIR) -I$(SSL_IDIR)
ifeq ($(UNAME_S),Linux)
	IDIRS += -I$(COREDUMPER_IDIR)
endif
LDIRS := -L$(JEMALLOC_PATH)/lib -L$(RE2_PATH)/obj -L$(LIBINJECTION_LDIR) -L$(PROMETHEUS_LDIR)

#LIBS := -rdynamic -Wl,-Bstatic -ljemalloc_pic -lre2 -Wl,-Bdynamic -ldl -lpthread -lm -lz -lrt $(EXTRALINK)
#LIBS := -Wl,--export-dynamic -Wl,-Bstatic -ljemalloc_pic -lre2 -Wl,-Bdynamic -ldl -lpthread -lm -lz -lrt $(EXTRALINK)

ODIR := obj


WASAN :=
ifeq ($(WITHASAN),1)
	WASAN := -fsanitize=address
	# Force the disable of JEMALLOC, since ASAN isn't compatible.
	export NOJEMALLOC=1
	# workaroud ASAN limitation ASLR > 28bits
	# https://github.com/google/sanitizers/issues/1716
	# sudo sysctl vm.mmap_rnd_bits=28
    $(warning ASAN needs ASLR =< 28bits, make sure 'sysctl vm.mmap_rnd_bits=28' is set.)
endif

NOJEM :=
ifeq ($(NOJEMALLOC),1)
	NOJEM := -DNOJEM
endif

WGCOV :=
ifeq ($(WITHGCOV),1)
	WGCOV := -DWITHGCOV --coverage -lgcov
endif


### detect compiler support for c++11/17
CPLUSPLUS := $(shell ${CC} -std=c++17 -dM -E -x c++ /dev/null 2>/dev/null | grep -F __cplusplus | egrep -o '[0-9]{6}L')
ifneq ($(CPLUSPLUS),201703L)
	CPLUSPLUS := $(shell ${CC} -std=c++11 -dM -E -x c++ /dev/null 2>/dev/null| grep -F __cplusplus | egrep -o '[0-9]{6}L')
ifneq ($(CPLUSPLUS),201103L)
    $(error Compiler must support at least c++11)
endif
endif
STDCPP := -std=c++$(shell echo $(CPLUSPLUS) | cut -c3-4) -DCXX$(shell echo $(CPLUSPLUS) | cut -c3-4)


PSQLCH :=
ifeq ($(PROXYSQLCLICKHOUSE),1)
	PSQLCH := -DPROXYSQLCLICKHOUSE
endif


# 'libhttpserver': Add 'ENABLE_EPOLL' by default for all platforms except
# for 'Darwin'. This is required when compiling 'libhttpserver' for avoiding
# internal use of 'SELECT' in favor of 'EPOLL'. See #3591.
ENABLE_EPOLL := -DENABLE_EPOLL
ifeq ($(UNAME_S),Darwin)
	ENABLE_EPOLL :=
endif

MYCFLAGS := $(IDIRS) $(OPTZ) $(DEBUG) -Wall -DGITVERSION=\"$(GIT_VERSION)\" $(NOJEM) $(WGCOV) $(WASAN)
MYCXXFLAGS := $(STDCPP) $(MYCFLAGS) $(PSQLCH) $(ENABLE_EPOLL)

default: libproxysql.a
.PHONY: default

_OBJ_CXX := ProxySQL_GloVars.oo network.oo debug.oo configfile.oo Query_Cache.oo SpookyV2.oo MySQL_Authentication.oo gen_utils.oo sqlite3db.oo mysql_connection.oo MySQL_HostGroups_Manager.oo mysql_data_stream.oo MySQL_Thread.oo MySQL_Session.oo MySQL_Protocol.oo mysql_backend.oo Query_Processor.oo MySQL_Query_Processor.oo PgSQL_Query_Processor.oo  ProxySQL_Admin.oo ProxySQL_Config.oo ProxySQL_Restapi.oo MySQL_Monitor.oo MySQL_Logger.oo thread.oo MySQL_PreparedStatement.oo ProxySQL_Cluster.oo ClickHouse_Authentication.oo ClickHouse_Server.oo ProxySQL_Statistics.oo Chart_bundle_js.oo ProxySQL_HTTP_Server.oo ProxySQL_RESTAPI_Server.oo font-awesome.min.css.oo main-bundle.min.css.oo MySQL_Variables.oo c_tokenizer.oo proxysql_utils.oo proxysql_coredump.oo proxysql_sslkeylog.oo \
	sha256crypt.oo \
	BaseSrvList.oo BaseHGC.oo Base_HostGroups_Manager.oo \
	QP_rule_text.oo QP_query_digest_stats.oo \
	GTID_Server_Data.oo MyHGC.oo MySrvConnList.oo MySrvC.oo \
	MySQL_encode.oo MySQL_ResultSet.oo \
	ProxySQL_Admin_Tests.oo ProxySQL_Admin_Tests2.oo ProxySQL_Admin_Scheduler.oo ProxySQL_Admin_Disk_Upgrade.oo ProxySQL_Admin_Stats.oo \
	Admin_Handler.oo Admin_FlushVariables.oo Admin_Bootstrap.oo \
	Base_Session.oo Base_Thread.oo \
	proxy_protocol_info.oo \
	proxysql_find_charset.oo ProxySQL_Poll.oo \
	PgSQL_Protocol.oo PgSQL_Thread.oo PgSQL_Data_Stream.oo PgSQL_Session.oo PgSQL_Variables.oo PgSQL_HostGroups_Manager.oo PgSQL_Connection.oo PgSQL_Backend.oo PgSQL_Logger.oo PgSQL_Authentication.oo PgSQL_Error_Helper.oo \
	MySQL_Query_Cache.oo PgSQL_Query_Cache.oo PgSQL_Monitor.oo \
	MySQL_Set_Stmt_Parser.oo PgSQL_Set_Stmt_Parser.oo \
	PgSQL_Variables_Validator.oo PgSQL_ExplicitTxnStateMgr.oo

OBJ_CXX := $(patsubst %,$(ODIR)/%,$(_OBJ_CXX))
HEADERS := ../include/*.h ../include/*.hpp

%.ko: %.cpp $(HEADERS)
	$(CXX) -fPIC -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS)

$(ODIR)/%.oo: %.cpp $(HEADERS)
	$(CXX) -fPIC -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS)

libproxysql.a: $(ODIR) $(OBJ) $(OBJ_CXX) $(SQLITE3_LDIR)/sqlite3.o
	ar rcs $@ $(OBJ) $(OBJ_CXX) $(SQLITE3_LDIR)/sqlite3.o

$(ODIR):
	mkdir $(ODIR)

#all: $(EXECUTABLE)


clean:
	rm -rf *.pid $(ODIR)/*.oo $(ODIR)/*.o $(ODIR)/*.gcno $(ODIR)/*.gcda *.ko *.so *~ core libproxysql.a $(ODIR)


## self note
# ../deps/protobuf/protobuf/src/protoc -I=. --cpp_out=. ./mysql_logger.proto
# mv mysql_logger.pb.cc mysql_logger.pb.cpp
