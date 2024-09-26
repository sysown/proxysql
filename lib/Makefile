#!/bin/make -f


GIT_VERSION ?= $(shell git describe --long --abbrev=7)
ifndef GIT_VERSION
    $(error GIT_VERSION is not set)
endif

DEPS_PATH := ../deps

UNAME_S := $(shell uname -s)


MARIADB_PATH := $(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR := $(MARIADB_PATH)/include

JEMALLOC_PATH := $(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR := $(JEMALLOC_PATH)/include/jemalloc

LIBCONFIG_PATH := $(DEPS_PATH)/libconfig/libconfig
LIBCONFIG_IDIR := -I$(LIBCONFIG_PATH)/lib

#INJECTION_PATH := $(DEPS_PATH)/libinjection
#INJECTION_IDIR := $(INJECTION_PATH)

RE2_PATH := $(DEPS_PATH)/re2/re2
RE2_IDIR := $(RE2_PATH)

PCRE_PATH := $(DEPS_PATH)/pcre/pcre

SQLITE3_DIR := $(DEPS_PATH)/sqlite3/sqlite3

CLICKHOUSE_CPP_DIR := $(DEPS_PATH)/clickhouse-cpp/clickhouse-cpp

LIBINJECTION_DIR := $(DEPS_PATH)/libinjection/libinjection
LIBINJECTION_IDIR := -I$(LIBINJECTION_DIR)/src

LIBHTTPSERVER_DIR := $(DEPS_PATH)/libhttpserver/libhttpserver
LIBHTTPSERVER_IDIR := -I$(LIBHTTPSERVER_DIR)/src

MICROHTTPD_DIR := $(DEPS_PATH)/libmicrohttpd/libmicrohttpd
MICROHTTPD_IDIR := -I$(MICROHTTPD_DIR) -I$(MICROHTTPD_DIR)/src/include

COREDUMPER_DIR := $(DEPS_PATH)/coredumper/coredumper
COREDUMPER_IDIR := $(COREDUMPER_DIR)/include

CURL_DIR := $(DEPS_PATH)/curl/curl
CURL_IDIR := $(CURL_DIR)/include

SSL_DIR := $(DEPS_PATH)/libssl/openssl/
SSL_IDIR := $(SSL_DIR)/include

EV_DIR := $(DEPS_PATH)/libev/libev/
EV_IDIR := $(EV_DIR)

PROMETHEUS_PATH := $(DEPS_PATH)/prometheus-cpp/prometheus-cpp
PROMETHEUS_IDIR := $(PROMETHEUS_PATH)/pull/include -I$(PROMETHEUS_PATH)/core/include
PROMETHEUS_LDIR := $(PROMETHEUS_PATH)/lib

LIBUSUAL_PATH=$(DEPS_PATH)/libusual/libusual
LIBUSUAL_IDIR=$(LIBUSUAL_PATH)
LIBUSUAL_LDIR=$(LIBUSUAL_PATH)/.libs/

LIBSCRAM_PATH=$(DEPS_PATH)/libscram/
LIBSCRAM_IDIR=$(LIBSCRAM_PATH)/include/
LIBSCRAM_LDIR=$(LIBSCRAM_PATH)/lib/

POSTGRES_PATH=$(DEPS_PATH)/postgresql/postgresql/src/
POSTGRES_IFACE=$(POSTGRES_PATH)/interfaces/libpq/ -I$(POSTGRES_PATH)/include
POSTGRES_LDIR=$(POSTGRES_IFACES)/libpq/

IDIR := ../include

IDIRS := -I$(IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) $(LIBCONFIG_IDIR) -I$(RE2_IDIR) -I$(SQLITE3_DIR) -I$(PCRE_PATH) -I/usr/local/include -I$(CLICKHOUSE_CPP_DIR) -I$(CLICKHOUSE_CPP_DIR)/contrib/ $(MICROHTTPD_IDIR) $(LIBHTTPSERVER_IDIR) $(LIBINJECTION_IDIR) -I$(CURL_IDIR) -I$(EV_DIR) -I$(SSL_IDIR) -I$(PROMETHEUS_IDIR) -I$(LIBUSUAL_IDIR) -I$(LIBSCRAM_IDIR) -I$(POSTGRES_IFACE)
ifeq ($(UNAME_S),Linux)
	IDIRS += -I$(COREDUMPER_IDIR)
endif
LDIRS := -L$(JEMALLOC_PATH)/lib -L$(RE2_PATH)/obj -L$(INJECTION_PATH) -L$(PROMETHEUS_LDIR)

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

_OBJ_CXX := ProxySQL_GloVars.oo network.oo debug.oo configfile.oo Query_Cache.oo SpookyV2.oo MySQL_Authentication.oo gen_utils.oo sqlite3db.oo mysql_connection.oo MySQL_HostGroups_Manager.oo mysql_data_stream.oo MySQL_Thread.oo MySQL_Session.oo MySQL_Protocol.oo mysql_backend.oo Query_Processor.oo MySQL_Query_Processor.oo PgSQL_Query_Processor.oo  ProxySQL_Admin.oo ProxySQL_Config.oo ProxySQL_Restapi.oo MySQL_Monitor.oo MySQL_Logger.oo thread.oo MySQL_PreparedStatement.oo ProxySQL_Cluster.oo ClickHouse_Authentication.oo ClickHouse_Server.oo ProxySQL_Statistics.oo Chart_bundle_js.oo ProxySQL_HTTP_Server.oo ProxySQL_RESTAPI_Server.oo font-awesome.min.css.oo main-bundle.min.css.oo set_parser.oo MySQL_Variables.oo c_tokenizer.oo proxysql_utils.oo proxysql_coredump.oo proxysql_sslkeylog.oo \
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
	PgSQL_Protocol.oo PgSQL_Thread.oo PgSQL_Data_Stream.oo PgSQL_Session.oo PgSQL_Variables.oo PgSQL_HostGroups_Manager.oo PgSQL_Connection.oo PgSQL_Backend.oo PgSQL_Logger.oo PgSQL_Authentication.oo PgSQL_Error_Helper.oo PgSQL_Monitor.oo

OBJ_CXX := $(patsubst %,$(ODIR)/%,$(_OBJ_CXX))
HEADERS := ../include/*.h ../include/*.hpp

%.ko: %.cpp $(HEADERS)
	$(CXX) -fPIC -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS)

$(ODIR)/%.oo: %.cpp $(HEADERS)
	$(CXX) -fPIC -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS)

libproxysql.a: $(ODIR) $(OBJ) $(OBJ_CXX) $(SQLITE3_DIR)/sqlite3.o
	ar rcs $@ $(OBJ) $(OBJ_CXX) $(SQLITE3_DIR)/sqlite3.o

$(ODIR):
	mkdir $(ODIR)

#all: $(EXECUTABLE)


clean:
	rm -rf *.pid $(ODIR)/*.oo $(ODIR)/*.o $(ODIR)/*.gcno $(ODIR)/*.gcda *.ko *.so *~ core libproxysql.a $(ODIR)


## self note
# ../deps/protobuf/protobuf/src/protoc -I=. --cpp_out=. ./mysql_logger.proto
# mv mysql_logger.pb.cc mysql_logger.pb.cpp
