#!/bin/make -f


GIT_VERSION ?= $(shell git describe --long --abbrev=7)
ifndef GIT_VERSION
	$(error GIT_VERSION is not set)
endif


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)
PROXYSQL_IDIR := $(PROXYSQL_PATH)/include
PROXYSQL_LDIR := $(PROXYSQL_PATH)/lib

DEPS_PATH := $(PROXYSQL_PATH)/deps

MARIADB_PATH := $(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR := $(MARIADB_PATH)/include
MARIADB_LDIR := $(MARIADB_PATH)/libmariadb

TAP_PATH := $(PROXYSQL_PATH)/test/tap/tap
TAP_IDIR := $(TAP_PATH)
TAP_LDIR := $(TAP_PATH)

TEST_DEPS_PATH := $(PROXYSQL_PATH)/test/deps

TEST_MARIADB_PATH := $(TEST_DEPS_PATH)/mariadb-connector-c/mariadb-connector-c
TEST_MARIADB_IDIR := $(TEST_MARIADB_PATH)/include
TEST_MARIADB_LDIR := $(TEST_MARIADB_PATH)/libmariadb

TEST_MYSQL_PATH := $(TEST_DEPS_PATH)/mysql-connector-c/mysql-connector-c
TEST_MYSQL_IDIR := $(TEST_MYSQL_PATH)/include
TEST_MYSQL_EDIR := $(TEST_MYSQL_PATH)/libbinlogevents/export
TEST_MYSQL_LDIR := $(TEST_MYSQL_PATH)/libmysql

### detect compiler support for c++11/17
CPLUSPLUS := $(shell ${CC} -std=c++17 -dM -E -x c++ /dev/null 2>/dev/null | grep -F __cplusplus | grep -Po '\d\d\d\d\d\dL')
ifneq ($(CPLUSPLUS),201703L)
	CPLUSPLUS := $(shell ${CC} -std=c++11 -dM -E -x c++ /dev/null 2>/dev/null| grep -F __cplusplus | grep -Po '\d\d\d\d\d\dL')
ifneq ($(CPLUSPLUS),201103L)
$(error Compiler must support at least c++11)
endif
endif
STDCPP := -std=c++$(shell echo $(CPLUSPLUS) | cut -c3-4) -DCXX$(shell echo $(CPLUSPLUS) | cut -c3-4)

WGCOV :=
ifeq ($(WITHGCOV),1)
	WGCOV := -DWITHGCOV --coverage -lgcov
endif

WASAN :=
ifeq ($(WITHASAN),1)
	WASAN := -fsanitize=address
endif

OPT := $(STDCPP) -O2 -ggdb -Wl,--no-as-needed $(WGCOV)

IDIRS := -I$(PROXYSQL_IDIR)
IDIRS += -I$(DEPS_PATH)/sqlite3/sqlite3
IDIRS += -I$(DEPS_PATH)/json
IDIRS += -I$(DEPS_PATH)/prometheus-cpp/prometheus-cpp/core/include
IDIRS += -I$(DEPS_PATH)/prometheus-cpp/prometheus-cpp/pull/include
IDIRS += -I$(DEPS_PATH)/libconfig/libconfig/lib
IDIRS += -I$(DEPS_PATH)/jemalloc/jemalloc/include/jemalloc
IDIRS += -I$(DEPS_PATH)/libhttpserver/libhttpserver/src
IDIRS += -I$(DEPS_PATH)/libmicrohttpd/libmicrohttpd/src/include/
IDIRS += -I$(DEPS_PATH)/re2/re2
IDIRS += -I$(DEPS_PATH)/libev/libev
IDIRS += -I$(DEPS_PATH)/curl/curl/include


### main targets

.DEFAULT: default
.PHONY: default
default: all

.PHONY: all
all: tests

.PHONY: debug
debug: DEBUG := -DDEBUG
debug: OPT := $(STDCPP) -O0 -DDEBUG -ggdb -Wl,--no-as-needed $(WGCOV) $(WASAN)
debug: tests


### test deps targets

#.PHONY: build_test_deps
#build_test_deps: $(TAP_LDIR)/libtap.so $(TEST_MARIADB_LDIR)/libmariadbclient.a $(TEST_MYSQL_LDIR)/libmysqlclient.a

$(TAP_LDIR)/libtap.so:
	cd $(TAP_PATH) && CC=${CC} CXX=${CXX} ${MAKE} 

$(TEST_MARIADB_LDIR)/libmariadbclient.a:
	cd $(TEST_DEPS_PATH) && CC=${CC} CXX=${CXX} ${MAKE} mariadb_client

$(TEST_MYSQL_LDIR)/libmysqlclient.a:
	cd $(TEST_DEPS_PATH) && CC=${CC} CXX=${CXX} ${MAKE} mysql_client


### test and helper targets

#tests: build_test_deps
tests: $(patsubst %.cpp,%,$(wildcard *-t.cpp)) ok_packet_mixed_queries-t fwd_eof_query fwd_eof_ok_query

COMMONARGS := $(OPT) -I$(TAP_IDIR) -L$(TAP_LDIR) -ltap -lcpp_dotenv -lcurl -lssl -lcrypto -lz -ldl -lpthread -DGITVERSION=\"$(GIT_VERSION)\"

ok_packet_mixed_queries-t: eof_packet_mixed_queries-t.cpp
	$(CXX) $< $(IDIRS) -I$(TEST_MARIADB_IDIR) -L$(TEST_MARIADB_LDIR) -lmariadbclient $(COMMONARGS) -o $@

eof_packet_mixed_queries-t: eof_packet_mixed_queries-t.cpp
	$(CXX) -DNON_EOF_SUPPORT $< $(IDIRS) -I$(TEST_MARIADB_IDIR) -L$(TEST_MARIADB_LDIR) -lmariadbclient $(COMMONARGS) -o $@

fwd_eof_query: fwd_eof_query.cpp
	$(CXX) -DNON_EOF_SUPPORT $< $(IDIRS) -I$(TEST_MARIADB_IDIR) -L$(TEST_MARIADB_LDIR) -lmariadbclient $(COMMONARGS) -o $@

# NOTE: Compilation with 'libmysql' instead of 'libmariadb' client to confirm packet sequence id isn't check by 'libmariadb'
fwd_eof_ok_query: fwd_eof_query.cpp
	$(CXX) $< $(IDIRS) -I$(TEST_MARIADB_IDIR) -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) -L$(TEST_MYSQL_LDIR) -lmysqlclient $(COMMONARGS) -o $@
# NOTE end

deprecate_eof_cache-t: deprecate_eof_cache-t.cpp
	$(CXX) $< $(IDIRS) -I$(TEST_MARIADB_IDIR) -L$(TEST_MARIADB_LDIR) -lmariadbclient -L$(PROXYSQL_LDIR) -lproxysql $(COMMONARGS) -o $@

eof_cache_mixed_flags-t: eof_cache_mixed_flags-t.cpp
	$(CXX) $< $(IDIRS) -I$(TEST_MARIADB_IDIR) -L$(TEST_MARIADB_LDIR) -lmariadbclient $(COMMONARGS) -o $@

eof_mixed_flags_queries-t: eof_mixed_flags_queries-t.cpp
	$(CXX) $< $(IDIRS) -I$(TEST_MARIADB_IDIR) -L$(TEST_MARIADB_LDIR) -lmariadbclient $(COMMONARGS) -o $@

eof_conn_options_check-t: eof_conn_options_check-t.cpp
	$(CXX) $< $(IDIRS) -I$(TEST_MARIADB_IDIR) -L$(TEST_MARIADB_LDIR) -lmariadbclient $(COMMONARGS) -o $@

eof_fast_forward-t: eof_fast_forward-t.cpp
	$(CXX) $< $(IDIRS) -I$(TEST_MARIADB_IDIR) -L$(TEST_MARIADB_LDIR) -lmariadbclient $(COMMONARGS) -o $@


### clean targets

.SILENT: cleanall
.PHONY: cleanall
cleanall: clean
	cd $(TEST_DEPS_PATH) && ${MAKE} cleanall

.SILENT: clean
.PHONY: clean
clean:
	rm -f *-t || true
	rm -f fwd_eof_query || true
	rm -f fwd_eof_ok_query || true
	rm -f *.a *.o || true
	rm -f *.gcda *.gcno || true
