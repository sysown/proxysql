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

JEMALLOC_PATH := $(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR := $(JEMALLOC_PATH)/include/jemalloc
JEMALLOC_LDIR := $(JEMALLOC_PATH)/lib

JSON_IDIR := $(DEPS_PATH)/json

RE2_PATH := $(DEPS_PATH)/re2/re2
RE2_IDIR := $(RE2_PATH)
RE2_LDIR := $(RE2_PATH)/obj

SQLITE3_PATH := $(DEPS_PATH)/sqlite3/sqlite3
SQLITE3_IDIR := $(SQLITE3_PATH)
SQLITE3_LDIR := $(SQLITE3_PATH)

LIBHTTPSERVER_DIR := $(DEPS_PATH)/libhttpserver/libhttpserver
LIBHTTPSERVER_IDIR := $(LIBHTTPSERVER_DIR)/src
LIBHTTPSERVER_LDIR := $(LIBHTTPSERVER_DIR)/build/src/.libs/

LIBCONFIG_PATH := $(DEPS_PATH)/libconfig/libconfig
LIBCONFIG_IDIR := $(LIBCONFIG_PATH)/lib
LIBCONFIG_LDIR := $(LIBCONFIG_PATH)/lib/.libs

CURL_DIR := $(DEPS_PATH)/curl/curl
CURL_IDIR := $(CURL_DIR)/include
CURL_LDIR := $(CURL_DIR)/lib/.libs

PCRE_PATH := $(DEPS_PATH)/pcre/pcre
PCRE_LDIR := $(PCRE_PATH)/.libs

MICROHTTPD_DIR := $(DEPS_PATH)/libmicrohttpd/libmicrohttpd/src
MICROHTTPD_IDIR := $(MICROHTTPD_DIR)/include
MICROHTTPD_LDIR := $(MICROHTTPD_DIR)/microhttpd/.libs

SSL_DIR := $(DEPS_PATH)/libssl/openssl/
SSL_IDIR := $(SSL_DIR)/include
SSL_LDIR := $(SSL_DIR)

EV_DIR := $(DEPS_PATH)/libev/libev/
EV_IDIR := $(EV_DIR)
EV_LDIR := $(EV_DIR)/.libs

PROMETHEUS_PATH := $(DEPS_PATH)/prometheus-cpp/prometheus-cpp
PROMETHEUS_IDIR := $(PROMETHEUS_PATH)/pull/include -I$(PROMETHEUS_PATH)/core/include
PROMETHEUS_LDIR := $(PROMETHEUS_PATH)/lib

CITYHASH_DIR := $(DEPS_PATH)/cityhash/cityhash/
CITYHASH_IDIR := $(CITYHASH_DIR)
CITYHASH_LDIR := $(CITYHASH_DIR)/src/.libs

COREDUMPER_DIR := $(DEPS_PATH)/coredumper/coredumper
COREDUMPER_IDIR := $(COREDUMPER_DIR)/include
COREDUMPER_LDIR := $(COREDUMPER_DIR)/src

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
CPLUSPLUS := $(shell ${CC} -std=c++17 -dM -E -x c++ /dev/null 2>/dev/null | grep -F __cplusplus | egrep -o '[0-9]{6}L')
ifneq ($(CPLUSPLUS),201703L)
	CPLUSPLUS := $(shell ${CC} -std=c++11 -dM -E -x c++ /dev/null 2>/dev/null| grep -F __cplusplus | egrep -o '[0-9]{6}L')
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
	# Force the disable of JEMALLOC, since ASAN isn't compatible.
	export NOJEMALLOC=1
	# workaroud ASAN limitation ASLR > 28bits
	# https://github.com/google/sanitizers/issues/1716
	# sudo sysctl vm.mmap_rnd_bits=28
    $(warning ASAN needs ASLR =< 28bits, make sure 'sysctl vm.mmap_rnd_bits=28' is set.)
endif

OPT := $(STDCPP) -O2 -ggdb -Wl,--no-as-needed -Wl,-rpath,"../../tap" $(WGCOV) $(WASAN)

IDIRS := -I$(TAP_IDIR) -I$(RE2_IDIR) -I$(PROXYSQL_IDIR) -I$(JEMALLOC_IDIR) -I$(LIBCONFIG_IDIR)\
		 -I$(MICROHTTPD_IDIR) -I$(LIBHTTPSERVER_IDIR) -I$(CURL_IDIR) -I$(EV_IDIR) -I$(PROMETHEUS_IDIR)\
		 -I$(DOTENV_DYN_IDIR) -I$(SSL_IDIR) -I$(SQLITE3_IDIR) -I$(JSON_IDIR)
LDIRS := -L$(TAP_LDIR) -L$(RE2_LDIR) -L$(PROXYSQL_LDIR) -L$(JEMALLOC_LDIR) -L$(LIBCONFIG_LDIR)\
		 -L$(MICROHTTPD_LDIR) -L$(LIBHTTPSERVER_LDIR) -L$(CURL_LDIR) -L$(EV_LDIR) -L$(PROMETHEUS_LDIR)\
		 -L$(DOTENV_DYN_LDIR) -L$(SSL_LDIR) -L$(SQLITE3_LDIR) -L$(PCRE_LDIR)

### main targets

.DEFAULT: default
.PHONY: default
default: all

.PHONY: all
all: tests

.PHONY: debug
debug: DEBUG := -DDEBUG
debug: OPT := $(STDCPP) -O0 -DDEBUG -ggdb -Wl,--no-as-needed -Wl,-rpath,"../../tap" $(WGCOV) $(WASAN)
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
tests:
	@echo "Removing empty .gcno files ..."
	find -L . -type f -name '*.gcno' -empty -ls -delete

COMMONARGS = $(OPT) -Wl,-Bdynamic -ltap -lcpp_dotenv -lcurl -lre2 -lssl -lcrypto -lz -ldl -lpthread -DGITVERSION=\"$(GIT_VERSION)\"

ok_packet_mixed_queries-t: eof_packet_mixed_queries-t.cpp
	$(CXX) $< $(IDIRS) $(LDIRS) -I$(MARIADB_IDIR) -L$(MARIADB_LDIR) -lmariadbclient $(COMMONARGS) -o $@

eof_packet_mixed_queries-t: eof_packet_mixed_queries-t.cpp
	$(CXX) -DNON_EOF_SUPPORT $< $(IDIRS) $(LDIRS) -I$(TEST_MARIADB_IDIR) -L$(TEST_MARIADB_LDIR) -lmariadbclient $(COMMONARGS) -o $@

fwd_eof_query: fwd_eof_query.cpp
	$(CXX) -DNON_EOF_SUPPORT $< $(IDIRS) $(LDIRS) -I$(TEST_MARIADB_IDIR) -L$(TEST_MARIADB_LDIR) -lmariadbclient $(COMMONARGS) -o $@

# NOTE: Compilation with 'libmysql' instead of 'libmariadb' client to confirm packet sequence id isn't check by 'libmariadb'
fwd_eof_ok_query: fwd_eof_query.cpp
	$(CXX) $< $(IDIRS) $(LDIRS) -I$(TEST_MARIADB_IDIR) -I$(TEST_MYSQL_IDIR) -I$(TEST_MYSQL_EDIR) -L$(TEST_MYSQL_LDIR) -lmysqlclient $(COMMONARGS) -o $@
# NOTE end

deprecate_eof_cache-t: deprecate_eof_cache-t.cpp
	$(CXX) $< $(IDIRS) $(LDIRS) $(PROXYSQL_LDIR)/proxysql_utils.cpp  -I$(TEST_MARIADB_IDIR) -L$(TEST_MARIADB_LDIR) -lmariadbclient $(COMMONARGS) -o $@

eof_cache_mixed_flags-t: eof_cache_mixed_flags-t.cpp
	$(CXX) $< $(IDIRS) $(LDIRS) -I$(TEST_MARIADB_IDIR) -L$(TEST_MARIADB_LDIR) -lmariadbclient $(COMMONARGS) -o $@

eof_mixed_flags_queries-t: eof_mixed_flags_queries-t.cpp
	$(CXX) $< $(IDIRS) $(LDIRS) -I$(TEST_MARIADB_IDIR) -L$(TEST_MARIADB_LDIR) -lmariadbclient $(COMMONARGS) -o $@

eof_conn_options_check-t: eof_conn_options_check-t.cpp
	$(CXX) $< $(IDIRS) $(LDIRS) -I$(MARIADB_IDIR) -L$(MARIADB_LDIR) -lmariadbclient $(COMMONARGS) -o $@

eof_fast_forward-t: eof_fast_forward-t.cpp
	$(CXX) $< $(IDIRS) $(LDIRS) -I$(MARIADB_IDIR) -L$(MARIADB_LDIR) -lmariadbclient $(COMMONARGS) -o $@


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
