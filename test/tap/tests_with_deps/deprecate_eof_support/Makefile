#!/bin/make -f


TEST_DEPS_PATH ?= /var/lib/jenkins/scripts/test-scripts/deps

MARIADB_BASE_FOLDER := $(TEST_DEPS_PATH)/mariadb-client-library-3.1.9/
MARIADB_TEST_DEP := $(TEST_DEPS_PATH)/mariadb-client-library-3.1.9/mariadb-connector-c

BASE_DIR_EXIST := $(shell if [ -d $(MARIADB_BASE_FOLDER) ]; then echo 1; else echo 0; fi)
DEP_FOLDER_EMPTY := $(shell if [ -f $(MARIADB_TEST_DEP)/CMakeLists.txt ]; then echo 1; else echo 0; fi)


ifeq ($(BASE_DIR_EXIST),1)

ifeq ($(DEP_FOLDER_EMPTY),0)
$(error "Dependency folder '$(MARIADB_TEST_DEP)' is empty. Make sure folder is initialized.")
endif


GIT_VERSION ?= $(shell git describe --long --abbrev=7)
ifndef GIT_VERSION
	$(error GIT_VERSION is not set)
endif


PROXYSQL_PATH := ../../../..
PROXYSQL_LDIR := $(PROXYSQL_PATH)/lib

DEPS_PATH := $(PROXYSQL_PATH)/deps

MARIADB_PATH := $(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR := $(MARIADB_PATH)/include
MARIADB_LDIR := $(MARIADB_PATH)/libmariadb

TAP_PATH := ../../tap
TAP_IDIR := $(TAP_PATH)
TAP_LDIR := $(TAP_PATH)

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

IDIRS := -I$(PROXYSQL_PATH)/include
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
IDIRS += -I$(MARIADB_TEST_DEP)/include

TESTS_DEPS := $(TAP_LDIR)/libtap.so $(MARIADB_TEST_DEP)/libmariadb/libmariadbclient.a


.PHONY: default
default: all

.PHONY: all
all: build_deps tests

.PHONY: debug
debug: DEBUG := -DDEBUG
debug: OPT := $(STDCPP) -O0 -DDEBUG -ggdb -Wl,--no-as-needed $(WGCOV) $(WASAN)
debug: build_deps tests


$(MARIADB_TEST_DEP)/libmariadb/libmariadbclient.a:
	cd $(MARIADB_BASE_FOLDER) && CC=${CC} CXX=${CXX} ${MAKE} mariadb_client

.PHONY: build_deps
build_deps: $(TESTS_DEPS)


tests: $(patsubst %.cpp,%,$(wildcard *-t.cpp)) fwd_eof_query fwd_eof_ok_query


COMMONARGS := $(OPT) -I$(TAP_IDIR) -L$(TAP_LDIR) -ltap -lcpp_dotenv -Wl,--no-as-needed -lz -ldl -lpthread -DGITVERSION=\"$(GIT_VERSION)\"

ok_packet_mixed_queries-t: eof_packet_mixed_queries-t.cpp $(TESTS_DEPS)
	$(CXX) $^ $(IDIRS) $(COMMONARGS) -o $@

eof_packet_mixed_queries-t: eof_packet_mixed_queries-t.cpp $(TESTS_DEPS)
	$(CXX) -DNON_EOF_SUPPORT $^ $(IDIRS) $(COMMONARGS) -o $@

fwd_eof_query: fwd_eof_query.cpp $(TESTS_DEPS)
	$(CXX) -DNON_EOF_SUPPORT $^ $(IDIRS) $(COMMONARGS) -o $@

# NOTE: Compilation with 'libmysql' instead of 'libmariadb' client to confirm packet sequence id isn't check by 'libmariadb'
fwd_eof_ok_query: fwd_eof_query.cpp $(TAP_LDIR)/libtap.so
	$(CXX) $^ $(IDIRS) -I$(MARIADB_IDIR) -I/usr/include/mysql/ -lmysqlclient -L/usr/lib/x86_64-linux-gnu/ $(COMMONARGS) -o $@
# NOTE end

deprecate_eof_cache-t: deprecate_eof_cache-t.cpp $(TESTS_DEPS)
	$(CXX) $^ $(IDIRS) -L$(PROXYSQL_LDIR) -lproxysql $(COMMONARGS) -o $@

eof_cache_mixed_flags-t: eof_cache_mixed_flags-t.cpp $(TESTS_DEPS)
	$(CXX) $^ $(IDIRS) $(COMMONARGS) -o $@

eof_mixed_flags_queries-t: eof_mixed_flags_queries-t.cpp $(TESTS_DEPS)
	$(CXX) $^ $(IDIRS) $(COMMONARGS) -o $@

eof_conn_options_check-t: eof_conn_options_check-t.cpp $(TESTS_DEPS)
	$(CXX) $^ $(IDIRS) $(COMMONARGS) -o $@

eof_fast_forward-t: eof_fast_forward-t.cpp $(TESTS_DEPS)
	$(CXX) $^ $(IDIRS)  $(COMMONARGS) -o $@


$(TAP_LIBDIR)/libtap.a:
	cd ../../tap && CC=${CC} CXX=${CXX} ${MAKE} 


.PHONY: clean
clean:
	rm -f *-t
	rm -f fwd_eof_query
	rm -f fwd_eof_ok_query
	rm -f *.a *.o
	cd $(MARIADB_BASE_FOLDER) && ${MAKE} clean


else
.PHONY: all
all:
$(warning The required deps were not found. Tests 'deprecate_eof_support' wont be build)

.PHONY: debug
debug:
$(warning The required deps were not found. Tests 'deprecate_eof_support' wont be build)

.PHONY: clean
clean:
	rm -f *-t
	rm -f fwd_eof_query
	rm -f fwd_eof_ok_query
	rm -f *.a *.o
endif
