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

PROXYSQL_PATH := ../../../..
DEPS_PATH := $(PROXYSQL_PATH)/deps

WGCOV :=
ifeq ($(WITHGCOV),1)
	WGCOV := -DWITHGCOV --coverage -lgcov
endif

WASAN :=
ifeq ($(WITHASAN),1)
	WASAN := -fsanitize=address
endif

OPT := -O2 $(WGCOV) -Wl,--no-as-needed
LLP := $(shell pwd)/../../tap
TAP_LIBDIR := ../../tap

TESTS_DEPS := $(TAP_LIBDIR)/libtap.a $(MARIADB_TEST_DEP)/libmariadb/libmariadbclient.a

INCLUDEDIRS := -I$(PROXYSQL_PATH)/include
INCLUDEDIRS += -I$(DEPS_PATH)/sqlite3/sqlite3
INCLUDEDIRS += -I$(DEPS_PATH)/json
INCLUDEDIRS += -I$(DEPS_PATH)/prometheus-cpp/prometheus-cpp/core/include -I$(DEPS_PATH)/prometheus-cpp/prometheus-cpp/pull/include
INCLUDEDIRS += -I$(DEPS_PATH)/libconfig/libconfig/lib
INCLUDEDIRS += -I$(DEPS_PATH)/jemalloc/jemalloc/include/jemalloc
INCLUDEDIRS += -I$(DEPS_PATH)/libhttpserver/libhttpserver/src
INCLUDEDIRS += -I$(DEPS_PATH)/libmicrohttpd/libmicrohttpd/src/include/
INCLUDEDIRS += -I$(DEPS_PATH)/re2/re2
INCLUDEDIRS += -I$(DEPS_PATH)/libev/libev
INCLUDEDIRS += -I$(MARIADB_TEST_DEP)/include

PROXYLDIR := $(PROXYSQL_PATH)/lib

.PHONY: default
default: all

.PHONY: all
all: build_deps tests

.PHONY: debug
debug: DEBUG := -DDEBUG
debug: OPT := -O0 -DDEBUG -ggdb -Wl,--no-as-needed $(WGCOV) $(WASAN)
debug: build_deps tests


$(MARIADB_TEST_DEP)/libmariadb/libmariadbclient.a:
	cd $(MARIADB_BASE_FOLDER) && CC=${CC} CXX=${CXX} ${MAKE} mariadb_client

.PHONY: build_deps
build_deps: $(MARIADB_TEST_DEP)/libmariadb/libmariadbclient.a


.PHONY: clean
clean:
	rm -f *-t
	rm -f fwd_eof_query
	rm -f fwd_eof_ok_query
	rm -f *.a *.o
	cd $(MARIADB_BASE_FOLDER) && ${MAKE} clean


tests: $(patsubst %.cpp,%,$(wildcard *-t.cpp)) fwd_eof_query fwd_eof_ok_query

COMMONARGS1 := $(OPT) -std=c++11 -I$(TAP_LIBDIR) -L$(TAP_LIBDIR) -ltap -lcpp_dotenv -Wl,--no-as-needed -lz -ldl -lpthread -DGITVERSION=\"$(GIT_VERSION)\" -DDEBUG
COMMONARGS := $(COMMONARGS1) $(MYLIBS)

ok_packet_mixed_queries-t: eof_packet_mixed_queries-t.cpp $(TESTS_DEPS)
	$(CXX) $< $(INCLUDEDIRS) $(LDIRS) -lmysqlclient $(COMMONARGS) -o $@

eof_packet_mixed_queries-t: eof_packet_mixed_queries-t.cpp ok_packet_mixed_queries-t $(TESTS_DEPS)
	$(CXX) -DNON_EOF_SUPPORT $< $(INCLUDEDIRS) -I$(MARIADB_TEST_DEP)/include/ -L$(MARIADB_TEST_DEP)/libmariadb -lmysqlclient $(COMMONARGS) -o $@

fwd_eof_query: fwd_eof_query.cpp $(TESTS_DEPS)
	$(CXX) -DNON_EOF_SUPPORT $< $(INCLUDEDIRS) -L$(MARIADB_TEST_DEP)/libmariadb -lmysqlclient $(COMMONARGS) -o $@

#fwd_eof_ok_query: fwd_eof_query.cpp $(TESTS_DEPS)
#	$(CXX) -DDEBUG fwd_eof_query.cpp $(INCLUDEDIRS) $(LDIRS) $(OPT) -std=c++11 -I$(TAP_LIBDIR) -L$(TAP_LIBDIR) $(MYLIBS) -L$(SSL_LDIR) -ltap -Wl,--no-as-needed -ldl -lpthread -o fwd_eof_ok_query -DGITVERSION=\"$(GIT_VERSION)\"

# NOTE: Compilation with 'libmysql' instead of 'libmariadb' client to confirm packet sequence id isn't check by 'libmariadb'
fwd_eof_ok_query: fwd_eof_query.cpp fwd_eof_query $(TAP_LIBDIR)/libtap.a
	$(CXX) $<  $(INCLUDEDIRS) -I/usr/include/mysql/ -lmysqlclient -I$(IDIR) -L/usr/lib/x86_64-linux-gnu/ $(COMMONARGS1) -o $@

deprecate_eof_cache-t: deprecate_eof_cache-t.cpp $(TESTS_DEPS)
	$(CXX) $^ $(INCLUDEDIRS) -L$(MARIADB_TEST_DEP)/libmariadb -L$(PROXYLDIR) -lproxysql $(COMMONARGS) -o $@

eof_cache_mixed_flags-t: eof_cache_mixed_flags-t.cpp $(TESTS_DEPS)
	$(CXX) $^ $(INCLUDEDIRS) -L$(MARIADB_TEST_DEP)/libmariadb $(COMMONARGS) -o $@

eof_mixed_flags_queries-t: eof_mixed_flags_queries-t.cpp $(TESTS_DEPS)
	$(CXX) $^ $(INCLUDEDIRS) -L$(MARIADB_TEST_DEP)/libmariadb $(COMMONARGS) -o $@

eof_conn_options_check-t: eof_conn_options_check-t.cpp $(TESTS_DEPS)
	$(CXX) $< $(INCLUDEDIRS) $(LDIRS) -lmysqlclient $(COMMONARGS) -o $@

eof_fast_forward-t: eof_fast_forward-t.cpp $(TESTS_DEPS)
	$(CXX) $< $(INCLUDEDIRS) $(LDIRS) -lmysqlclient $(COMMONARGS) -o $@

$(TAP_LIBDIR)/libtap.a:
	cd ../../tap && CC=${CC} CXX=${CXX} ${MAKE} 

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
