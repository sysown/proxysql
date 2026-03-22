#!/bin/make -f
#
# Makefile for ProxySQL unit tests.
#
# Unit tests link against libproxysql.a with stub globals (test_globals.o)
# instead of main.o, allowing individual components to be tested in
# isolation without a running ProxySQL daemon or backend servers.
#
# See: GitHub issue #5473 (Phase 2.1: Test Infrastructure Foundation)


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk


# ===========================================================================
# Include directories — mirrors test/tap/tests/Makefile
# ===========================================================================

IDIRS :=	-I$(TAP_IDIR) \
			-I$(RE2_IDIR) \
			-I$(PROXYSQL_IDIR) \
			-I$(JEMALLOC_IDIR) \
			-I$(LIBCONFIG_IDIR) \
			-I$(MARIADB_IDIR) \
			-I$(LIBDAEMON_IDIR) \
			-I$(MICROHTTPD_IDIR) \
			-I$(LIBHTTPSERVER_IDIR) \
			-I$(CURL_IDIR) -I$(EV_IDIR) \
			-I$(PROMETHEUS_IDIR) \
			-I$(DOTENV_DYN_IDIR) \
			-I$(SQLITE3_IDIR) \
			-I$(JSON_IDIR) \
			-I$(POSTGRESQL_IDIR) \
			-I$(LIBSCRAM_IDIR) \
			-I$(LIBUSUAL_IDIR) \
			-I$(SSL_IDIR) \
			-I$(ZSTD_IDIR) \
			-I$(PROXYSQL_PATH)/include \
			-I$(PROXYSQL_PATH)/test/tap/test_helpers


# ===========================================================================
# Library directories
# ===========================================================================

LDIRS :=	-L$(TAP_LDIR) \
			-L$(RE2_LDIR) \
			-L$(PROXYSQL_LDIR) \
			-L$(JEMALLOC_LDIR) \
			-L$(LIBCONFIG_LDIR) \
			-L$(MARIADB_LDIR) \
			-L$(LIBDAEMON_LDIR) \
			-L$(MICROHTTPD_LDIR) \
			-L$(LIBHTTPSERVER_LDIR) \
			-L$(CURL_LDIR) -L$(EV_LDIR) \
			-L$(PROMETHEUS_LDIR) \
			-L$(DOTENV_DYN_LDIR) \
			-L$(PCRE_LDIR) \
			-L$(LIBINJECTION_LDIR) \
			-L$(POSTGRESQL_LDIR) \
			-L$(LIBSCRAM_LDIR) \
			-L$(LIBUSUAL_LDIR) \
			-L$(SSL_LDIR)

ifeq ($(UNAME_S),Linux)
	LDIRS += -L$(COREDUMPER_LDIR)
endif
ifeq ($(UNAME_S),Darwin)
	IDIRS += -I/usr/local/include -I/opt/homebrew/include
	LDIRS += -L/usr/local/lib -L/opt/homebrew/lib
endif


# ===========================================================================
# ClickHouse include/link paths (enabled by default)
# ===========================================================================

CLICKHOUSE_CPP_PATH := $(DEPS_PATH)/clickhouse-cpp/clickhouse-cpp
CLICKHOUSE_CPP_IDIR := $(CLICKHOUSE_CPP_PATH) -I$(CLICKHOUSE_CPP_PATH)/contrib/absl
CLICKHOUSE_CPP_LDIR := $(CLICKHOUSE_CPP_PATH)/clickhouse
LZ4_LDIR := $(DEPS_PATH)/lz4/lz4/lib

IDIRS += -I$(CLICKHOUSE_CPP_IDIR)


# ===========================================================================
# libproxysql.a — the core library under test
# ===========================================================================

LIBPROXYSQLAR := $(PROXYSQL_LDIR)/libproxysql.a


# ===========================================================================
# Static libraries required at link time
# ===========================================================================

STATIC_LIBS := $(CITYHASH_LDIR)/libcityhash.a \
			   $(LZ4_LDIR)/liblz4.a \
			   $(ZSTD_LDIR)/libzstd.a

ifeq ($(PROXYSQLCLICKHOUSE),1)
	STATIC_LIBS += $(CLICKHOUSE_CPP_LDIR)/libclickhouse-cpp-lib.a
endif

ifeq ($(UNAME_S),Linux)
	STATIC_LIBS += $(COREDUMPER_LDIR)/libcoredumper.a
endif

ifeq ($(PROXYSQLGENAI),1)
	STATIC_LIBS += $(SQLITE3_LDIR)/../libsqlite_rembed.a $(SQLITE3_LDIR)/vec.o
endif


# ===========================================================================
# Linker flags — platform-specific
# ===========================================================================

ifeq ($(UNAME_S),Darwin)
# macOS: No -Bstatic/-Bdynamic; use explicit .a paths for static linking.
# libproxysql.a already bundles most deps on Darwin (see src/Makefile).
LIBPROXYSQLAR_FULL := $(LIBPROXYSQLAR) \
	$(JEMALLOC_LDIR)/libjemalloc.a \
	$(MICROHTTPD_LDIR)/libmicrohttpd.a \
	$(LIBHTTPSERVER_LDIR)/libhttpserver.a \
	$(PCRE_LDIR)/libpcre.a \
	$(PCRE_LDIR)/libpcrecpp.a \
	$(LIBDAEMON_LDIR)/libdaemon.a \
	$(LIBCONFIG_LDIR)/libconfig++.a \
	$(LIBCONFIG_LDIR)/libconfig.a \
	$(CURL_LDIR)/libcurl.a \
	$(SQLITE3_LDIR)/sqlite3.o \
	$(LIBINJECTION_LDIR)/libinjection.a \
	$(EV_LDIR)/libev.a \
	$(LIBSCRAM_LDIR)/libscram.a \
	$(LIBUSUAL_LDIR)/libusual.a \
	$(MARIADB_LDIR)/libmariadbclient.a \
	$(RE2_LDIR)/libre2.a \
	$(POSTGRESQL_PATH)/interfaces/libpq/libpq.a \
	$(POSTGRESQL_PATH)/common/libpgcommon.a \
	$(POSTGRESQL_PATH)/port/libpgport.a

MYLIBS := -lssl -lcrypto -lpthread -lm -lz \
		  -liconv -lgnutls -lprometheus-cpp-pull -lprometheus-cpp-core -luuid \
		  -lzstd $(LWGCOV)
else
# Linux/FreeBSD: Use -Bstatic/-Bdynamic for controlled linking.
LIBPROXYSQLAR_FULL := $(LIBPROXYSQLAR)

MYLIBS := -Wl,--export-dynamic -Wl,-Bdynamic -lgnutls -lcurl -lssl -lcrypto -luuid \
		  -Wl,-Bstatic -lconfig -lproxysql -ldaemon -lconfig++ -lre2 -lpcrecpp -lpcre \
		  -lmariadbclient -lhttpserver -lmicrohttpd -linjection -lev \
		  -lprometheus-cpp-pull -lprometheus-cpp-core \
		  -Wl,-Bstatic -lpq -lpgcommon -lpgport \
		  -Wl,-Bdynamic -lpthread -lm -lz -lzstd -lrt -ldl \
		  -lscram -lusual -Wl,--allow-multiple-definition \
		  $(LWGCOV)
endif

ifneq ($(NOJEMALLOC),1)
ifeq ($(UNAME_S),Linux)
	MYLIBS += -Wl,-Bstatic -ljemalloc -Wl,-Bdynamic
endif
endif


# ===========================================================================
# Compiler flags
# ===========================================================================

PSQLCH :=
ifeq ($(PROXYSQLCLICKHOUSE),1)
	PSQLCH := -DPROXYSQLCLICKHOUSE
endif
PSQLGA :=
ifeq ($(PROXYSQLGENAI),1)
	PSQLGA := -DPROXYSQLGENAI
endif
PSQL31 :=
ifeq ($(PROXYSQL31),1)
	PSQL31 := -DPROXYSQL31
endif
PSQLFFTO :=
ifeq ($(PROXYSQLFFTO),1)
	PSQLFFTO := -DPROXYSQLFFTO
endif
PSQLTSDB :=
ifeq ($(PROXYSQLTSDB),1)
	PSQLTSDB := -DPROXYSQLTSDB
endif

OPT := $(STDCPP) -O0 -ggdb $(PSQLCH) $(PSQLGA) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB) \
	   -DGITVERSION=\"$(GIT_VERSION)\" $(NOJEM) $(WGCOV) $(WASAN) \
	   -Wl,--no-as-needed -Wl,-rpath,$(TAP_LDIR)

ifeq ($(UNAME_S),Darwin)
	OPT := $(STDCPP) -O0 -ggdb $(PSQLCH) $(PSQLGA) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB) \
		   -DGITVERSION=\"$(GIT_VERSION)\" $(NOJEM) $(WGCOV) $(WASAN)
endif


# ===========================================================================
# Test helper objects
# ===========================================================================

TEST_HELPERS_DIR := $(PROXYSQL_PATH)/test/tap/test_helpers
ODIR := obj

TEST_HELPERS_OBJ := $(ODIR)/test_globals.o $(ODIR)/test_init.o $(ODIR)/tap.o

$(ODIR):
	mkdir -p $(ODIR)

# Compile tap.o directly from tap.cpp to avoid the full TAP build chain
# and its cpp-dotenv dependency (which doesn't build on macOS).
# Unit tests only need the core TAP functions: plan(), ok(), is(), etc.
TAP_SRC := $(TAP_PATH)/tap.cpp
$(ODIR)/tap.o: $(TAP_SRC) | $(ODIR)
	$(CXX) -c -o $@ $< $(OPT) $(IDIRS) -w

$(ODIR)/test_globals.o: $(TEST_HELPERS_DIR)/test_globals.cpp | $(ODIR)
	$(CXX) -c -o $@ $< $(OPT) $(IDIRS) -Wall

$(ODIR)/test_init.o: $(TEST_HELPERS_DIR)/test_init.cpp | $(ODIR)
	$(CXX) -c -o $@ $< $(OPT) $(IDIRS) -Wall


# ===========================================================================
# Unit test targets
# ===========================================================================

UNIT_TESTS := smoke_test-t query_cache_unit-t query_processor_unit-t \
	protocol_unit-t auth_unit-t connection_pool_unit-t \
	rule_matching_unit-t hostgroups_unit-t monitor_health_unit-t \
	pgsql_command_complete_unit-t \
	ffto_protocol_unit-t \
	server_selection_unit-t \
  hostgroup_routing_unit-t \
	transaction_state_unit-t \
	pgsql_error_classifier_unit-t \
	pgsql_monitor_unit-t \
	mysql_error_classifier_unit-t \
	backend_sync_unit-t

.PHONY: all
all: $(UNIT_TESTS)

.PHONY: debug
debug: OPT += -DDEBUG
debug: $(UNIT_TESTS)

ALLOW_MULTI_DEF :=
ifneq ($(UNAME_S),Darwin)
	ALLOW_MULTI_DEF := -Wl,--allow-multiple-definition
endif

# Pattern rule: all unit tests use the same compile + link flags.
# Each test binary is built from its .cpp source, linked against
# the test harness objects and libproxysql.a with all dependencies.
%-t: %-t.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		$(LIBPROXYSQLAR_FULL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@


# ===========================================================================
# Clean
# ===========================================================================

.PHONY: clean
.SILENT: clean
clean:
	rm -rf $(ODIR) $(UNIT_TESTS)
