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

# ClickHouse library: auto-detect if built (always built in current builds)
# Append LZ4/ZSTD again after ClickHouse to resolve its dependencies
ifneq ($(wildcard $(CLICKHOUSE_CPP_LDIR)/libclickhouse-cpp-lib.a),)
	STATIC_LIBS += $(CLICKHOUSE_CPP_LDIR)/libclickhouse-cpp-lib.a \
				   $(LZ4_LDIR)/liblz4.a $(ZSTD_LDIR)/libzstd.a
endif

ifeq ($(UNAME_S),Linux)
	STATIC_LIBS += $(COREDUMPER_LDIR)/libcoredumper.a
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

# Auto-detect feature flags from libproxysql.a symbols.
# This ensures unit tests compile with the same flags the library was built with,
# regardless of whether the environment variables are set during `make`.
PSQLCH :=
ifneq ($(shell nm $(LIBPROXYSQLAR) 2>/dev/null | grep -c ClickHouse_Server),0)
	PROXYSQLCLICKHOUSE := 1
	PSQLCH := -DPROXYSQLCLICKHOUSE
endif
PSQLGA :=
ifneq ($(shell nm $(LIBPROXYSQLAR) 2>/dev/null | grep -c GenAI_Thread),0)
	PROXYSQLGENAI := 1
	PSQLGA := -DPROXYSQLGENAI
endif
PSQLFFTO :=
ifneq ($(shell nm $(LIBPROXYSQLAR) 2>/dev/null | grep -c MySQLFFTO),0)
	PROXYSQLFFTO := 1
	PSQLFFTO := -DPROXYSQLFFTO
endif
PSQL31 :=
ifneq ($(shell nm $(LIBPROXYSQLAR) 2>/dev/null | grep -c MySQLFFTO),0)
	PROXYSQL31 := 1
	PSQL31 := -DPROXYSQL31
endif
PSQLTSDB :=
ifneq ($(shell nm $(LIBPROXYSQLAR) 2>/dev/null | grep -c init_tsdb_variables),0)
	PROXYSQLTSDB := 1
	PSQLTSDB := -DPROXYSQLTSDB
endif

ifeq ($(PROXYSQLGENAI),1)
	STATIC_LIBS += $(SQLITE3_LDIR)/../libsqlite_rembed.a $(SQLITE3_LDIR)/vec.o
endif
PSQLDEBUG :=
ifneq ($(shell nm $(LIBPROXYSQLAR) 2>/dev/null | grep -cw 'init_debug_struct'),0)
	PSQLDEBUG := -DDEBUG
endif

OPT := $(STDCPP) -O0 -ggdb $(PSQLCH) $(PSQLGA) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB) $(PSQLDEBUG) \
	   -DGITVERSION=\"$(GIT_VERSION)\" $(NOJEM) $(WGCOV) $(WASAN) \
	   -Wl,--no-as-needed -Wl,-rpath,$(TAP_LDIR)

ifeq ($(UNAME_S),Darwin)
	OPT := $(STDCPP) -O0 -ggdb $(PSQLCH) $(PSQLGA) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB) $(PSQLDEBUG) \
		   -DGITVERSION=\"$(GIT_VERSION)\" $(NOJEM) $(WGCOV) $(WASAN)
endif


# ===========================================================================
# Test helper objects
# ===========================================================================

TEST_HELPERS_DIR := $(PROXYSQL_PATH)/test/tap/test_helpers
FAKE_PLUGIN_SO := $(TEST_HELPERS_DIR)/libproxysql_fake_plugin.so
MYSQLX_PLUGIN_SO := $(PROXYSQL_PATH)/plugins/mysqlx/ProxySQL_MySQLX_Plugin.so
MYSQLX_PLUGIN_OPTZ := -O0 -ggdb $(filter -DDEBUG,$(OPT))
ODIR := obj
PROXYSQL_TEST_HEADERS := $(wildcard $(PROXYSQL_PATH)/include/*.h) $(wildcard $(PROXYSQL_PATH)/include/*.hpp)

TEST_HELPERS_OBJ := $(ODIR)/test_globals.o $(ODIR)/test_init.o $(ODIR)/tap.o

$(ODIR):
	mkdir -p $(ODIR)

# Compile tap.o directly from tap.cpp to avoid the full TAP build chain
# and its cpp-dotenv dependency (which doesn't build on macOS).
# Unit tests only need the core TAP functions: plan(), ok(), is(), etc.
TAP_SRC := $(TAP_PATH)/tap.cpp
$(ODIR)/tap.o: $(TAP_SRC) | $(ODIR)
	$(CXX) -c -o $@ $< $(OPT) $(IDIRS) -w

$(ODIR)/test_globals.o: $(TEST_HELPERS_DIR)/test_globals.cpp $(PROXYSQL_TEST_HEADERS) | $(ODIR)
	$(CXX) -c -o $@ $< $(OPT) $(IDIRS) -I$(PROXYSQL_PATH)/test -Wall

$(ODIR)/test_init.o: $(TEST_HELPERS_DIR)/test_init.cpp $(PROXYSQL_TEST_HEADERS) | $(ODIR)
	$(CXX) -c -o $@ $< $(OPT) $(IDIRS) -Wall

$(FAKE_PLUGIN_SO): $(TEST_HELPERS_DIR)/fake_plugin.cpp $(PROXYSQL_PATH)/include/ProxySQL_Plugin.h | $(TEST_HELPERS_DIR)
	$(CXX) -shared -fPIC -o $@ $< $(STDCPP) $(IDIRS) -ldl

.PHONY: mysqlx_plugin_build
mysqlx_plugin_build:
	$(MAKE) -C $(PROXYSQL_PATH)/plugins/mysqlx all \
		CC=$(CC) CXX=$(CXX) OPTZ="$(MYSQLX_PLUGIN_OPTZ)" \
		WGCOV="$(WGCOV)" WASAN="$(WASAN)"

# Keep on-demand unit-test library rebuilds aligned with the default top-level
# feature set so incremental rebuilds do not mix incompatible objects.
# Always delegate libproxysql.a freshness checks to the lib submake so unit
# tests do not link against a stale archive after source/header changes.
.PHONY: FORCE
FORCE:

$(LIBPROXYSQLAR): FORCE
	$(MAKE) -C $(PROXYSQL_PATH)/lib libproxysql.a \
		PROXYSQLCLICKHOUSE=1 PROXYSQLGENAI=$(PROXYSQLGENAI) \
		PROXYSQLFFTO=$(PROXYSQLFFTO) PROXYSQLTSDB=$(PROXYSQLTSDB) \
		PROXYSQL31=$(PROXYSQL31) CC=$(CC) CXX=$(CXX)


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
	backend_sync_unit-t \
	mysql_encode_unit-t \
	pgsql_variables_validator_unit-t \
	proxysql_utils_unit-t \
	gen_utils_unit-t \
	proxy_protocol_unit-t \
	pgsql_txn_state_unit-t \
	genai_anomaly_unit-t \
	genai_fts_string_unit-t \
	sqlite3db_unit-t \
	pgsql_error_helper_unit-t \
	genai_stats_parsing_unit-t \
	genai_llm_clients_unit-t \
	charset_find_unit-t \
	genai_query_handler_unit-t \
	genai_mcp_endpoint_unit-t \
	genai_mcp_thread_unit-t \
	config_validation_unit-t \
	config_write_unit-t \
	query_processor_firewall_unit-t \
	statistics_unit-t \
	log_utils_unit-t \
	genai_thread_unit-t \
	listen_validator_unit-t \
	plugin_config_unit-t \
	c_tokenizer_unit-t \
	pgsql_tokenizer_unit-t \
	ezoption_parser_unit-t \
	genai_discovery_schema_unit-t \
	gtid_utils_unit-t \
	genai_mysql_catalog_unit-t \
	admin_disk_upgrade_unit-t \
	glovars_unit-t \
	plugin_manager_unit-t \
	plugin_registry_unit-t \
	test_mysqlx_plugin_load-t \
	mysqlx_config_store_unit-t \
	test_mysqlx_admin_tables-t \
	test_mysqlx_listener_smoke-t \
	mysqlx_protocol_unit-t \
	mysqlx_protocol_socket_unit-t \
	mysqlx_route_store_unit-t \
	mysqlx_stats_unit-t \
	mysqlx_config_store_concurrent_unit-t \
	mysqlx_config_store_pure_unit-t \
	mysqlx_admin_schema_unit-t

.PHONY: all
all: $(UNIT_TESTS)

.PHONY: debug
debug: OPT += -DDEBUG
debug: $(UNIT_TESTS)

ALLOW_MULTI_DEF :=
ifneq ($(UNAME_S),Darwin)
	ALLOW_MULTI_DEF := -Wl,--allow-multiple-definition
endif

# Standalone header-only tests: need tap.o + noise stubs, no libproxysql.a
$(ODIR)/tap_noise_stubs.o: | $(ODIR)
	@printf '#include <vector>\n#include <string>\n#include <mutex>\nstd::vector<std::string> noise_failures;\nstd::mutex noise_failure_mutex;\nextern "C" { void stop_noise_tools(){} int get_noise_tools_count(){return 0;} }\n' | \
		$(CXX) -x c++ -c -o $@ - $(STDCPP)

ezoption_parser_unit-t: ezoption_parser_unit-t.cpp $(ODIR)/tap.o $(ODIR)/tap_noise_stubs.o
	$(CXX) $< $(ODIR)/tap.o $(ODIR)/tap_noise_stubs.o \
		-I$(TAP_IDIR) -I$(PROXYSQL_PATH)/include \
		$(STDCPP) -O0 -ggdb $(WGCOV) $(LWGCOV) -lpthread -o $@

plugin_manager_unit-t: plugin_manager_unit-t.cpp $(FAKE_PLUGIN_SO) $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR)
	$(CXX) $< $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		-DPROXYSQL_FAKE_PLUGIN_PATH=\"$(FAKE_PLUGIN_SO)\" \
		$(IDIRS) $(LDIRS) $(OPT) $(LIBPROXYSQLAR_FULL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

plugin_config_unit-t: plugin_config_unit-t.cpp $(FAKE_PLUGIN_SO) $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR)
	$(CXX) $< $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		-DPROXYSQL_FAKE_PLUGIN_PATH=\"$(FAKE_PLUGIN_SO)\" \
		$(IDIRS) $(LDIRS) $(OPT) $(LIBPROXYSQLAR_FULL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

test_mysqlx_plugin_load-t: ../test_mysqlx_plugin_load-t.cpp $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR) mysqlx_plugin_build
	$(CXX) ../test_mysqlx_plugin_load-t.cpp $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		-DPROXYSQL_MYSQLX_PLUGIN_PATH=\"$(MYSQLX_PLUGIN_SO)\" \
		$(IDIRS) $(LDIRS) $(OPT) $(LIBPROXYSQLAR_FULL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

mysqlx_config_store_unit-t: mysqlx_config_store_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(LIBPROXYSQLAR_FULL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@

mysqlx_config_store_concurrent_unit-t: mysqlx_config_store_concurrent_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(LIBPROXYSQLAR_FULL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -lpthread -o $@

mysqlx_config_store_pure_unit-t: mysqlx_config_store_pure_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(LIBPROXYSQLAR_FULL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@

mysqlx_admin_schema_unit-t: mysqlx_admin_schema_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_admin_schema.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_admin_schema.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(LIBPROXYSQLAR_FULL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@

MYSQLX_PROTO_DIR := $(PROXYSQL_PATH)/plugins/mysqlx/proto
MYSQLX_PROTO_SRCS := $(wildcard $(MYSQLX_PROTO_DIR)/*.pb.cc)
MYSQLX_PROTO_OBJS := $(patsubst $(MYSQLX_PROTO_DIR)/%.pb.cc,$(ODIR)/mysqlx_proto_%.pb.o,$(MYSQLX_PROTO_SRCS))

$(ODIR)/mysqlx_proto_%.pb.o: $(MYSQLX_PROTO_DIR)/%.pb.cc | $(ODIR)
	$(CXX) -c -o $@ $< $(STDCPP) -fPIC -O0 -ggdb -I$(MYSQLX_PROTO_DIR) -w

mysqlx_stats_unit-t: mysqlx_stats_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(LIBPROXYSQLAR_FULL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@

mysqlx_route_store_unit-t: mysqlx_route_store_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(LIBPROXYSQLAR_FULL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@

mysqlx_protocol_unit-t: mysqlx_protocol_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) $(LIBPROXYSQLAR_FULL) $(STATIC_LIBS) \
		$(MYLIBS) -lprotobuf -lssl -lcrypto $(ALLOW_MULTI_DEF) -o $@

mysqlx_protocol_socket_unit-t: mysqlx_protocol_socket_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) $(LIBPROXYSQLAR_FULL) $(STATIC_LIBS) \
		$(MYLIBS) -lprotobuf -lssl -lcrypto $(ALLOW_MULTI_DEF) -o $@

test_mysqlx_listener_smoke-t: ../test_mysqlx_listener_smoke-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_worker.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR) mysqlx_plugin_build
	$(CXX) ../test_mysqlx_listener_smoke-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_worker.cpp $(TEST_HELPERS_OBJ) \
		-DPROXYSQL_MYSQLX_PLUGIN_PATH=\"$(MYSQLX_PLUGIN_SO)\" \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(IDIRS) $(LDIRS) $(OPT) $(LIBPROXYSQLAR_FULL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl -lpthread $(ALLOW_MULTI_DEF) -o $@

test_mysqlx_admin_tables-t: ../test_mysqlx_admin_tables-t.cpp $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR) mysqlx_plugin_build
	$(CXX) ../test_mysqlx_admin_tables-t.cpp $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		-DPROXYSQL_MYSQLX_PLUGIN_PATH=\"$(MYSQLX_PLUGIN_SO)\" \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(IDIRS) $(LDIRS) $(OPT) $(LIBPROXYSQLAR_FULL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

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
	rm -rf $(ODIR) $(UNIT_TESTS) $(FAKE_PLUGIN_SO)
