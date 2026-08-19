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
			-I$(PARSERSQL_IDIR) \
			-I$(PROXYSQL_PATH)/deps/lz4/lz4/lib \
			-I$(PROXYSQL_PATH)/include \
			-I$(PROXYSQL_PATH)/test/tap/test_helpers

ifdef PROXYSQL40
IDIRS += -I$(PROXYSQL_PATH)/plugins/genai/include

# ProxySQL vendors protobuf 3.21.12 under deps/protobuf/ and builds it
# into deps/protobuf/protobuf-3.21.12/install/. The committed
# plugins/mysqlx/proto/*.pb.h files are generated against that exact
# version and include headers (e.g. <google/protobuf/generated_message_bases.h>)
# that only exist in protobuf 3.16+. Every unit-test rule below that
# transitively pulls in mysqlx.pb.h through plugins/mysqlx/src/*.cpp
# must see those headers, otherwise gcc silently falls through to its
# default /usr/include/ search path and either fails to find protobuf
# at all (clean GH-hosted ubuntu-22.04) or picks up the system 3.12.4
# headers (Ubuntu 22.04 / Debian 11 libprotobuf-dev) which are missing
# the newer includes -- both modes seen on PR #5823.
#
# Add to the shared IDIRS so every rule using $(IDIRS) inherits the
# include path, instead of patching each ~22 mysqlx unit-test rule
# individually. Only meaningful when PROXYSQL40=1 because that's the
# only build configuration that vendors / builds protobuf
# (deps/Makefile gates `targets += protobuf` on PROXYSQL40=1).
PROTOBUF_VERSION := 3.21.12
PROTOBUF_INSTALL_DIR := $(PROXYSQL_PATH)/deps/protobuf/protobuf-$(PROTOBUF_VERSION)/install
PROTOBUF_INCLUDE_DIR := $(PROTOBUF_INSTALL_DIR)/include
PROTOBUF_LDIR := $(PROTOBUF_INSTALL_DIR)/lib
PROTOBUF_LIB := $(PROTOBUF_LDIR)/libprotobuf.a
IDIRS += -I$(PROTOBUF_INCLUDE_DIR)
# NOTE: the matching `LDIRS += -L$(PROTOBUF_LDIR)` lives further down,
# after the LDIRS := initial assignment (~line 86). Appending here
# would be silently wiped by that later := redefinition. See the
# duplicate ifdef PROXYSQL40 block below.
endif


# ===========================================================================
# Library directories
# ===========================================================================

LDIRS :=	-L$(TAP_LDIR) \
			-L$(RE2_LDIR) \
			-L$(ABSL_LDIR) \
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
			-L$(SSL_LDIR) \
			-L$(PARSERSQL_LDIR)

ifeq ($(UNAME_S),Linux)
	LDIRS += -L$(COREDUMPER_LDIR)
endif
ifeq ($(UNAME_S),Darwin)
	IDIRS += -I/usr/local/include -I/opt/homebrew/include
	LDIRS += -L/usr/local/lib -L/opt/homebrew/lib
endif

# mysqlx_*_unit-t rules below link the vendored protobuf static
# archive at $(PROTOBUF_LIB) explicitly (full path, not -lprotobuf).
# Earlier versions of this Makefile used `-lprotobuf` and relied on
# `-L$(PROTOBUF_LDIR)` putting the vendored install first in the link
# search path. That worked on hosts without libprotobuf-dev, but on
# CI runners where the deb-compliant entrypoint apt-installs
# libprotobuf-dev (system v3.12), `-Bdynamic -lprotobuf` resolves to
# the system .so before falling through to the vendored .a (vendored
# build is static-only). The proto-generated .pb.o references symbols
# only in v3.21.12 (ZeroFieldsBase, AddDescriptorsRunner, ...), so
# the link fails with thousands of undefined references against the
# system v3.12. Mirror plugins/mysqlx/Makefile, which references the
# .a by full path for the same reason.
#
# LDIRS still picks up PROTOBUF_LDIR for transitive deps that may use
# pkg-config or autotools-driven search.
ifdef PROXYSQL40
LDIRS += -L$(PROTOBUF_LDIR)
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

ifneq ($(PROXYSQL40),)
ifneq ($(wildcard $(SQLITE3_LDIR)/vec.o),)
	STATIC_LIBS += $(SQLITE3_LDIR)/vec.o
endif
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
	$(PARSERSQL_LDIR)/libsqlparser.a \
	$(LIBINJECTION_LDIR)/libinjection.a \
	$(EV_LDIR)/libev.a \
	$(LIBSCRAM_LDIR)/libscram.a \
	$(LIBUSUAL_LDIR)/libusual.a \
	$(MARIADB_LDIR)/libmariadbclient.a \
	$(RE2_STATIC_LIB) $(RE2_ABSL_LIBS) \
	$(POSTGRESQL_PATH)/interfaces/libpq/libpq.a \
	$(POSTGRESQL_PATH)/common/libpgcommon.a \
	$(POSTGRESQL_PATH)/port/libpgport.a

MYLIBS := -lssl -lcrypto -lpthread -lm -lz \
		  -liconv -lgnutls -lprometheus-cpp-pull -lprometheus-cpp-core -luuid \
		  -lzstd $(LWGCOV)
else
# Linux/FreeBSD: Use -Bstatic/-Bdynamic for controlled linking.
LIBPROXYSQLAR_FULL := $(LIBPROXYSQLAR)

# Linux: do NOT list `-lproxysql` here. The pattern rule (and explicit
# per-test rules) link libproxysql.a once via $(WHOLE_LIBPROXYSQL); a
# second `-lproxysql` reference combined with `--whole-archive` would
# pull every .oo in twice, producing ODR violations under ASAN
# (`detect_odr_violation=1` aborts at startup; ld is silenced by
# `--allow-multiple-definition`).
MYLIBS := -Wl,--export-dynamic -Wl,-Bdynamic -lgnutls -lcurl -lssl -lcrypto -luuid \
		  -Wl,-Bstatic -lconfig -lsqlparser -ldaemon -lconfig++ $(RE2_STATIC_LIBS) -lpcrecpp -lpcre \
		  -lmariadbclient -lhttpserver -lmicrohttpd -linjection -lev \
		  -lprometheus-cpp-pull -lprometheus-cpp-core \
		  -Wl,-Bstatic -lpq -lpgcommon -lpgport \
		  -Wl,-Bdynamic -lpthread -lm -lz -lzstd -lrt -ldl \
		  -lscram -lusual -Wl,--allow-multiple-definition \
		  $(LWGCOV)
endif

# WHOLE_LIBPROXYSQL holds the platform-correct way to force every member
# of libproxysql.a into the link, so unit tests that dlopen plugin .so
# files (genai_plugin_load_unit-t, plugin_*_unit-t, ...) export every
# libproxysql symbol the plugin might reference.
#
# On Linux/FreeBSD it wraps the file path in `-Wl,--whole-archive`; on
# macOS it's just the file path because LIBPROXYSQLAR_FULL there already
# enumerates every dep .a explicitly and Apple's ld does not support
# `--whole-archive` (it uses `-force_load` instead).
ifeq ($(UNAME_S),Darwin)
WHOLE_LIBPROXYSQL := $(LIBPROXYSQLAR_FULL)
else
WHOLE_LIBPROXYSQL := -Wl,--whole-archive $(LIBPROXYSQLAR_FULL) -Wl,--no-whole-archive
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
PSQLFFTO :=
ifneq ($(shell nm $(LIBPROXYSQLAR) 2>/dev/null | grep -c MySQLFFTO),0)
	PROXYSQLFFTO := 1
	PSQLFFTO := -DPROXYSQLFFTO
endif

# PROXYSQL40 — detected via a chassis-exclusive symbol that only exists
# when libproxysql.a was built with -DPROXYSQL40 (the four-phase plugin
# lifecycle). `invoke_register_schemas_phase` is the canonical probe.
PSQL40 :=
ifneq ($(shell nm $(LIBPROXYSQLAR) 2>/dev/null | grep -c invoke_register_schemas_phase),0)
	PROXYSQL40 := 1
	PSQL40 := -DPROXYSQL40
endif
PSQLTSDB :=
ifneq ($(shell nm $(LIBPROXYSQLAR) 2>/dev/null | grep -c init_tsdb_variables),0)
	PROXYSQLTSDB := 1
	PSQLTSDB := -DPROXYSQLTSDB
endif

PSQLED25519 :=
ifneq ($(shell nm $(LIBPROXYSQLAR) 2>/dev/null | grep -c proxysql_ed25519_verify_signature),0)
	PROXYSQLED25519 := 1
	PSQLED25519 := -DPROXYSQLED25519
endif

# PROXYSQL31 is the parent tier flag for FFTO + TSDB; the codebase has no
# #ifdef PROXYSQL31 blocks of its own, so autodetect it as "at least one
# of FFTO or TSDB is enabled".  This matches the top-level Makefile's
# cascade (PROXYSQL31=1 => PROXYSQLFFTO=1 && PROXYSQLTSDB=1).
PSQL31 :=
ifneq ($(PROXYSQLFFTO)$(PROXYSQLTSDB),)
	PROXYSQL31 := 1
	PSQL31 := -DPROXYSQL31
endif

ifneq ($(PROXYSQL40),)
ifneq ($(wildcard $(SQLITE3_LDIR)/vec.o),)
	STATIC_LIBS += $(SQLITE3_LDIR)/vec.o
endif
endif
PSQLDEBUG :=
ifneq ($(shell nm $(LIBPROXYSQLAR) 2>/dev/null | grep -cw 'init_debug_struct'),0)
	PSQLDEBUG := -DDEBUG
endif

# The unit-test archive freshness rule below rebuilds libproxysql.a in a
# submake.  Keep that rebuild in the same DEBUG configuration detected above:
# MySQL_Data_Stream embeds MySQL_Protocol, whose DEBUG-only members affect the
# public class layout used by both the archive and these test translation units.
LIB_OPTZ_ARG :=
ifneq ($(PSQLDEBUG),)
	LIB_OPTZ_ARG := OPTZ="-O0 -ggdb -DDEBUG"
endif

# MYSQLX_TEST_BUILD enables the test-only methods (`*_for_test`) on the
# mysqlx plugin's public classes (e.g. MysqlxSession::inject_identity_for_test).
# Defined ONLY here, in the unit-test Makefile — never in plugins/mysqlx/Makefile.
# That way the production .so does not compile in entry points that could be
# misused (most importantly identity-forgery setters), while tests that include
# the plugin headers and link against the plugin sources still see the helpers
# they need.
OPT := $(STDCPP) -O0 -ggdb $(PSQLCH) $(PSQLGA) $(PSQL40) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB) $(PSQLED25519) $(PSQLDEBUG) \
	   -DGITVERSION=\"$(GIT_VERSION)\" -DMYSQLX_TEST_BUILD $(NOJEM) $(WGCOV) $(WASAN) \
	   -Wl,--no-as-needed -Wl,-rpath,$(TAP_LDIR)

ifeq ($(UNAME_S),Darwin)
	OPT := $(STDCPP) -O0 -ggdb $(PSQLCH) $(PSQLGA) $(PSQL40) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB) $(PSQLED25519) $(PSQLDEBUG) \
		   -DGITVERSION=\"$(GIT_VERSION)\" -DMYSQLX_TEST_BUILD $(NOJEM) $(WGCOV) $(WASAN)
endif


# ===========================================================================
# Test helper objects
# ===========================================================================

TEST_HELPERS_DIR := $(PROXYSQL_PATH)/test/tap/test_helpers
FAKE_PLUGIN_SO := $(TEST_HELPERS_DIR)/libproxysql_fake_plugin.so
FAKE_PLUGIN2_SO := $(TEST_HELPERS_DIR)/libproxysql_fake_plugin2.so
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
	$(CXX) -shared -fPIC -o $@ $< $(STDCPP) $(PSQL40) $(IDIRS) -ldl

.PHONY: mysqlx_plugin_build
mysqlx_plugin_build:
	$(MAKE) -C $(PROXYSQL_PATH)/plugins/mysqlx all \
		CC=$(CC) CXX=$(CXX) OPTZ="$(MYSQLX_PLUGIN_OPTZ)" \
		WGCOV="$(WGCOV)" WASAN="$(WASAN)" \
		PROXYSQL40=$(PROXYSQL40) \
		PROXYSQL31=$(PROXYSQL31) PROXYSQLFFTO=$(PROXYSQLFFTO) \
		PROXYSQLTSDB=$(PROXYSQLTSDB)

# Same source compiled with different macros to produce a second plugin .so
# with a distinct plugin name and env-var prefix.  Used by multi-plugin tests.
$(FAKE_PLUGIN2_SO): $(TEST_HELPERS_DIR)/fake_plugin.cpp $(PROXYSQL_PATH)/include/ProxySQL_Plugin.h | $(TEST_HELPERS_DIR)
	$(CXX) -shared -fPIC -o $@ $< $(STDCPP) $(PSQL40) $(IDIRS) -ldl \
		-DFAKE_PLUGIN_NAME=\"fake_plugin2\" \
		-DFAKE_PLUGIN_ENV_PREFIX=\"PROXYSQL_FAKE_PLUGIN2_\"

# Keep on-demand unit-test library rebuilds aligned with the default top-level
# feature set so incremental rebuilds do not mix incompatible objects.
# Always delegate libproxysql.a freshness checks to the lib submake so unit
# tests do not link against a stale archive after source/header changes.
.PHONY: FORCE
FORCE:

$(LIBPROXYSQLAR): FORCE
	$(MAKE) -C $(PROXYSQL_PATH)/lib libproxysql.a \
		PROXYSQLCLICKHOUSE=1 \
		PROXYSQLFFTO=$(PROXYSQLFFTO) PROXYSQLTSDB=$(PROXYSQLTSDB) \
		PROXYSQLED25519=$(PROXYSQLED25519) \
		PROXYSQL40=$(PROXYSQL40) PROXYSQL31=$(PROXYSQL31) \
		$(LIB_OPTZ_ARG) CC=$(CC) CXX=$(CXX)


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
	mysql_variables_unit-t \
	mysql_user_variables_unit-t \
	mysql_decompress_payload_unit-t \
	mysql_resolution_unit-t \
	pgsql_variables_validator_unit-t \
	proxysql_utils_unit-t \
	gen_utils_unit-t \
	proxy_protocol_unit-t \
	pgsql_txn_state_unit-t \
	sqlite3db_unit-t \
	pgsql_error_helper_unit-t \
	charset_find_unit-t \
	config_validation_unit-t \
	config_write_unit-t \
	query_processor_firewall_unit-t \
	statistics_unit-t \
	log_utils_unit-t \
	listen_validator_unit-t \
	c_tokenizer_unit-t \
	pgsql_tokenizer_unit-t \
	ezoption_parser_unit-t \
	gtid_trxid_interval_unit-t \
	gtid_set_unit-t \
	gtid_server_data_unit-t \
	admin_disk_upgrade_unit-t \
	glovars_unit-t \
	pgsql_servers_ssl_params_unit-t \
	connection_unhealthy_unit-t \
	cluster_sync_unit-t \
	parsersql_unit-t \
	pgsql_query_processor_unit-t \
	http_server_unit-t \
	mysql_resultset_framer_unit-t \
	mysql_resultset_framer_traffic_unit-t \
	pgsql_response_framer_unit-t \
	pgsql_response_framer_traffic_unit-t \
	ffto_state_machine_unit-t \
	re2_vendor_unit-t \
	restapi_server_unit-t \
	mcp_client_unit-t

ifeq ($(PROXYSQL31),1)
UNIT_TESTS += caching_sha2_rsa_unit-t
endif

ifeq ($(PROXYSQLED25519),1)
UNIT_TESTS += ed25519_unit-t
endif

# GenAI units declared in the ai-g1/ai-g2 TAP shards. Keep this focused list
# separate from the three plugin-lifecycle units, which are not group members.
AI_GENAI_UNIT_TESTS := \
	genai_config_query_unit-t \
	genai_discovery_schema_unit-t \
	genai_fts_string_unit-t \
	genai_llm_clients_unit-t \
	genai_mcp_endpoint_unit-t \
	genai_mcp_thread_unit-t \
	genai_mysql_catalog_unit-t \
	genai_query_handler_unit-t \
	genai_rag_fetch_from_source_unit-t \
	genai_stats_parsing_unit-t \
	genai_thread_unit-t

# Plugin-chassis + mysqlx-plugin unit tests — built only when
# libproxysql.a was compiled with -DPROXYSQL40 (autodetected higher up
# in this Makefile).  v3.0/v3.1 builds have no plugin loader and the
# mysqlx plugin source references chassis types, so none of these are
# compilable under !PROXYSQL40.
ifeq ($(PROXYSQL40),1)
# mysqlx + plugin + test_mysqlx unit tests: always built under PROXYSQL40=1.
UNIT_TESTS += \
	plugin_config_unit-t \
	plugin_dispatch_unit-t \
	plugin_manager_unit-t \
	plugin_registry_unit-t \
	plugin_query_hook_unit-t \
	plugin_prometheus_unit-t \
	plugin_lifecycle_unit-t \
	plugin_runtime_views_unit-t \
	test_mysqlx_plugin_load-t \
	test_mysqlx_admin_tables-t \
	mysqlx_config_store_unit-t \
	mysqlx_config_store_concurrent_unit-t \
	mysqlx_config_store_pure_unit-t \
	mysqlx_protocol_unit-t \
	mysqlx_protocol_socket_unit-t \
	mysqlx_route_store_unit-t \
	mysqlx_stats_unit-t \
	mysqlx_admin_schema_unit-t \
	mysqlx_admin_commands_unit-t \
	mysqlx_admin_disk_commands_unit-t \
	mysqlx_data_stream_unit-t \
	mysqlx_connection_unit-t \
	mysqlx_session_unit-t \
	mysqlx_thread_unit-t \
	mysqlx_message_dispatch_unit-t \
	mysqlx_concurrent_unit-t \
	mysqlx_backend_auth_unit-t \
	mysqlx_credential_verify_unit-t \
	mysqlx_robustness_unit-t \
	mysqlx_tls_unit-t \
	mysqlx_compression_unit-t

# genai_*_unit-t binaries: each statically links 30+
# plugins/genai/src/*.cpp files. At debug -O0 -ggdb each lands at
# ~160 MB; the full 14-binary set is ~2 GB compiled and bloats the
# in-build working set on disk-constrained CI runners. CI-mysqlx
# (the only consumer of the -tap-mysqlx CI-builds matrix variant)
# does not run any of these. Set SKIP_GENAI_UNIT_TESTS=1 (injected
# via docker-compose env from ci-builds.yml's matrix-conditional
# block) to skip building them. Leave it unset on every other CI
# variant so the full unit-test suite still compiles when
# CI-unittests is re-enabled.
ifneq ($(SKIP_GENAI_UNIT_TESTS),1)
UNIT_TESTS += $(AI_GENAI_UNIT_TESTS) \
	genai_plugin_load_unit-t \
	genai_plugin_anomaly_unit-t \
	genai_plugin_backend_client_unit-t
endif
endif

.PHONY: all
all: $(UNIT_TESTS)

# Alias: top-level 'make unit_tests' (via test/tap/Makefile) forwards the goal
# name here via $(MAKECMDGOALS), so this target must exist even though `all`
# does the same thing.
.PHONY: unit_tests
unit_tests: all

.PHONY: ai_genai_unit_tests
.NOTPARALLEL: ai_genai_unit_tests
ai_genai_unit_tests: $(AI_GENAI_UNIT_TESTS)

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
		$(STDCPP) -O0 -ggdb $(WGCOV) $(LWGCOV) $(WASAN) -lpthread -o $@

mcp_client_unit-t: mcp_client_unit-t.cpp $(TAP_PATH)/mcp_client.cpp $(ODIR)/tap.o $(ODIR)/tap_noise_stubs.o
	$(CXX) $< $(TAP_PATH)/mcp_client.cpp $(ODIR)/tap.o $(ODIR)/tap_noise_stubs.o \
		$(IDIRS) $(LDIRS) $(OPT) -Wl,-Bdynamic -lcurl -lpthread -o $@

re2_vendor_unit-t: re2_vendor_unit-t.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(TEST_HELPERS_OBJ) $(IDIRS) -I$(ABSL_IDIR) $(LDIRS) $(OPT) \
		$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@

plugin_manager_unit-t: plugin_manager_unit-t.cpp $(FAKE_PLUGIN_SO) $(FAKE_PLUGIN2_SO) $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR)
	$(CXX) $< $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		-DPROXYSQL_FAKE_PLUGIN_PATH=\"$(FAKE_PLUGIN_SO)\" \
		-DPROXYSQL_FAKE_PLUGIN2_PATH=\"$(FAKE_PLUGIN2_SO)\" \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

plugin_config_unit-t: plugin_config_unit-t.cpp $(FAKE_PLUGIN_SO) $(FAKE_PLUGIN2_SO) $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR)
	$(CXX) $< $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		-DPROXYSQL_FAKE_PLUGIN_PATH=\"$(FAKE_PLUGIN_SO)\" \
		-DPROXYSQL_FAKE_PLUGIN2_PATH=\"$(FAKE_PLUGIN2_SO)\" \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

plugin_dispatch_unit-t: plugin_dispatch_unit-t.cpp $(FAKE_PLUGIN_SO) $(FAKE_PLUGIN2_SO) $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR)
	$(CXX) $< $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		-DPROXYSQL_FAKE_PLUGIN_PATH=\"$(FAKE_PLUGIN_SO)\" \
		-DPROXYSQL_FAKE_PLUGIN2_PATH=\"$(FAKE_PLUGIN2_SO)\" \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

plugin_runtime_views_unit-t: plugin_runtime_views_unit-t.cpp $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR)
	$(CXX) $< $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

test_mysqlx_plugin_load-t: ../test_mysqlx_plugin_load-t.cpp $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR) mysqlx_plugin_build
	$(CXX) ../test_mysqlx_plugin_load-t.cpp $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		-DPROXYSQL_MYSQLX_PLUGIN_PATH=\"$(MYSQLX_PLUGIN_SO)\" \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

mysqlx_config_store_unit-t: mysqlx_config_store_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@

mysqlx_config_store_concurrent_unit-t: mysqlx_config_store_concurrent_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -lpthread -o $@

mysqlx_config_store_pure_unit-t: mysqlx_config_store_pure_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@

mysqlx_admin_schema_unit-t: mysqlx_admin_schema_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_admin_schema.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_admin_schema.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@

mysqlx_admin_commands_unit-t: mysqlx_admin_commands_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_admin_schema.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_admin_schema.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@

mysqlx_admin_disk_commands_unit-t: mysqlx_admin_disk_commands_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_admin_schema.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_admin_schema.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@

MYSQLX_PROTO_DIR := $(PROXYSQL_PATH)/plugins/mysqlx/proto
MYSQLX_PROTO_SRCS := $(wildcard $(MYSQLX_PROTO_DIR)/*.pb.cc)
MYSQLX_PROTO_OBJS := $(patsubst $(MYSQLX_PROTO_DIR)/%.pb.cc,$(ODIR)/mysqlx_proto_%.pb.o,$(MYSQLX_PROTO_SRCS))

# Compiles plugins/mysqlx/proto/*.pb.cc into mysqlx_proto_*.pb.o.
# PROTOBUF_LIB / PROTOBUF_INCLUDE_DIR are defined at the top of this
# Makefile under `ifdef PROXYSQL40` -- the same place where IDIRS gets
# `-I$(PROTOBUF_INCLUDE_DIR)` appended, so $(IDIRS) here already covers
# the vendored protobuf headers. PROTOBUF_LIB as a prerequisite chains
# the deps protobuf build for anyone running this target standalone
# (the top-level `make debug` chain already builds it via build_deps_*).
$(ODIR)/mysqlx_proto_%.pb.o: $(MYSQLX_PROTO_DIR)/%.pb.cc $(PROTOBUF_LIB) | $(ODIR)
	$(CXX) -c -o $@ $< $(STDCPP) -fPIC -O0 -ggdb \
		-I$(MYSQLX_PROTO_DIR) $(IDIRS) -w

mysqlx_stats_unit-t: mysqlx_stats_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@

mysqlx_route_store_unit-t: mysqlx_route_store_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@

mysqlx_protocol_unit-t: mysqlx_protocol_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) $(PROTOBUF_LIB) -lssl -lcrypto $(ALLOW_MULTI_DEF) -o $@

mysqlx_protocol_socket_unit-t: mysqlx_protocol_socket_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) $(PROTOBUF_LIB) -lssl -lcrypto $(ALLOW_MULTI_DEF) -o $@

test_mysqlx_admin_tables-t: ../test_mysqlx_admin_tables-t.cpp $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR) mysqlx_plugin_build
	$(CXX) ../test_mysqlx_admin_tables-t.cpp $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		-DPROXYSQL_MYSQLX_PLUGIN_PATH=\"$(MYSQLX_PLUGIN_SO)\" \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

mysqlx_data_stream_unit-t: mysqlx_data_stream_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include \
		$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@

mysqlx_connection_unit-t: mysqlx_connection_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) \
		$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS) \
		$(PROTOBUF_LIB) -lssl -lcrypto $(ALLOW_MULTI_DEF) -o $@

mysqlx_session_unit-t: mysqlx_session_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_session.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_thread.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_session.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_thread.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) $(PROTOBUF_LIB) -lssl -lcrypto $(ALLOW_MULTI_DEF) -lpthread -o $@

mysqlx_thread_unit-t: mysqlx_thread_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_thread.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_session.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_thread.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_session.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) $(PROTOBUF_LIB) -lssl -lcrypto $(ALLOW_MULTI_DEF) -lpthread -o $@

mysqlx_message_dispatch_unit-t: mysqlx_message_dispatch_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_thread.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_session.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_thread.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_session.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) $(PROTOBUF_LIB) -lssl -lcrypto $(ALLOW_MULTI_DEF) -lpthread -o $@

mysqlx_concurrent_unit-t: mysqlx_concurrent_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_thread.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_session.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_thread.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_session.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) $(PROTOBUF_LIB) -lssl -lcrypto $(ALLOW_MULTI_DEF) -lpthread -o $@

mysqlx_backend_auth_unit-t: mysqlx_backend_auth_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) $(PROTOBUF_LIB) -lssl -lcrypto $(ALLOW_MULTI_DEF) -lpthread -o $@

mysqlx_credential_verify_unit-t: mysqlx_credential_verify_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) $(PROTOBUF_LIB) -lssl -lcrypto $(ALLOW_MULTI_DEF) -o $@

mysqlx_robustness_unit-t: mysqlx_robustness_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_session.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_thread.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_listener_reconcile.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_session.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_thread.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_listener_reconcile.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) $(PROTOBUF_LIB) -lssl -lcrypto $(ALLOW_MULTI_DEF) -lpthread -o $@

mysqlx_tls_unit-t: mysqlx_tls_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) $(PROTOBUF_LIB) -lssl -lcrypto $(ALLOW_MULTI_DEF) -lpthread -o $@

# X Protocol compression negotiation + decompression / compression wire-up.
# Same source-set as mysqlx_session_unit-t since it drives MysqlxSession via
# a socketpair; the underlying zstd/lz4 dependencies are pulled in through
# $(STATIC_LIBS) (the -lzstd already there) plus the explicit liblz4.a we
# add here for the lz4_message algorithm path.
mysqlx_compression_unit-t: mysqlx_compression_unit-t.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_session.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_thread.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_session.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_data_stream.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_connection.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_thread.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_protocol.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_config_store.cpp $(PROXYSQL_PATH)/plugins/mysqlx/src/mysqlx_stats.cpp $(MYSQLX_PROTO_OBJS) $(TEST_HELPERS_OBJ) \
		-I$(PROXYSQL_PATH)/plugins/mysqlx/include -I$(MYSQLX_PROTO_DIR) \
		-I$(ZSTD_IDIR) -I$(PROXYSQL_PATH)/deps/lz4/lz4/lib \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(LZ4_LDIR)/liblz4.a \
		$(MYLIBS) $(PROTOBUF_LIB) -lssl -lcrypto $(ALLOW_MULTI_DEF) -lpthread -o $@
mysql_resolution_unit-t: mysql_resolution_unit-t.cpp $(ODIR)/tap.o $(ODIR)/tap_noise_stubs.o
	$(CXX) $< $(ODIR)/tap.o $(ODIR)/tap_noise_stubs.o \
		-I$(TAP_IDIR) -I$(PROXYSQL_PATH)/include \
		$(STDCPP) -O0 -ggdb $(WGCOV) $(LWGCOV) $(WASAN) -lpthread -o $@

plugin_query_hook_unit-t: plugin_query_hook_unit-t.cpp $(FAKE_PLUGIN_SO) $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR)
	$(CXX) $< $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		-DPROXYSQL_FAKE_PLUGIN_PATH=\"$(FAKE_PLUGIN_SO)\" \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

plugin_prometheus_unit-t: plugin_prometheus_unit-t.cpp $(FAKE_PLUGIN_SO) $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR)
	$(CXX) $< $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		-DPROXYSQL_FAKE_PLUGIN_PATH=\"$(FAKE_PLUGIN_SO)\" \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

plugin_lifecycle_unit-t: plugin_lifecycle_unit-t.cpp $(FAKE_PLUGIN_SO) $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR)
	$(CXX) $< $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		-DPROXYSQL_FAKE_PLUGIN_PATH=\"$(FAKE_PLUGIN_SO)\" \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

# The plugin-side Anomaly_Detector unit test compiles the plugin's
# Anomaly_Detector.cpp directly into the test binary so that private
# methods (normalize_query, check_sql_injection) can be exercised via
# the friend-class helper without dlopening the .so.
GENAI_ANOMALY_SRC := $(PROXYSQL_PATH)/plugins/genai/src/Anomaly_Detector.cpp
GENAI_PLUGIN_INCLUDE := -I$(PROXYSQL_PATH)/plugins/genai/include
# Plugin-side .cpp files all wrap their body in `#ifdef PROXYSQL40`,
# so dedicated rules that compile them must pass -DPROXYSQL40 on the
# command line.  The unit-test build's PSQLGA is intentionally empty
# (libproxysql.a doesn't carry plugin code post-Step-7); each rule
# below opts in for itself.
GENAI_PLUGIN_DEFINES := -DPROXYSQL40
genai_plugin_anomaly_unit-t: genai_plugin_anomaly_unit-t.cpp $(GENAI_ANOMALY_SRC) $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR)
	$(CXX) $< $(GENAI_ANOMALY_SRC) $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		$(GENAI_PLUGIN_DEFINES) $(GENAI_PLUGIN_INCLUDE) $(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

# The plugin-side backend_client unit test compiles the plugin's
# backend_client.cpp + local_proxy_endpoint.cpp directly into the test
# binary; same compile-twice trick as genai_plugin_anomaly_unit-t.
# Allows exercising the parser and dial guards without dlopening the .so.
GENAI_BACKEND_CLIENT_SRCS := \
	$(PROXYSQL_PATH)/plugins/genai/src/backend_client.cpp \
	$(PROXYSQL_PATH)/plugins/genai/src/local_proxy_endpoint.cpp
genai_plugin_backend_client_unit-t: genai_plugin_backend_client_unit-t.cpp $(GENAI_BACKEND_CLIENT_SRCS) $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR)
	$(CXX) $< $(GENAI_BACKEND_CLIENT_SRCS) $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		$(GENAI_PLUGIN_DEFINES) $(GENAI_PLUGIN_INCLUDE) $(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

# genai_plugin_load_unit-t loads the real genai plugin .so (built by
# plugins/genai/Makefile) and exercises its lifecycle.  The Makefile here
# delegates the .so build to the plugin directory rather than restating
# its compile rules.
GENAI_PLUGIN_SO := $(PROXYSQL_PATH)/plugins/genai/ProxySQL_GenAI_Plugin.so
.PHONY: $(GENAI_PLUGIN_SO)
$(GENAI_PLUGIN_SO):
	$(MAKE) -C $(PROXYSQL_PATH)/plugins/genai

genai_plugin_load_unit-t: genai_plugin_load_unit-t.cpp $(GENAI_PLUGIN_SO) $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o $(LIBPROXYSQLAR)
	$(CXX) $< $(PROXYSQL_PATH)/lib/ProxySQL_PluginManager.cpp $(ODIR)/tap.o $(ODIR)/test_globals.o $(ODIR)/test_init.o \
		-DPROXYSQL40 -DPROXYSQL_GENAI_PLUGIN_PATH=\"$(GENAI_PLUGIN_SO)\" $(GENAI_PLUGIN_DEFINES) \
		$(IDIRS) $(LDIRS) $(OPT) $(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) \
		$(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

# Compile the plugin source set once for the eleven shard-declared tests. The
# object path preserves each source's plugins/genai/src/... location, avoiding
# basename collisions between the main and tool_handlers directories. OPT
# carries the active debug, coverage, and sanitizer flags into every object.
GENAI_SOURCE_ROOT := $(PROXYSQL_PATH)/plugins/genai/src
GENAI_ALL_SRCS := $(sort $(wildcard $(GENAI_SOURCE_ROOT)/*.cpp $(GENAI_SOURCE_ROOT)/tool_handlers/*.cpp))
GENAI_OBJECT_ROOT := $(ODIR)/genai
GENAI_ALL_OBJS := $(patsubst $(PROXYSQL_PATH)/%.cpp,$(GENAI_OBJECT_ROOT)/%.o,$(GENAI_ALL_SRCS))
GENAI_TEST_ARCHIVE := $(GENAI_OBJECT_ROOT)/libgenai_test.a

$(GENAI_OBJECT_ROOT)/%.o: $(PROXYSQL_PATH)/%.cpp
	mkdir -p $(dir $@)
	$(CXX) -c $< -o $@ $(GENAI_PLUGIN_DEFINES) $(GENAI_PLUGIN_INCLUDE) $(IDIRS) $(OPT)

$(GENAI_TEST_ARCHIVE): $(GENAI_ALL_OBJS)
	$(RM) $@
	$(AR) rcs $@ $^

$(AI_GENAI_UNIT_TESTS): %: %.cpp $(GENAI_TEST_ARCHIVE) $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(TEST_HELPERS_OBJ) $(GENAI_TEST_ARCHIVE) \
		$(GENAI_PLUGIN_DEFINES) $(GENAI_PLUGIN_INCLUDE) $(IDIRS) $(LDIRS) $(OPT) \
		$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS) -ldl $(ALLOW_MULTI_DEF) -o $@

ifeq ($(UNAME_S),Linux)
# Let the RSA unit test observe the exact flock attempt without a production hook.
caching_sha2_rsa_unit-t: ALLOW_MULTI_DEF += -Wl,--wrap=flock
endif

# Pattern rule: all unit tests use the same compile + link flags.
# Each test binary is built from its .cpp source, linked against
# the test harness objects and libproxysql.a with all dependencies.
%-t: %-t.cpp $(TEST_HELPERS_OBJ) $(LIBPROXYSQLAR)
	$(CXX) $< $(TEST_HELPERS_OBJ) $(IDIRS) $(LDIRS) $(OPT) \
		$(WHOLE_LIBPROXYSQL) $(STATIC_LIBS) $(MYLIBS) \
		$(ALLOW_MULTI_DEF) -o $@


# ===========================================================================
# Clean
# ===========================================================================

.PHONY: clean
.SILENT: clean
clean:
	rm -rf $(ODIR)
	rm -f *-t $(FAKE_PLUGIN_SO) $(FAKE_PLUGIN2_SO)
