#!/bin/make -f


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk

IDIRS :=	-I$(PROXYSQL_IDIR) \
			-I$(JEMALLOC_IDIR) \
			-I$(MARIADB_IDIR) \
			-I$(LIBCONFIG_IDIR) \
			-I$(LIBDAEMON_IDIR) \
			-I$(RE2_IDIR) \
			-I$(PCRE_IDIR) \
			-I$(PCRE2_IDIR) \
			-I$(CLICKHOUSE_CPP_IDIR) \
			-I$(MICROHTTPD_IDIR) \
			-I$(LIBHTTPSERVER_IDIR) \
			-I$(LIBINJECTION_IDIR) \
			-I$(CURL_IDIR) \
			-I$(EV_IDIR) \
			-I$(PROMETHEUS_IDIR) \
			-I$(LIBUSUAL_IDIR) \
			-I$(LIBSCRAM_IDIR) \
			-I$(SQLITE3_IDIR) \
			-I$(POSTGRESQL_IDIR) \
			-I$(JSON_IDIR) \
			-I$(SSL_IDIR) \
			-I$(ZSTD_IDIR) \
			-I$(PARSERSQL_IDIR) \

ifeq ($(UNAME_S),Linux)
	IDIRS += -I$(COREDUMPER_IDIR)
endif
ifeq ($(UNAME_S),Darwin)
	IDIRS += -I/usr/local/include -I/opt/homebrew/include
	LDIRS += -L/usr/local/lib -L/opt/homebrew/lib
endif

LDIRS :=	-L$(JEMALLOC_LDIR) \
			-L$(RE2_LDIR) \
			-L$(ABSL_LDIR) \
			-L$(LIBINJECTION_LDIR) \
			-L$(PROMETHEUS_LDIR) \
			-L$(PARSERSQL_LDIR) \

#LIBS := -rdynamic -Wl,-Bstatic -ljemalloc_pic $(RE2_STATIC_LIBS) -Wl,-Bdynamic -ldl -lpthread -lm -lz -lrt $(EXTRALINK)
#LIBS := -Wl,--export-dynamic -Wl,-Bstatic -ljemalloc_pic $(RE2_STATIC_LIBS) -Wl,-Bdynamic -ldl -lpthread -lm -lz -lrt $(EXTRALINK)

ODIR := obj

PSQLCH :=
ifeq ($(PROXYSQLCLICKHOUSE),1)
	PSQLCH := -DPROXYSQLCLICKHOUSE
endif

PSQL40 :=
ifeq ($(PROXYSQL40),1)
	PSQL40 := -DPROXYSQL40
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

PSQLED25519 :=
ifeq ($(PROXYSQLED25519),1)
	PSQLED25519 := -DPROXYSQLED25519
endif

# 'libhttpserver': Add 'ENABLE_EPOLL' by default for all platforms except
# for 'Darwin'. This is required when compiling 'libhttpserver' for avoiding
# internal use of 'SELECT' in favor of 'EPOLL'. See #3591.
ENABLE_EPOLL := -DENABLE_EPOLL
ifeq ($(UNAME_S),Darwin)
	ENABLE_EPOLL :=
endif


MYCFLAGS := $(IDIRS) $(OPTZ) $(DEBUG) -Wall -DGITVERSION=\"$(GIT_VERSION)\" $(NOJEM) $(WGCOV) $(WASAN)
MYCXXFLAGS := $(STDCPP) $(MYCFLAGS) $(PSQLCH) $(PSQL40) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB) $(PSQLED25519) $(ENABLE_EPOLL)

# Declared explicitly so the BUILD_FLAGS_STAMP rule below cannot be picked up
# as the default goal -- make takes the first rule it sees as the goal.
.DEFAULT_GOAL := default

# ---------------------------------------------------------------------------
# Build-flag stamp: keep the whole object set on one flag set.
#
# The top-level Makefile does not pass these as make variables -- it passes
# them as environment variables on the recursive make command line, e.g.
#   cd lib && OPTZ="${O0} -ggdb -DDEBUG" PROXYSQLCLICKHOUSE=1 ... ${MAKE}
# A targeted `make -C lib obj/Foo.oo` therefore inherits NONE of them and
# compiles that file with the default (release) flags, notably without
# -DDEBUG.
#
# Make decides staleness by timestamp alone, so the mismatched .oo looks up to
# date to the next `make debug` and is archived into libproxysql.a silently.
# Classes with conditional members -- MySQL_Protocol and MySQL_Data_Stream both
# have #ifdef DEBUG and #ifdef PROXYSQL31 members -- then disagree on layout
# between translation units, and every field past the first conditional member
# is read at the wrong offset. Observed as SIGSEGV in
# MySQL_Protocol::generate_pkt_initial_handshake() on every client connect,
# where myprot.myds resolves to a garbage pointer.
#
# Recording the effective flags in a stamp that every object depends on forces
# a full rebuild whenever the flag set changes, which covers both this and the
# PROXYSQL31/PROXYSQL40 tier mismatch. `cmp -s` leaves the stamp's mtime alone
# when nothing changed, so ordinary rebuilds are not triggered.
# ---------------------------------------------------------------------------
BUILD_FLAGS_STAMP := $(ODIR)/.build_flags

# The recorded flag set deliberately excludes -DGITVERSION=... (it changes on
# every commit, so recording it would force a full rebuild each time) and
# includes the compiler, so switching toolchains also invalidates the objects.
# The macro is dropped with $(subst), not $(filter-out): the latter is a
# whitespace word-list function, so it would collapse whitespace inside a quoted
# flag value (e.g. -DMSG="a  b" vs -DMSG="a b") and could leave stale objects.
# It is exported and referenced as "$$STAMP_FLAGS" below so the shell expands it
# from the environment without re-parsing it, which keeps literal quotes and
# backticks in a flag intact rather than letting the shell consume them.
STAMP_FLAGS := $(CC) $(CXX) $(subst -DGITVERSION=\"$(GIT_VERSION)\",,$(MYCXXFLAGS)) $(CXXFLAGS)
export STAMP_FLAGS

# Order-only prerequisite on $(ODIR): the recipe must not race the directory
# rule's own `mkdir` under `make -j`, and so it no longer needs its own mkdir.
$(BUILD_FLAGS_STAMP): FORCE | $(ODIR)
	@printf '%s\n' "$$STAMP_FLAGS" | cmp -s - $@ || printf '%s\n' "$$STAMP_FLAGS" > $@

default: libproxysql.a
.PHONY: default

_OBJ_CXX := ProxySQL_GloVars.oo network.oo debug.oo configfile.oo Query_Cache.oo SpookyV2.oo MySQL_Authentication.oo MySQL_Backend_Auth.oo Aws_Iam_Provider.oo Aws_Locality_Manager.oo MySQL_Passthrough_Auth_Cache.oo gen_utils.oo sqlite3db.oo mysql_connection.oo MySQL_HostGroups_Manager.oo mysql_data_stream.oo MySQL_Thread.oo MySQL_Session.oo MySQL_Protocol.oo mysql_backend.oo Query_Processor.oo MySQL_Query_Processor.oo PgSQL_Query_Processor.oo  ProxySQL_Admin.oo ProxySQL_Config.oo ProxySQL_Restapi.oo MySQL_Monitor.oo MySQL_Logger.oo log_utils.oo thread.oo MySQL_PreparedStatement.oo ProxySQL_Cluster.oo ClickHouse_Authentication.oo ClickHouse_Server.oo ProxySQL_Statistics.oo Chart_bundle_js.oo ProxySQL_HTTP_Server.oo ProxySQL_RESTAPI_Server.oo font-awesome.min.css.oo main-bundle.min.css.oo MySQL_Variables.oo MySQL_User_Variables.oo c_tokenizer.oo proxysql_utils.oo proxysql_coredump.oo proxysql_sslkeylog.oo \
	sha256crypt.oo \
	ProxySQL_PluginManager.oo ProxySQL_PluginCLI.oo ProxySQL_PluginSecrets.oo ProxySQL_PluginListenerGate.oo ProxySQL_PluginConfig.oo ProxySQL_ManagedRuntime.oo \
	ProxySQL_ServerDiscovery.oo \
	ProxySQL_StartupGate.oo \
	ProxySQL_ClusterPluginHash.oo \
	ProxySQL_ServerModuleCluster.oo \
	BaseSrvList.oo BaseHGC.oo Base_HostGroups_Manager.oo \
	QP_rule_text.oo QP_query_digest_stats.oo \
	GTID_Server_Data.oo MyHGC.oo MySrvConnList.oo MySrvC.oo \
	MySQL_encode.oo MySQL_ResultSet.oo \
	ProxySQL_Admin_Tests.oo ProxySQL_Admin_Tests2.oo ProxySQL_Admin_Scheduler.oo ProxySQL_Admin_Disk_Upgrade.oo ProxySQL_Admin_Stats.oo \
	Admin_Handler.oo Admin_FlushVariables.oo Admin_Bootstrap.oo \
	Base_Session.oo Base_Thread.oo \
	proxysql_gtid.oo \
	proxy_protocol_info.oo \
	proxysql_find_charset.oo ProxySQL_Poll.oo \
	PgSQL_Protocol.oo PgSQL_Thread.oo PgSQL_Data_Stream.oo PgSQL_Session.oo PgSQL_Variables.oo PgSQL_HostGroups_Manager.oo PgSQL_Connection.oo PgSQL_Backend.oo PgSQL_Logger.oo PgSQL_Authentication.oo PgSQL_Error_Helper.oo PgSQL_Backend_Protocol.oo PgSQL_Backend_Auth.oo \
	MySQL_Query_Cache.oo PgSQL_Query_Cache.oo PgSQL_Monitor.oo DNS_Cache.oo \
	MySQL_Set_Stmt_Parser.oo PgSQL_Set_Stmt_Parser.oo \
	PgSQL_Variables_Validator.oo PgSQL_ExplicitTxnStateMgr.oo \
	PgSQL_PreparedStatement.oo PgSQL_Extended_Query_Message.oo \
	pgsql_tokenizer.oo \
	MonitorHealthDecision.oo \
	ServerSelection.oo \
	TransactionState.oo \
	HostgroupRouting.oo \
	PgSQLCommandComplete.oo \
	PgSQLErrorFields.oo \
	MySQLProtocolUtils.oo \
	PgSQLErrorClassifier.oo \
	PgSQLMonitorDecision.oo \
	MySQLErrorClassifier.oo \
	BackendSyncDecision.oo \
	Query_Processor_ParserSQL.oo \
	proxy_sqlite3_symbols.oo

ifeq ($(PROXYSQL31),1)
_OBJ_CXX += MySQL_Caching_Sha2_RSA.oo MySQL_Server_Version_By_Interface.oo
endif

# TSDB object files
ifeq ($(PROXYSQLTSDB),1)
_OBJ_CXX += TSDB_Dashboard_html.oo
endif

# FFTO object files
ifeq ($(PROXYSQLFFTO),1)
_OBJ_CXX += MySQLFFTO.oo PgSQLFFTO.oo MySQLResultsetFramer.oo PgSQLResponseFramer.oo
endif

# ed25519 frontend authentication (MariaDB client_ed25519)
ifeq ($(PROXYSQLED25519),1)
_OBJ_CXX += MySQL_Ed25519.oo
endif

OBJ_CXX := $(patsubst %,$(ODIR)/%,$(_OBJ_CXX))
HEADERS := ../include/*.h ../include/*.hpp

%.ko: %.cpp $(HEADERS)
	$(CXX) -fPIC -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS)

$(ODIR)/proxy_sqlite3_symbols.oo: proxy_sqlite3_symbols.cpp $(HEADERS) $(BUILD_FLAGS_STAMP)
	$(CXX) -fPIC -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS) -DSQLITE_CORE -DSQLITE_VEC_STATIC

# Keep the ABI-9 server-discovery registry object fresh when its public
# contract changes; this is intentionally explicit despite $(HEADERS), as
# external plugin builds consume this header directly.
$(ODIR)/ProxySQL_PluginManager.oo: ../include/ProxySQL_ServerDiscovery.h

$(ODIR)/%.oo: %.cpp $(HEADERS) $(BUILD_FLAGS_STAMP)
	$(CXX) -fPIC -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS)

# Recreate the archive from scratch: `ar rcs` replaces/inserts members but never
# removes them, so when a flag change shrinks the object list (e.g. dropping the
# FFTO/TSDB objects) the stale members would survive and be pulled back in by
# the `--whole-archive` link in src/Makefile, reintroducing the very mismatch
# the stamp above prevents.
libproxysql.a: $(ODIR) $(OBJ) $(OBJ_CXX) $(SQLITE3_LDIR)/sqlite3.o
	rm -f $@
	ar rcs $@ $(OBJ) $(OBJ_CXX) $(SQLITE3_LDIR)/sqlite3.o

$(ODIR):
	mkdir -p $(ODIR)

# Always considered out of date, so BUILD_FLAGS_STAMP is re-examined on every
# run. Declared after `default:` so it cannot become the default goal.
.PHONY: FORCE
FORCE:

#all: $(EXECUTABLE)


clean:
	rm -rf *.pid $(ODIR)/*.oo $(ODIR)/*.o $(ODIR)/*.gcno $(ODIR)/*.gcda *.ko *.so *~ core libproxysql.a $(ODIR) \
		MySQL_Lexer.yy.c MySQL_Parser.output MySQL_Parser.tab.c MySQL_Parser.tab.h


## self note
# ../deps/protobuf/protobuf/src/protoc -I=. --cpp_out=. ./mysql_logger.proto
# mv mysql_logger.pb.cc mysql_logger.pb.cpp
