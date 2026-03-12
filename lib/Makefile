#!/bin/make -f


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk

SQLITE_REMBED_LIB := $(SQLITE3_LDIR)/../libsqlite_rembed.a

IDIRS :=	-I$(PROXYSQL_IDIR) \
			-I$(JEMALLOC_IDIR) \
			-I$(MARIADB_IDIR) \
			-I$(LIBCONFIG_IDIR) \
			-I$(LIBDAEMON_IDIR) \
			-I$(RE2_IDIR) \
			-I$(PCRE_IDIR) \
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

IDIR := ../include/

ifeq ($(UNAME_S),Linux)
	IDIRS += -I$(COREDUMPER_IDIR)
endif

LDIRS :=	-L$(JEMALLOC_LDIR) \
			-L$(RE2_LDIR) \
			-L$(LIBINJECTION_LDIR) \
			-L$(PROMETHEUS_LDIR)

#LIBS := -rdynamic -Wl,-Bstatic -ljemalloc_pic -lre2 -Wl,-Bdynamic -ldl -lpthread -lm -lz -lrt $(EXTRALINK)
#LIBS := -Wl,--export-dynamic -Wl,-Bstatic -ljemalloc_pic -lre2 -Wl,-Bdynamic -ldl -lpthread -lm -lz -lrt $(EXTRALINK)

ODIR := obj

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

# 'libhttpserver': Add 'ENABLE_EPOLL' by default for all platforms except
# for 'Darwin'. This is required when compiling 'libhttpserver' for avoiding
# internal use of 'SELECT' in favor of 'EPOLL'. See #3591.
ENABLE_EPOLL := -DENABLE_EPOLL
ifeq ($(UNAME_S),Darwin)
	ENABLE_EPOLL :=
endif


MYCFLAGS := $(IDIRS) $(OPTZ) $(DEBUG) -Wall -DGITVERSION=\"$(GIT_VERSION)\" $(NOJEM) $(WGCOV) $(WASAN)
MYCXXFLAGS := $(STDCPP) $(MYCFLAGS) $(PSQLCH) $(PSQLGA) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB) $(ENABLE_EPOLL)

default: libproxysql.a
.PHONY: default

_OBJ_CXX := ProxySQL_GloVars.oo network.oo debug.oo configfile.oo Query_Cache.oo SpookyV2.oo MySQL_Authentication.oo gen_utils.oo sqlite3db.oo mysql_connection.oo MySQL_HostGroups_Manager.oo mysql_data_stream.oo MySQL_Thread.oo MySQL_Session.oo MySQL_Protocol.oo mysql_backend.oo Query_Processor.oo MySQL_Query_Processor.oo PgSQL_Query_Processor.oo  ProxySQL_Admin.oo ProxySQL_Config.oo ProxySQL_Restapi.oo MySQL_Monitor.oo MySQL_Logger.oo log_utils.oo thread.oo MySQL_PreparedStatement.oo ProxySQL_Cluster.oo ClickHouse_Authentication.oo ClickHouse_Server.oo ProxySQL_Statistics.oo Chart_bundle_js.oo ProxySQL_HTTP_Server.oo ProxySQL_RESTAPI_Server.oo font-awesome.min.css.oo main-bundle.min.css.oo MySQL_Variables.oo c_tokenizer.oo proxysql_utils.oo proxysql_coredump.oo proxysql_sslkeylog.oo \
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
	PgSQL_Variables_Validator.oo PgSQL_ExplicitTxnStateMgr.oo \
	PgSQL_PreparedStatement.oo PgSQL_Extended_Query_Message.oo \
	MySQL_Parser.oo Base_Session_Utils.oo MySQL_Session_Utils.oo PgSQL_Session_Utils.oo \
	MySQL_Lexer.yy.oo MySQL_Parser.tab.oo MySQL_SET_Parser_Utils.oo MySQL_Variables_Utils.oo \
	PgSQL_Variables_Utils.oo \
	pgsql_tokenizer.oo \
	proxy_sqlite3_symbols.oo

# TSDB object files
ifeq ($(PROXYSQLTSDB),1)
_OBJ_CXX += TSDB_Dashboard_html.oo
endif

# FFTO object files
ifeq ($(PROXYSQLFFTO),1)
_OBJ_CXX += MySQLFFTO.oo PgSQLFFTO.oo
endif

# GenAI object files (conditionally included)
ifeq ($(PROXYSQLGENAI),1)
_OBJ_CXX += GenAI_Thread.oo \
	MCP_Thread.oo ProxySQL_MCP_Server.oo MCP_Endpoint.oo MCP_Tool_Handler.oo \
	MySQL_Catalog.oo MySQL_Tool_Handler.oo MySQL_FTS.oo \
	Config_Tool_Handler.oo Query_Tool_Handler.oo \
	Admin_Tool_Handler.oo Cache_Tool_Handler.oo Stats_Tool_Handler.oo \
	AI_Features_Manager.oo LLM_Bridge.oo LLM_Clients.oo Anomaly_Detector.oo AI_Vector_Storage.oo AI_Tool_Handler.oo \
	RAG_Tool_Handler.oo \
	Discovery_Schema.oo Static_Harvester.oo PgSQL_Static_Harvester.oo \
	Observe_Tool_Handler.oo
endif

OBJ_CXX := $(patsubst %,$(ODIR)/%,$(_OBJ_CXX))
HEADERS := ../include/*.h ../include/*.hpp

MYSQL_BISON_C = MySQL_Parser.tab.c
MYSQL_BISON_H = MySQL_Parser.tab.h
MYSQL_FLEX_C = MySQL_Lexer.yy.c
MYSQL_LEXER_FILE = MySQL_Lexer.l
MYSQL_PARSER = MySQL_Parser
BISON ?= bison

ifeq ($(UNAME_S),Darwin)
ifneq ($(wildcard /opt/homebrew/opt/bison/bin/bison),)
	BISON := /opt/homebrew/opt/bison/bin/bison
else ifneq ($(wildcard /usr/local/opt/bison/bin/bison),)
	BISON := /usr/local/opt/bison/bin/bison
endif
endif

BISON_SUPPORTS_PERCENT_CODE := $(shell \
	tmp=$$(mktemp /tmp/proxysql-bison.XXXXXX 2>/dev/null || mktemp -t proxysql-bison) && \
	printf '%%code requires { }\n%%%%\nstmt:\n;\n' > $$tmp && \
	$(BISON) -o /dev/null $$tmp >/dev/null 2>&1; \
	status=$$?; rm -f $$tmp; echo $$status \
)

ifneq ($(BISON_SUPPORTS_PERCENT_CODE),0)
$(error Bison at '$(BISON)' is too old for MySQL_Parser.y; install a modern GNU bison or override BISON=/path/to/bison)
endif

BISON_WARN_FLAGS :=

ifneq ($(shell $(BISON) --help 2>/dev/null | grep -F "counterexamples"),)
	BISON_WARN_FLAGS += -Wcounterexamples
endif

$(MYSQL_FLEX_C): $(MYSQL_LEXER_FILE) $(MYSQL_BISON_H)
	flex -o $(MYSQL_FLEX_C) $(MYSQL_LEXER_FILE)

$(MYSQL_BISON_C): $(MYSQL_PARSER).y $(IDIR)/MySQL_AST.h $(IDIR)/$(MYSQL_PARSER).h
	$(BISON) $(BISON_WARN_FLAGS) -d -v --report=all -o $(MYSQL_BISON_C) --defines=$(MYSQL_BISON_H) $(MYSQL_PARSER).y

$(MYSQL_BISON_H): $(MYSQL_BISON_C)

$(ODIR)/MySQL_Parser.tab.oo: $(MYSQL_BISON_C) $(MYSQL_BISON_H) $(IDIR)/$(MYSQL_PARSER).h
	$(CXX) -fPIC -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS)

$(ODIR)/MySQL_Lexer.yy.oo: $(MYSQL_FLEX_C) $(MYSQL_BISON_H) $(IDIR)/$(MYSQL_PARSER).h
	$(CXX) -fPIC -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS)

$(ODIR)/$(MYSQL_PARSER).oo: $(MYSQL_PARSER).cpp $(ODIR)/MySQL_Lexer.yy.oo
	$(CXX) -fPIC -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS)

MYSQL_PARSER_OBJ := $(ODIR)/$(MYSQL_PARSER).oo $(ODIR)/MySQL_Lexer.yy.oo $(ODIR)/MySQL_Parser.tab.oo

%.ko: %.cpp $(HEADERS)
	$(CXX) -fPIC -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS)

$(ODIR)/proxy_sqlite3_symbols.oo: proxy_sqlite3_symbols.cpp $(HEADERS)
	$(CXX) -fPIC -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS) -DSQLITE_CORE -DSQLITE_VEC_STATIC

$(ODIR)/%.oo: %.cpp $(HEADERS)
	$(CXX) -fPIC -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS)

libproxysql.a: $(ODIR) $(OBJ) $(OBJ_CXX) $(SQLITE3_LDIR)/sqlite3.o $(MYSQL_PARSER_OBJ)
	ar rcs $@ $(OBJ) $(OBJ_CXX) $(SQLITE3_LDIR)/sqlite3.o

$(ODIR):
	mkdir $(ODIR)

clean:
	rm -rf *.pid $(ODIR)/*.oo $(ODIR)/*.o $(ODIR)/*.gcno $(ODIR)/*.gcda *.ko *.so *~ core libproxysql.a $(ODIR) \
		MySQL_Lexer.yy.c MySQL_Parser.output MySQL_Parser.tab.c MySQL_Parser.tab.h


## self note
# ../deps/protobuf/protobuf/src/protoc -I=. --cpp_out=. ./mysql_logger.proto
# mv mysql_logger.pb.cc mysql_logger.pb.cpp
