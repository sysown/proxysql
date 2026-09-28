#!/bin/make -f

PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk

PLUGIN_DIR := $(PROXYSQL_PATH)/plugins/genai
ODIR := $(PLUGIN_DIR)/obj
PLUGIN_SO := $(PLUGIN_DIR)/ProxySQL_GenAI_Plugin.so

# Include paths:
#   - PROXYSQL_IDIR pulls in ProxySQL core headers (sqlite3db.h,
#     proxysql.h, ProxySQL_Plugin.h, etc.) — this is fine because
#     plugin code uses public types (SQLite3DB*, the plugin ABI),
#     not core internals.
#   - PROMETHEUS_IDIR is needed for prometheus-cpp counter / family
#     headers consumed by plugin_main.cpp and plugin_hooks.cpp.
#   - SQLITE3_IDIR is needed transitively because sqlite3db.h includes
#     sqlite3.h.
#   - JSON_IDIR is needed for the vendored nlohmann/json used by the
#     embedding back-end's serialisation (Anomaly_Detector.cpp).
PLUGIN_IDIRS := -I$(PLUGIN_DIR)/include
# MariaDB / libev / scram / postgresql / libusual / libconfig include
# paths are needed transitively because proxysql.h pulls in mysql.h
# and other deps from those trees (Anomaly_Detector.cpp's includes
# bring proxysql.h in transitively).  This list mirrors test/tap/tests/unit.
IDIRS := $(PLUGIN_IDIRS) -I$(PROXYSQL_IDIR) -I$(PROMETHEUS_IDIR) \
         -I$(SQLITE3_IDIR) -I$(JSON_IDIR) \
         -I$(MARIADB_IDIR) -I$(LIBCONFIG_IDIR) -I$(LIBDAEMON_IDIR) \
         -I$(EV_IDIR) -I$(LIBSCRAM_IDIR) -I$(LIBUSUAL_IDIR) \
         -I$(POSTGRESQL_IDIR) -I$(SSL_IDIR) -I$(JEMALLOC_IDIR) \
         -I$(MICROHTTPD_IDIR) -I$(LIBHTTPSERVER_IDIR) \
         -I$(CURL_IDIR) -I$(RE2_IDIR) -I$(PCRE2_IDIR) -I$(ZSTD_IDIR)

OPTZ ?= -O2 -ggdb

# Propagate feature-tier flags from the top-level build.  These MUST match
# the flags libproxysql.a was built with; in particular, ProxySQL_Plugin.h
# is fully gated behind PROXYSQL40 (the plugin chassis is a v4.0 feature),
# so omitting -DPROXYSQL40 here yields an empty header and breaks the build.
# (If this Makefile is run standalone, the caller is expected to export
# PROXYSQL40/31/etc. to match the lib.)
PSQL40 := -DPROXYSQL40
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
PSQLGA := -DPROXYSQL40

# -fvisibility=hidden / -fvisibility-inlines-hidden keep the .so's
# exported symbol surface to just `proxysql_plugin_descriptor_v1`
# (declared `__attribute__((visibility("default")))` in plugin_main.cpp
# via `extern "C"` and reached by dlsym).  Without this flag every
# inline / non-static method we compile (Anomaly_Detector, MCP_Thread,
# every tool handler) would be exported, bloating the symbol table and
# risking accidental cross-plugin symbol collisions.  Mirrors the
# plugins/mysqlx Makefile.
#
# -fstack-protector-strong is hardening; cheap insurance for a runtime-
# loaded .so that handles untrusted SQL and JSON payloads.
CXXFLAGS := $(STDCPP) -fPIC $(OPTZ) $(WGCOV) $(WASAN) -pthread \
	-fvisibility=hidden -fvisibility-inlines-hidden \
	-fstack-protector-strong \
	$(PSQL40) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB) $(PSQLGA)

PLUGIN_LDFLAGS :=
ifeq ($(UNAME_S),Darwin)
PLUGIN_LDFLAGS += -Wl,-undefined,dynamic_lookup
endif

.DEFAULT_GOAL := all

SRCS := $(PLUGIN_DIR)/src/plugin_main.cpp \
	$(PLUGIN_DIR)/src/plugin_hooks.cpp \
	$(PLUGIN_DIR)/src/plugin_commands.cpp \
	$(PLUGIN_DIR)/src/plugin_tables.cpp \
	$(PLUGIN_DIR)/src/AI_Features_Manager.cpp \
	$(PLUGIN_DIR)/src/AI_Tool_Handler.cpp \
	$(PLUGIN_DIR)/src/AI_Vector_Storage.cpp \
	$(PLUGIN_DIR)/src/Anomaly_Detector.cpp \
	$(PLUGIN_DIR)/src/backend_client.cpp \
	$(PLUGIN_DIR)/src/Discovery_Schema.cpp \
	$(PLUGIN_DIR)/src/GenAI_Thread.cpp \
	$(PLUGIN_DIR)/src/LLM_Bridge.cpp \
	$(PLUGIN_DIR)/src/LLM_Clients.cpp \
	$(PLUGIN_DIR)/src/local_proxy_endpoint.cpp \
	$(PLUGIN_DIR)/src/MCP_Endpoint.cpp \
	$(PLUGIN_DIR)/src/MCP_Thread.cpp \
	$(PLUGIN_DIR)/src/MySQL_Catalog.cpp \
	$(PLUGIN_DIR)/src/MySQL_FTS.cpp \
	$(PLUGIN_DIR)/src/PgSQL_Static_Harvester.cpp \
	$(PLUGIN_DIR)/src/ProxySQL_MCP_Server.cpp \
	$(PLUGIN_DIR)/src/Static_Harvester.cpp \
	$(PLUGIN_DIR)/src/tool_handlers/Admin_Tool_Handler.cpp \
	$(PLUGIN_DIR)/src/tool_handlers/Cache_Tool_Handler.cpp \
	$(PLUGIN_DIR)/src/tool_handlers/Config_Tool_Handler.cpp \
	$(PLUGIN_DIR)/src/tool_handlers/MCP_Tool_Handler.cpp \
	$(PLUGIN_DIR)/src/tool_handlers/MySQL_Tool_Handler.cpp \
	$(PLUGIN_DIR)/src/tool_handlers/Observe_Tool_Handler.cpp \
	$(PLUGIN_DIR)/src/tool_handlers/Query_Tool_Handler.cpp \
	$(PLUGIN_DIR)/src/tool_handlers/RAG_Tool_Handler.cpp \
	$(PLUGIN_DIR)/src/tool_handlers/Stats_Tool_Handler.cpp
HEADERS := $(wildcard $(PLUGIN_DIR)/include/*.h) \
	$(PROXYSQL_PATH)/include/ProxySQL_Plugin.h
OBJS := $(patsubst $(PLUGIN_DIR)/src/%.cpp,$(ODIR)/%.o,$(SRCS))

$(ODIR):
	mkdir -p $(ODIR)
	mkdir -p $(ODIR)/tool_handlers

$(ODIR)/%.o: $(PLUGIN_DIR)/src/%.cpp $(HEADERS) | $(ODIR)
	@mkdir -p $(dir $@)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(IDIRS)

# The executable force-loads and exports vendored libcurl. Keep curl unresolved
# here so the process has one libcurl owner and one OpenSSL owner.
$(PLUGIN_SO): $(OBJS)
	$(CXX) -shared -o $@ $^ $(CXXFLAGS) $(PLUGIN_LDFLAGS)

.PHONY: all
all: $(PLUGIN_SO)

.PHONY: clean
clean:
	rm -rf $(ODIR) $(PLUGIN_SO)
