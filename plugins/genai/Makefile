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
         -I$(CURL_IDIR) -I$(RE2_IDIR) -I$(PCRE_IDIR) -I$(ZSTD_IDIR)

OPTZ ?= -O2 -ggdb
CXXFLAGS := $(STDCPP) -fPIC $(OPTZ) $(WGCOV) $(WASAN) -pthread

.DEFAULT_GOAL := all

SRCS := $(PLUGIN_DIR)/src/plugin_main.cpp \
	$(PLUGIN_DIR)/src/plugin_hooks.cpp \
	$(PLUGIN_DIR)/src/Anomaly_Detector.cpp
HEADERS := $(wildcard $(PLUGIN_DIR)/include/*.h) \
	$(PROXYSQL_PATH)/include/ProxySQL_Plugin.h
OBJS := $(patsubst $(PLUGIN_DIR)/src/%.cpp,$(ODIR)/%.o,$(SRCS))

$(ODIR):
	mkdir -p $(ODIR)

$(ODIR)/%.o: $(PLUGIN_DIR)/src/%.cpp $(HEADERS) | $(ODIR)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(IDIRS)

$(PLUGIN_SO): $(OBJS)
	$(CXX) -shared -o $@ $^ $(CXXFLAGS)

.PHONY: all
all: $(PLUGIN_SO)

.PHONY: clean
clean:
	rm -rf $(ODIR) $(PLUGIN_SO)
