#!/bin/make -f

PROXYSQL_PATH := $(shell set -e; d="$$PWD"; for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do if [ -f "$$d/src/proxysql_global.cpp" ]; then echo "$$d"; exit 0; fi; if [ "$$d" = "/" ]; then break; fi; d="$$(dirname "$$d")"; done; echo "ERROR: plugins/mysql_router/Makefile: repository root not found" >&2; exit 1)

ifneq (,$(findstring ERROR,$(PROXYSQL_PATH)))
$(error $(PROXYSQL_PATH))
endif

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk

PLUGIN_DIR := $(PROXYSQL_PATH)/plugins/mysql_router
ODIR := $(PLUGIN_DIR)/obj
PLUGIN_SO := $(PLUGIN_DIR)/proxysql_mysql_router.so

IDIRS := -I$(PROXYSQL_IDIR) -I$(PLUGIN_DIR)/include -I$(SQLITE3_IDIR) \
	-I$(PROMETHEUS_IDIR)

OPTZ ?= -O2 -ggdb

ifeq ($(PROXYSQL40),1)
	PROXYSQL31 := 1
endif
ifeq ($(PROXYSQL31),1)
	PROXYSQLFFTO := 1
	PROXYSQLTSDB := 1
endif

PSQL40 := $(if $(filter 1,$(PROXYSQL40)),-DPROXYSQL40)
PSQL31 := $(if $(filter 1,$(PROXYSQL31)),-DPROXYSQL31)
PSQLFFTO := $(if $(filter 1,$(PROXYSQLFFTO)),-DPROXYSQLFFTO)
PSQLTSDB := $(if $(filter 1,$(PROXYSQLTSDB)),-DPROXYSQLTSDB)

CXXFLAGS := $(STDCPP) -fPIC -fvisibility=hidden -fvisibility-inlines-hidden \
	$(OPTZ) $(WGCOV) $(WASAN) -pthread -fstack-protector-strong \
	$(PSQL40) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB)

ifeq ($(WASAN),)
ifneq (,$(findstring -O,$(OPTZ)))
ifeq (,$(findstring -O0,$(OPTZ)))
	CXXFLAGS += -D_FORTIFY_SOURCE=2
endif
endif
endif

PLUGIN_LDFLAGS :=
ifeq ($(UNAME_S),Darwin)
	PLUGIN_LDFLAGS += -Wl,-undefined,dynamic_lookup
else
	PLUGIN_LDFLAGS += -Wl,--version-script=$(PLUGIN_DIR)/exports.map
endif

SRCS := $(PLUGIN_DIR)/src/plugin.cpp \
	$(PLUGIN_DIR)/src/admin_schema.cpp \
	$(PLUGIN_DIR)/src/bootstrap_options.cpp \
	$(PLUGIN_DIR)/src/config_store.cpp \
	$(PLUGIN_DIR)/src/status.cpp \
	$(PLUGIN_DIR)/src/metrics.cpp
HEADERS := $(wildcard $(PLUGIN_DIR)/include/*.h) \
	$(PROXYSQL_PATH)/include/ProxySQL_Plugin.h \
	$(PLUGIN_DIR)/exports.map
OBJS := $(patsubst $(PLUGIN_DIR)/src/%.cpp,$(ODIR)/%.o,$(SRCS))

.DEFAULT_GOAL := all

$(ODIR):
	mkdir -p $(ODIR)

$(ODIR)/%.o: $(PLUGIN_DIR)/src/%.cpp $(HEADERS) | $(ODIR)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(IDIRS)

$(PLUGIN_SO): $(OBJS)
	$(CXX) -shared -o $@ $^ $(CXXFLAGS) $(PLUGIN_LDFLAGS)

.PHONY: all
all: $(PLUGIN_SO)

.PHONY: clean
clean:
	rm -rf $(ODIR) $(PLUGIN_SO)
