#!/bin/make -f
# Azure Entra ID token provider for MySQL backend authentication (#6649).

PROXYSQL_PATH := $(shell set -e; d="$$PWD"; for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do if [ -f "$$d/src/proxysql_global.cpp" ]; then echo "$$d"; exit 0; fi; if [ "$$d" = "/" ]; then break; fi; d="$$(dirname "$$d")"; done; echo "ERROR: plugins/azure_entra/Makefile: repository root not found" >&2; exit 1)

ifneq (,$(findstring ERROR,$(PROXYSQL_PATH)))
$(error $(PROXYSQL_PATH))
endif

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk

PLUGIN_DIR := $(PROXYSQL_PATH)/plugins/azure_entra
ODIR := $(PLUGIN_DIR)/obj
PLUGIN_SO := $(PLUGIN_DIR)/proxysql_azure_entra.so
RUNTIME_PLUGIN := $(PROXYSQL_PATH)/test/tap/tap/_runtime_libs/proxysql_azure_entra.so

# The core exports OpenSSL and libcurl; compile against the vendored headers
# without linking a second copy into the plugin.
IDIRS := -I$(SSL_IDIR) -I$(PROXYSQL_IDIR) -I$(PLUGIN_DIR)/include -I$(CURL_IDIR) -I$(JSON_IDIR)

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
	$(PSQLCH) $(PSQL40) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB) -DGITVERSION=\"$(GIT_VERSION)\"

PLUGIN_LDFLAGS :=
ifeq ($(UNAME_S),Darwin)
	PLUGIN_LDFLAGS += -Wl,-undefined,dynamic_lookup
else
	PLUGIN_LDFLAGS += -Wl,--version-script=$(PLUGIN_DIR)/exports.map
endif

SRCS := $(PLUGIN_DIR)/src/plugin.cpp \
	$(PLUGIN_DIR)/src/entra_config.cpp \
	$(PLUGIN_DIR)/src/entra_exchange.cpp \
	$(PLUGIN_DIR)/src/entra_token_source.cpp \
	$(PLUGIN_DIR)/src/curl_transport.cpp
HEADERS := $(wildcard $(PLUGIN_DIR)/include/*.h) \
	$(PROXYSQL_PATH)/include/ProxySQL_Plugin.h \
	$(PROXYSQL_PATH)/include/Aws_Iam_Provider.h \
	$(PLUGIN_DIR)/exports.map
OBJS := $(patsubst $(PLUGIN_DIR)/src/%.cpp,$(ODIR)/%.o,$(SRCS))

.DEFAULT_GOAL := all

$(ODIR):
	mkdir -p $(ODIR)

$(ODIR)/%.o: $(PLUGIN_DIR)/src/%.cpp $(HEADERS) $(PLUGIN_DIR)/Makefile | $(ODIR)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(IDIRS)

$(PLUGIN_SO): $(OBJS)
	$(CXX) -shared -o $@ $^ $(CXXFLAGS) $(PLUGIN_LDFLAGS)

.PHONY: stage-runtime
stage-runtime: $(PLUGIN_SO)
	install -d -m 0755 $(dir $(RUNTIME_PLUGIN))
	install -m 0644 $(PLUGIN_SO) $(RUNTIME_PLUGIN)

.PHONY: all
all: stage-runtime

.PHONY: clean
clean:
	rm -rf $(ODIR) $(PLUGIN_SO) $(RUNTIME_PLUGIN)
