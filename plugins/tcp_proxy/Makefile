#!/bin/make -f

# Native TCP proxy plugin.  Linux is the initial supported data-plane platform;
# other platforms get an explicit diagnostic instead of a silent fallback.

PROXYSQL_PATH := $(shell set -e; d="$$PWD"; for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do if [ -f "$$d/src/proxysql_global.cpp" ]; then echo "$$d"; exit 0; fi; if [ "$$d" = "/" ]; then break; fi; d="$$(dirname "$$d")"; done; echo "ERROR: plugins/tcp_proxy/Makefile: repository root not found"; exit 1)

ifneq (,$(findstring ERROR,$(PROXYSQL_PATH)))
$(error $(PROXYSQL_PATH))
endif

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk

PLUGIN_DIR := $(PROXYSQL_PATH)/plugins/tcp_proxy
ODIR := $(PLUGIN_DIR)/obj
PLUGIN_SO := $(PLUGIN_DIR)/proxysql_tcp_proxy.so

IDIRS := -I$(PROXYSQL_IDIR) -I$(PLUGIN_DIR)/include -I$(SQLITE3_IDIR) \
	-I$(PROMETHEUS_IDIR) -I$(JSON_IDIR) -I$(SSL_IDIR)

OPTZ ?= -O2 -ggdb

# Feature-tier cascade mirrors the top-level build so the descriptor and
# services table layout match the core that dlopen()s this DSO.
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
	$(PSQLCH) $(PSQL40) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB) \
	-DGITVERSION=\"$(GIT_VERSION)\"

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

# Wildcard discovery intentionally includes future production engine units
# copied into src/ (config.cpp, engine.cpp, health.cpp, ...).  The plugin never
# links a second/simplified relay.
SRCS := $(wildcard $(PLUGIN_DIR)/src/*.cpp)
HEADERS := $(wildcard $(PLUGIN_DIR)/include/*.h) \
	$(wildcard $(PLUGIN_DIR)/src/*.h) \
	$(PROXYSQL_PATH)/include/ProxySQL_Plugin.h \
	$(PLUGIN_DIR)/exports.map
OBJS := $(patsubst $(PLUGIN_DIR)/src/%.cpp,$(ODIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)
DEPFLAGS := -MMD -MP

.DEFAULT_GOAL := all

$(ODIR):
	mkdir -p $(ODIR)

# Recompile when build flags (especially -DDEBUG and feature tiers) change.
# A release/debug mix silently changes descriptor/services layouts and must not
# be masked by stale objects.
BUILDFLAGS_STAMP := $(ODIR)/.buildflags
.PHONY: FORCE
FORCE:
$(BUILDFLAGS_STAMP): FORCE | $(ODIR)
	@if [ ! -f $@ ] || [ "$$(cat $@ 2>/dev/null)" != "$(CC) $(CXX) $(CXXFLAGS)" ]; then \
		echo "$(CC) $(CXX) $(CXXFLAGS)" > $@; \
	fi

ifeq ($(UNAME_S),Linux)
$(ODIR)/%.o: $(PLUGIN_DIR)/src/%.cpp $(HEADERS) $(PLUGIN_DIR)/Makefile \
		$(BUILDFLAGS_STAMP) | $(ODIR)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(DEPFLAGS) $(IDIRS)

-include $(DEPS)

$(PLUGIN_SO): $(OBJS)
	$(CXX) -shared -o $@ $^ $(CXXFLAGS) $(PLUGIN_LDFLAGS)

.PHONY: all
all: $(PLUGIN_SO)
else
.PHONY: all
all:
	@echo "ERROR: plugins/tcp_proxy supports Linux only (engine uses epoll/eventfd);" >&2
	@echo "       this host reports UNAME_S=$(UNAME_S)." >&2
	@exit 1
endif

.PHONY: clean
clean:
	rm -rf $(ODIR) $(PLUGIN_SO)
