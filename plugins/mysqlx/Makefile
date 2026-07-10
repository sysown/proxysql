#!/bin/make -f

# Walk upward until we find the repo root (src/proxysql_global.cpp).  A hop
# counter stops the climb at / on a sparse checkout that omits the marker
# file -- otherwise we'd loop forever.  Fails fast with a clear message so
# build output doesn't look like it's hanging.
PROXYSQL_PATH := $(shell set -e; d="$$PWD"; for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do if [ -f "$$d/src/proxysql_global.cpp" ]; then echo "$$d"; exit 0; fi; if [ "$$d" = "/" ]; then break; fi; d="$$(dirname "$$d")"; done; echo "ERROR: plugins/mysqlx/Makefile: could not find src/proxysql_global.cpp (repo root) from $$PWD; sparse checkout missing include/ and src/proxysql_global.cpp?" >&2; exit 1)

ifneq (,$(findstring ERROR,$(PROXYSQL_PATH)))
$(error $(PROXYSQL_PATH))
endif

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk

PLUGIN_DIR := $(PROXYSQL_PATH)/plugins/mysqlx
ODIR := $(PLUGIN_DIR)/obj
PLUGIN_SO := $(PLUGIN_DIR)/ProxySQL_MySQLX_Plugin.so

# Protobuf generated sources.
# Generated from test/deps/mysql-connector-c-8.4.0/.../plugin/x/protocol/protobuf/*.proto
# using protoc 3.21.12.  To regenerate:
#   PROTO_SRC=test/deps/mysql-connector-c-8.4.0/mysql-8.4.0/plugin/x/protocol/protobuf
#   protoc --proto_path=$PROTO_SRC --cpp_out=plugins/mysqlx/proto \
#     mysqlx.proto mysqlx_connection.proto mysqlx_session.proto \
#     mysqlx_datatypes.proto mysqlx_notice.proto mysqlx_sql.proto \
#     mysqlx_resultset.proto mysqlx_expect.proto
# Protobuf 3.21.12 is vendored under deps/protobuf and installed into a local
# prefix so the plugin does not depend on system/Homebrew protobuf packages.
PROTOBUF_VERSION := 3.21.12
PROTOBUF_SRC_DIR := $(PROXYSQL_PATH)/deps/protobuf/protobuf-$(PROTOBUF_VERSION)
PROTOBUF_INSTALL_DIR := $(PROTOBUF_SRC_DIR)/install
PROTOBUF_INCLUDE_DIR := $(PROTOBUF_INSTALL_DIR)/include
PROTOBUF_LIB := $(PROTOBUF_INSTALL_DIR)/lib/libprotobuf.a
PROTO_DIR := $(PLUGIN_DIR)/proto
PROTO_SRCS := $(wildcard $(PROTO_DIR)/*.pb.cc)
PROTO_OBJS := $(patsubst $(PROTO_DIR)/%.pb.cc,$(ODIR)/%.pb.o,$(PROTO_SRCS))

IDIRS := -I$(PROXYSQL_IDIR) -I$(PLUGIN_DIR)/include -I$(SQLITE3_IDIR) -I$(PROTO_DIR) -I$(PROTOBUF_INCLUDE_DIR) -I$(SSL_IDIR) -I$(PROMETHEUS_IDIR) -I$(LIBCONFIG_IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) -I$(RE2_IDIR) -I$(ZSTD_IDIR) -I$(PROXYSQL_PATH)/deps/lz4/lz4/lib

OPTZ ?= -O2 -ggdb
# Propagate feature-tier flags from the top-level build.  These MUST match
# the flags libproxysql.a was built with; a mismatch silently changes the
# ProxySQL_PluginDescriptor / ProxySQL_PluginServices layout the core and
# the plugin each see, and the loader then reads past the end of the
# plugin's static descriptor.
#
# Tier cascade (mirrors the top-level Makefile):
#   PROXYSQL40=1 ⇒ PROXYSQL31=1 ⇒ PROXYSQLFFTO=1 + PROXYSQLTSDB=1
ifeq ($(PROXYSQL40),1)
	PROXYSQL31 := 1
endif
ifeq ($(PROXYSQL31),1)
	PROXYSQLFFTO := 1
	PROXYSQLTSDB := 1
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

# -fvisibility=hidden + -fvisibility-inlines-hidden hides every C++ symbol by
# default; only the explicitly extern "C"-declared
# proxysql_plugin_descriptor_v1 entry point is exported. This prevents ODR
# collisions with the proxysql core when the .so is dlopen'd, and avoids
# leaking template instantiations across the boundary.
CXXFLAGS := $(STDCPP) -fPIC -fvisibility=hidden -fvisibility-inlines-hidden \
	$(OPTZ) $(WGCOV) $(WASAN) -pthread \
	$(PSQL40) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB)

# Hardening flags. Skip _FORTIFY_SOURCE under ASAN (incompatible) and when
# OPTZ contains -O0 (requires optimisation to take effect).
ifeq ($(WASAN),)
    ifeq (,$(findstring -O0,$(OPTZ)))
        CXXFLAGS += -D_FORTIFY_SOURCE=2
    endif
endif
CXXFLAGS += -fstack-protector-strong

.DEFAULT_GOAL := all

# Serialize this plugin's build. The vendored protobuf target (deps/Makefile)
# is a recursive sub-make whose recipe first `rm -rf`s deps/protobuf and then
# runs a slow cmake build+install. The plugin's .o, .pb.o and the final .so
# all list $(PROTOBUF_LIB) as a prereq, but under the parent build's -j that
# destructive rebuild has been observed to race the link -- the .so link
# fires while protobuf is only partway rebuilt and libprotobuf.a is absent:
#   /usr/bin/ld: cannot find .../protobuf-3.21.12/install/lib/libprotobuf.a
# .NOTPARALLEL forces protobuf to finish before any plugin object or link.
# The plugin build is small, so the lost parallelism is negligible.
.NOTPARALLEL:

SRCS := $(PLUGIN_DIR)/src/mysqlx_plugin.cpp \
	$(PLUGIN_DIR)/src/mysqlx_admin_schema.cpp \
	$(PLUGIN_DIR)/src/mysqlx_config_store.cpp \
	$(PLUGIN_DIR)/src/mysqlx_listener_reconcile.cpp \
	$(PLUGIN_DIR)/src/mysqlx_protocol.cpp \
	$(PLUGIN_DIR)/src/mysqlx_data_stream.cpp \
	$(PLUGIN_DIR)/src/mysqlx_connection.cpp \
	$(PLUGIN_DIR)/src/mysqlx_stats.cpp \
	$(PLUGIN_DIR)/src/mysqlx_session.cpp \
	$(PLUGIN_DIR)/src/mysqlx_thread.cpp
HEADERS := $(wildcard $(PLUGIN_DIR)/include/*.h) \
	$(PROXYSQL_PATH)/include/ProxySQL_Plugin.h
OBJS := $(patsubst $(PLUGIN_DIR)/src/%.cpp,$(ODIR)/%.o,$(SRCS))

$(ODIR):
	mkdir -p $(ODIR)

$(PROTOBUF_LIB):
	$(MAKE) -C $(PROXYSQL_PATH)/deps PROXYSQL40=1 protobuf
	@test -f $@ || { echo "ERROR: deps protobuf build did not produce $@" >&2; exit 1; }

# Several plugin sources transitively include <google/protobuf/...> via
# the .pb.h files under plugins/mysqlx/proto/ (e.g. mysqlx_protocol.cpp,
# mysqlx_connection.cpp, mysqlx_session.cpp -- all #include "mysqlx.pb.h"
# which #includes <google/protobuf/port_def.inc> and <google/protobuf/
# generated_message_bases.h>). Those headers only exist after the
# vendored protobuf 3.21.12 install is populated. Without listing
# $(PROTOBUF_LIB) as a prereq here, parallel make can schedule these
# .o compiles before the deps protobuf build fires -- the .pb.o rule
# (below) has the prereq, but it isn't enough on its own.
#
# The bug stayed hidden on hosts with a matching system libprotobuf-dev
# 3.21.x (e.g. Ubuntu 24.04 or 22.04 with backports) because the
# compile resolved everything from /usr/include/. CI runs on a clean
# ubuntu-22.04 with no system libprotobuf installed and exposes it.
$(ODIR)/%.o: $(PLUGIN_DIR)/src/%.cpp $(HEADERS) $(PROTOBUF_LIB) | $(ODIR)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(IDIRS)

$(ODIR)/%.pb.o: $(PROTO_DIR)/%.pb.cc $(PROTOBUF_LIB) | $(ODIR)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(IDIRS) -w

# X Protocol compression (zstd_stream / lz4_message) needs the static
# libzstd + liblz4 archives from deps/. We link them statically into the .so
# so the plugin works whether or not the host process exports zstd/lz4
# symbols globally — the loader uses RTLD_LOCAL, so a transitive dependency
# from the proxysql binary would not be visible here.
ZSTD_AR := $(PROXYSQL_PATH)/deps/zstd/zstd/lib/libzstd.a
LZ4_AR  := $(PROXYSQL_PATH)/deps/lz4/lz4/lib/liblz4.a

PLUGIN_LDFLAGS :=
ifeq ($(UNAME_S),Darwin)
PLUGIN_LDFLAGS += -Wl,-undefined,dynamic_lookup
endif

$(PLUGIN_SO): $(OBJS) $(PROTO_OBJS) $(PROTOBUF_LIB)
	$(CXX) -shared -o $@ $^ $(CXXFLAGS) -pthread -L$(SSL_LDIR) -lssl -lcrypto $(PLUGIN_LDFLAGS) \
		$(ZSTD_AR) $(LZ4_AR)

.PHONY: all
all: $(PLUGIN_SO)

.PHONY: clean
clean:
	rm -rf $(ODIR) $(PLUGIN_SO)
