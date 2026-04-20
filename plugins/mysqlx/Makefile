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
PROTO_DIR := $(PLUGIN_DIR)/proto
PROTO_SRCS := $(wildcard $(PROTO_DIR)/*.pb.cc)
PROTO_OBJS := $(patsubst $(PROTO_DIR)/%.pb.cc,$(ODIR)/%.pb.o,$(PROTO_SRCS))

# Generated .pb.cc files were produced with protoc 3.21.12. The plugin links
# dynamically against the system libprotobuf, which is ABI-compatible only
# within the protobuf 3.x major version (the 4.x release cycle introduced an
# incompatible ABI — libprotobuf.so SONAME changed). Detect the installed
# version up front and fail fast so we never produce a .so that links cleanly
# but crashes the first time a virtual is dispatched into the proto runtime.
PROTOBUF_GENERATED_VERSION := 3.21.12
PROTOBUF_VERSION := $(shell pkg-config --modversion protobuf 2>/dev/null)
ifeq ($(PROTOBUF_VERSION),)
    $(error libprotobuf not found via pkg-config. Install libprotobuf-dev (3.x). \
        The mysqlx plugin's vendored .pb.cc/.pb.h were generated with protoc \
        $(PROTOBUF_GENERATED_VERSION) and require an ABI-compatible 3.x runtime)
endif
PROTOBUF_MAJOR := $(firstword $(subst ., ,$(PROTOBUF_VERSION)))
ifneq ($(PROTOBUF_MAJOR),3)
    $(error libprotobuf $(PROTOBUF_VERSION) is not ABI-compatible with the \
        vendored .pb.cc generated for protoc $(PROTOBUF_GENERATED_VERSION). \
        Install libprotobuf 3.x (e.g. 3.21.12) or regenerate the proto sources \
        against the installed version. See the regeneration recipe above)
endif

IDIRS := -I$(PROXYSQL_IDIR) -I$(PLUGIN_DIR)/include -I$(SQLITE3_IDIR) -I$(PROTO_DIR) -I$(SSL_IDIR) -I$(PROMETHEUS_IDIR) -I$(LIBCONFIG_IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) -I$(RE2_IDIR)

OPTZ ?= -O2 -ggdb
# Propagate feature-tier flags from the top-level build.  These MUST match
# the flags libproxysql.a was built with; a mismatch silently changes the
# ProxySQL_PluginDescriptor / ProxySQL_PluginServices layout the core and
# the plugin each see, and the loader then reads past the end of the
# plugin's static descriptor.  (If this Makefile is run standalone, the
# caller is expected to export PROXYSQL40/31/etc. to match the lib.)
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
PSQLGA :=
ifeq ($(PROXYSQLGENAI),1)
	PSQLGA := -DPROXYSQLGENAI
endif

# -fvisibility=hidden + -fvisibility-inlines-hidden hides every C++ symbol by
# default; only the explicitly extern "C"-declared
# proxysql_plugin_descriptor_v1 entry point is exported. This prevents ODR
# collisions with the proxysql core when the .so is dlopen'd, and avoids
# leaking template instantiations across the boundary.
CXXFLAGS := $(STDCPP) -fPIC -fvisibility=hidden -fvisibility-inlines-hidden \
	$(OPTZ) $(WGCOV) $(WASAN) -pthread \
	$(PSQL40) $(PSQL31) $(PSQLFFTO) $(PSQLTSDB) $(PSQLGA)

# Hardening flags. Skip _FORTIFY_SOURCE under ASAN (incompatible) and when
# OPTZ contains -O0 (requires optimisation to take effect).
ifeq ($(WASAN),)
    ifeq (,$(findstring -O0,$(OPTZ)))
        CXXFLAGS += -D_FORTIFY_SOURCE=2
    endif
endif
CXXFLAGS += -fstack-protector-strong

.DEFAULT_GOAL := all

SRCS := $(PLUGIN_DIR)/src/mysqlx_plugin.cpp \
	$(PLUGIN_DIR)/src/mysqlx_admin_schema.cpp \
	$(PLUGIN_DIR)/src/mysqlx_config_store.cpp \
	$(PLUGIN_DIR)/src/mysqlx_listener_reconcile.cpp \
	$(PLUGIN_DIR)/src/mysqlx_protocol.cpp \
	$(PLUGIN_DIR)/src/mysqlx_frontend_session.cpp \
	$(PLUGIN_DIR)/src/mysqlx_backend_session.cpp \
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

$(ODIR)/%.o: $(PLUGIN_DIR)/src/%.cpp $(HEADERS) | $(ODIR)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(IDIRS)

$(ODIR)/%.pb.o: $(PROTO_DIR)/%.pb.cc | $(ODIR)
	$(CXX) -c -o $@ $< $(CXXFLAGS) -I$(PROTO_DIR) -w

$(PLUGIN_SO): $(OBJS) $(PROTO_OBJS)
	$(CXX) -shared -o $@ $^ $(CXXFLAGS) -pthread -lprotobuf -lssl -lcrypto

.PHONY: all
all: $(PLUGIN_SO)

.PHONY: clean
clean:
	rm -rf $(ODIR) $(PLUGIN_SO)
