#!/bin/make -f

PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

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
# -fvisibility=hidden + -fvisibility-inlines-hidden hides every C++ symbol by
# default; only the explicitly extern "C"-declared
# proxysql_plugin_descriptor_v1 entry point is exported. This prevents ODR
# collisions with the proxysql core when the .so is dlopen'd, and avoids
# leaking template instantiations across the boundary.
CXXFLAGS := $(STDCPP) -fPIC -fvisibility=hidden -fvisibility-inlines-hidden $(OPTZ) $(WGCOV) $(WASAN) -pthread

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
