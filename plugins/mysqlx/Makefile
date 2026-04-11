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

IDIRS := -I$(PROXYSQL_IDIR) -I$(PLUGIN_DIR)/include -I$(SQLITE3_IDIR) -I$(PROTO_DIR) -I$(SSL_IDIR) -I$(PROMETHEUS_IDIR) -I$(LIBCONFIG_IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) -I$(RE2_IDIR)

OPTZ ?= -O2 -ggdb
CXXFLAGS := $(STDCPP) -fPIC $(OPTZ) $(WGCOV) $(WASAN) -pthread

.DEFAULT_GOAL := all

SRCS := $(PLUGIN_DIR)/src/mysqlx_plugin.cpp \
	$(PLUGIN_DIR)/src/mysqlx_admin_schema.cpp \
	$(PLUGIN_DIR)/src/mysqlx_config_store.cpp \
	$(PLUGIN_DIR)/src/mysqlx_worker.cpp \
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
