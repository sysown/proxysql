#!/bin/make -f

PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk

PLUGIN_DIR := $(PROXYSQL_PATH)/plugins/mysqlx
ODIR := $(PLUGIN_DIR)/obj
PLUGIN_SO := $(PLUGIN_DIR)/ProxySQL_MySQLX_Plugin.so

# Protobuf generated sources
PROTO_DIR := $(PLUGIN_DIR)/proto
PROTO_SRCS := $(wildcard $(PROTO_DIR)/*.pb.cc)
PROTO_OBJS := $(patsubst $(PROTO_DIR)/%.pb.cc,$(ODIR)/%.pb.o,$(PROTO_SRCS))

IDIRS := -I$(PROXYSQL_IDIR) -I$(PLUGIN_DIR)/include -I$(SQLITE3_IDIR) -I$(PROTO_DIR)

OPTZ ?= -O2 -ggdb
CXXFLAGS := $(STDCPP) -fPIC $(OPTZ) $(WGCOV) $(WASAN)

.DEFAULT_GOAL := all

SRCS := $(PLUGIN_DIR)/src/mysqlx_plugin.cpp \
	$(PLUGIN_DIR)/src/mysqlx_admin_schema.cpp \
	$(PLUGIN_DIR)/src/mysqlx_config_store.cpp \
	$(PLUGIN_DIR)/src/mysqlx_worker.cpp
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
	$(CXX) -shared -o $@ $^ $(CXXFLAGS) -lprotobuf

.PHONY: all
all: $(PLUGIN_SO)

.PHONY: clean
clean:
	rm -rf $(ODIR) $(PLUGIN_SO)
