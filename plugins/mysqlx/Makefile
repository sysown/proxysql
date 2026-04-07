#!/bin/make -f

PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk

PLUGIN_DIR := $(PROXYSQL_PATH)/plugins/mysqlx
ODIR := $(PLUGIN_DIR)/obj
PLUGIN_SO := $(PLUGIN_DIR)/ProxySQL_MySQLX_Plugin.so

IDIRS := -I$(PROXYSQL_IDIR) -I$(PLUGIN_DIR)/include

OPTZ ?= -O2 -ggdb
CXXFLAGS := $(STDCPP) -fPIC $(OPTZ) $(WGCOV) $(WASAN)

.DEFAULT_GOAL := all

SRCS := $(PLUGIN_DIR)/src/mysqlx_plugin.cpp \
	$(PLUGIN_DIR)/src/mysqlx_admin_schema.cpp
OBJS := $(patsubst $(PLUGIN_DIR)/src/%.cpp,$(ODIR)/%.o,$(SRCS))

$(ODIR):
	mkdir -p $(ODIR)

$(ODIR)/%.o: $(PLUGIN_DIR)/src/%.cpp | $(ODIR)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(IDIRS)

$(PLUGIN_SO): $(OBJS)
	$(CXX) -shared -o $@ $^ $(CXXFLAGS)

.PHONY: all
all: $(PLUGIN_SO)

.PHONY: clean
clean:
	rm -rf $(ODIR) $(PLUGIN_SO)
