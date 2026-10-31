#!/bin/make -f

PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk

.DEFAULT_GOAL := all

CPPFLAGS := -I$(SSL_IDIR)
CXXFLAGS := $(STDCPP) -O0 -ggdb -Wall -Wextra -Werror $(WASAN)
LDFLAGS := -L$(SSL_LDIR) $(WASAN)
LDLIBS := -lssl -lcrypto -lpthread

.PHONY: all clean
all: aws_iam_mysql_server-t

aws_iam_mysql_server-t: aws_iam_mysql_server.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@

clean:
	rm -f aws_iam_mysql_server-t
