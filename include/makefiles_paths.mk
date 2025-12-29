#!/bin/make -f


SYS_LOC_IDIR := /usr/local/include

PROXYSQL_PATH ?= $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)
PROXYSQL_IDIR := $(PROXYSQL_PATH)/include
PROXYSQL_LDIR := $(PROXYSQL_PATH)/lib

DEPS_PATH := $(PROXYSQL_PATH)/deps


include $(PROXYSQL_PATH)/common_mk/openssl_flags.mk


MARIADB_PATH := $(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR := $(MARIADB_PATH)/include
MARIADB_LDIR := $(MARIADB_PATH)/libmariadb

LIBDAEMON_PATH := $(DEPS_PATH)/libdaemon/libdaemon
LIBDAEMON_IDIR := $(LIBDAEMON_PATH)
LIBDAEMON_LDIR := $(LIBDAEMON_PATH)/libdaemon/.libs

JEMALLOC_PATH := $(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR := $(JEMALLOC_PATH)/include/jemalloc
JEMALLOC_LDIR := $(JEMALLOC_PATH)/lib

LIBCONFIG_PATH := $(DEPS_PATH)/libconfig/libconfig
LIBCONFIG_IDIR := $(LIBCONFIG_PATH)/lib
LIBCONFIG_LDIR := $(LIBCONFIG_PATH)/out

PROMETHEUS_PATH := $(DEPS_PATH)/prometheus-cpp/prometheus-cpp
PROMETHEUS_IDIR := $(PROMETHEUS_PATH)/pull/include -I$(PROMETHEUS_PATH)/core/include
PROMETHEUS_LDIR := $(PROMETHEUS_PATH)/lib

JSON_PATH := $(DEPS_PATH)/json
JSON_IDIR := $(JSON_PATH)

RE2_PATH := $(DEPS_PATH)/re2/re2
RE2_IDIR := $(RE2_PATH)
RE2_LDIR := $(RE2_PATH)/obj

PCRE_PATH := $(DEPS_PATH)/pcre/pcre
PCRE_IDIR := $(PCRE_PATH)
PCRE_LDIR := $(PCRE_PATH)/.libs

SQLITE3_PATH := $(DEPS_PATH)/sqlite3/sqlite3
SQLITE3_IDIR := $(SQLITE3_PATH)
SQLITE3_LDIR := $(SQLITE3_PATH)

CITYHASH_PATH := $(DEPS_PATH)/cityhash/cityhash
CITYHASH_LDIR := $(CITYHASH_PATH)/src/.libs

LZ4_PATH := $(DEPS_PATH)/lz4/lz4
LZ4_LDIR := $(LZ4_PATH)/lib

CLICKHOUSE_CPP_PATH := $(DEPS_PATH)/clickhouse-cpp/clickhouse-cpp
CLICKHOUSE_CPP_IDIR := $(CLICKHOUSE_CPP_PATH) -I$(CLICKHOUSE_CPP_PATH)/contrib/absl
CLICKHOUSE_CPP_LDIR := $(CLICKHOUSE_CPP_PATH)/clickhouse

LIBINJECTION_PATH := $(DEPS_PATH)/libinjection/libinjection
LIBINJECTION_IDIR := $(LIBINJECTION_PATH)/src
LIBINJECTION_LDIR := $(LIBINJECTION_PATH)/src

LIBHTTPSERVER_PATH := $(DEPS_PATH)/libhttpserver/libhttpserver
LIBHTTPSERVER_IDIR := $(LIBHTTPSERVER_PATH)/src
LIBHTTPSERVER_LDIR := $(LIBHTTPSERVER_PATH)/build/src/.libs

MICROHTTPD_PATH := $(DEPS_PATH)/libmicrohttpd/libmicrohttpd
MICROHTTPD_IDIR := $(MICROHTTPD_PATH) -I$(MICROHTTPD_PATH)/src/include
MICROHTTPD_LDIR := $(MICROHTTPD_PATH)/src/microhttpd/.libs

COREDUMPER_PATH := $(DEPS_PATH)/coredumper/coredumper
COREDUMPER_IDIR := $(COREDUMPER_PATH)/include
COREDUMPER_LDIR := $(COREDUMPER_PATH)/src

CURL_PATH := $(DEPS_PATH)/curl/curl
CURL_IDIR := $(CURL_PATH)/include
CURL_LDIR := $(CURL_PATH)/lib/.libs

EV_PATH := $(DEPS_PATH)/libev/libev
EV_IDIR := $(EV_PATH)
EV_LDIR := $(EV_PATH)/.libs

POSTGRESQL_PATH := $(DEPS_PATH)/postgresql/postgresql/src
POSTGRESQL_IDIR := $(POSTGRESQL_PATH)/include -I$(POSTGRESQL_PATH)/interfaces/libpq
POSTGRESQL_LDIR := $(POSTGRESQL_PATH)/interfaces/libpq -L$(POSTGRESQL_PATH)/common -L$(POSTGRESQL_PATH)/port

LIBUSUAL_PATH := $(DEPS_PATH)/libusual/libusual
LIBUSUAL_IDIR := $(LIBUSUAL_PATH)
LIBUSUAL_LDIR := $(LIBUSUAL_PATH)/.libs

LIBSCRAM_PATH := $(DEPS_PATH)/libscram
LIBSCRAM_IDIR := $(LIBSCRAM_PATH)/include
LIBSCRAM_LDIR := $(LIBSCRAM_PATH)/lib


TAP_PATH := $(PROXYSQL_PATH)/test/tap/tap
TAP_IDIR := $(TAP_PATH)
TAP_LDIR := $(TAP_PATH)

DOTENV_PATH := $(TAP_PATH)/cpp-dotenv/static/cpp-dotenv
DOTENV_IDIR := $(DOTENV_PATH)/include
DOTENV_LDIR := $(DOTENV_PATH)

DOTENV_DYN_PATH := $(TAP_LDIR)/cpp-dotenv/dynamic/cpp-dotenv
DOTENV_DYN_IDIR := $(DOTENV_DYN_PATH)/include
DOTENV_DYN_LDIR := $(TAP_LDIR)


TEST_DEPS_PATH := $(PROXYSQL_PATH)/test/deps

TEST_MARIADB_PATH := $(TEST_DEPS_PATH)/mariadb-connector-c/mariadb-connector-c
TEST_MARIADB_IDIR := $(TEST_MARIADB_PATH)/include
TEST_MARIADB_LDIR := $(TEST_MARIADB_PATH)/libmariadb

TEST_MYSQL_PATH := $(TEST_DEPS_PATH)/mysql-connector-c/mysql-connector-c
TEST_MYSQL_IDIR := $(TEST_MYSQL_PATH)/include
TEST_MYSQL_EDIR := $(TEST_MYSQL_PATH)/libbinlogevents/export/
TEST_MYSQL_LDIR := $(TEST_MYSQL_PATH)/libmysql

TEST_MYSQL8_PATH := $(TEST_DEPS_PATH)/mysql-connector-c-8.4.0/mysql-connector-c
TEST_MYSQL8_IDIR := $(TEST_MYSQL8_PATH)/include
TEST_MYSQL8_EDIR := $(TEST_MYSQL8_PATH)/libbinlogevents/export/
TEST_MYSQL8_LDIR := $(TEST_MYSQL8_PATH)/libmysql
