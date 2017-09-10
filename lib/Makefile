

GIT_VERSION := $(shell git describe --long --tags)

DEPS_PATH=../deps


MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include

JEMALLOC_PATH=$(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR=$(JEMALLOC_PATH)/include/jemalloc

LIBCONFIG_PATH=$(DEPS_PATH)/libconfig/libconfig-1.4.9
LIBCONFIG_IDIR=-I$(LIBCONFIG_PATH)/lib

#INJECTION_PATH=$(DEPS_PATH)/libinjection
#INJECTION_IDIR=$(INJECTION_PATH)

RE2_PATH=$(DEPS_PATH)/re2/re2
RE2_IDIR=$(RE2_PATH)

PCRE_PATH=$(DEPS_PATH)/pcre/pcre

SQLITE3_DIR=$(DEPS_PATH)/sqlite3/sqlite3

CLICKHOUSE_CPP_DIR=$(DEPS_PATH)/clickhouse-cpp/clickhouse-cpp

IDIR=../include

IDIRS=-I$(IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) $(LIBCONFIG_IDIR) -I$(RE2_IDIR) -I$(SQLITE3_DIR) -I$(PCRE_PATH) -I/usr/local/include -I$(CLICKHOUSE_CPP_DIR)

LDIRS=-L$(JEMALLOC_PATH)/lib -L$(RE2_PATH)/obj -L$(INJECTION_PATH)

#LIBS=-rdynamic -Wl,-Bstatic -ljemalloc_pic -lre2 -Wl,-Bdynamic -ldl -lpthread -lm -lz -lrt $(EXTRALINK)
#LIBS=-Wl,--export-dynamic -Wl,-Bstatic -ljemalloc_pic -lre2 -Wl,-Bdynamic -ldl -lpthread -lm -lz -lrt $(EXTRALINK)

ODIR= obj

#CC=gcc
#CXX=g++
#CC=clang

#CFLAGS=$(IDIRS) $(OPTZ) $(DEBUG) -Wall #-lcrypto
#CXXFLAGS=-std=c++11 $(CFLAGS) $(LDIRS) $(LIBS)
NOJEMALLOC := $(shell echo $(NOJEMALLOC))
ifeq ($(NOJEMALLOC),1)
NOJEM=-DNOJEM
else
NOJEM=
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
NOJEM=-DNOJEM
endif

PROXYSQLCLICKHOUSE := $(shell echo $(PROXYSQLCLICKHOUSE))
ifeq ($(PROXYSQLCLICKHOUSE),1)
PSQLCH=-DPROXYSQLCLICKHOUSE
else
PSQLCH=
endif

MYCFLAGS=$(IDIRS) $(OPTZ) $(DEBUG) -Wall -DGITVERSION=\"$(GIT_VERSION)\" $(NOJEM)
MYCXXFLAGS=-std=c++11 $(MYCFLAGS) $(PSQLCH)

default: libproxysql.a
.PHONY: default

_OBJ = c_tokenizer.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))
_OBJ_CXX = ProxySQL_GloVars.oo network.oo debug.oo configfile.oo Query_Cache.oo SpookyV2.oo MySQL_Authentication.oo gen_utils.oo sqlite3db.oo mysql_connection.oo MySQL_HostGroups_Manager.oo mysql_data_stream.oo MySQL_Thread.oo MySQL_Session.oo MySQL_Protocol.oo mysql_backend.oo Query_Processor.oo ProxySQL_Admin.oo MySQL_Monitor.oo MySQL_Logger.oo thread.oo MySQL_PreparedStatement.oo ProxySQL_Cluster.oo SQLite3_Server.oo ClickHouse_Authentication.oo ClickHouse_Server.oo
OBJ_CXX = $(patsubst %,$(ODIR)/%,$(_OBJ_CXX))

%.ko: %.cpp
	$(CXX) -fPIC -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS)

$(ODIR)/%.o: %.c
	$(CC) -fPIC -c -o $@ $< $(MYCFLAGS) $(CFLAGS)

$(ODIR)/%.oo: %.cpp
	$(CXX) -fPIC -c -o $@ $< $(MYCXXFLAGS) $(CXXFLAGS)

libproxysql.a: $(ODIR) $(OBJ) $(OBJ_CXX) $(RE2_PATH)/obj/libre2.a $(SQLITE3_DIR)/sqlite3.o
	ar rcs $@ $(OBJ) $(OBJ_CXX) $(RE2_PATH)/obj/libre2.a $(SQLITE3_DIR)/sqlite3.o

$(ODIR):
	mkdir $(ODIR)

#all: $(EXECUTABLE)


clean:
	rm -f *.pid $(ODIR)/*.oo $(ODIR)/*.o *.ko *.so *~ core libproxysql.a


## self note
# ../deps/protobuf/protobuf/src/protoc -I=. --cpp_out=. ./mysql_logger.proto
# mv mysql_logger.pb.cc mysql_logger.pb.cpp
