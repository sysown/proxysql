



DEPS_PATH=../../deps

MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include
MARIADB_LDIR=$(MARIADB_PATH)/libmariadb


DAEMONPATH=$(DEPS_PATH)/libdaemon/libdaemon
DAEMONPATH_IDIR=$(DAEMONPATH)
DAEMONPATH_LDIR=$(DAEMONPATH)/libdaemon/.libs

JEMALLOC_PATH=$(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR=$(JEMALLOC_PATH)/include/jemalloc
JEMALLOC_LDIR=$(JEMALLOC_PATH)/lib

LIBCONFIG_PATH=$(DEPS_PATH)/libconfig/libconfig-1.7.2
LIBCONFIG_IDIR=-I$(LIBCONFIG_PATH)/lib
LIBCONFIG_LDIR=-L$(LIBCONFIG_PATH)/lib/.libs

EV_DIR=$(DEPS_PATH)/libev/libev/
EV_IDIR=$(EV_DIR)

RE2_PATH=$(DEPS_PATH)/re2/re2
RE2_IDIR=$(RE2_PATH)

SQLITE3_DIR=$(DEPS_PATH)/sqlite3/sqlite3

IDIR=../../include
LDIR=../../lib
IDIRS=-I$(IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) $(LIBCONFIG_IDIR) -I$(DAEMONPATH_IDIR) -I$(SQLITE3_DIR) -I$(EV_IDIR)
LDIRS=-L$(LDIR) -L$(JEMALLOC_LDIR) $(LIBCONFIG_LDIR) -L$(RE2_PATH)/obj -L$(MARIADB_LDIR) -L$(DAEMONPATH_LDIR)

DEBUG=-DDEBUG
MYCPPFLAGS=-std=c++11 $(IDIRS) $(OPTZ) $(DEBUG) -ggdb
LDFLAGS+=
MYLIBS=-Wl,--export-dynamic -Wl,-Bstatic -lconfig -lproxysql -ldaemon -ljemalloc -lconfig++ -lre2 -lmariadbclient -Wl,-Bdynamic -lpthread -lm -lz -lrt -lcrypto -lssl $(EXTRALINK)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	MYLIBS+= -ldl
endif
ifeq ($(UNAME_S),FreeBSD)
	MYLIBS+= -lexecinfo
endif

LIBPROXYSQLAR=$(LDIR)/libproxysql.a

.PHONY: default
default: client1

client1: client1.cpp
	$(CXX) -o $@ $@.cpp $(LIBPROXYSQLAR) $(MYCPPFLAGS) $(CPPFLAGS) $(LDIRS) $(LIBS) $(LDFLAGS) $(MYLIBS)

client2: client2.cpp
	$(CXX) -o $@ $@.cpp $(LIBPROXYSQLAR) $(MYCPPFLAGS) $(CPPFLAGS) $(LDIRS) $(LIBS) $(LDFLAGS) $(MYLIBS)

client3: client3.cpp
	$(CXX) -o $@ $@.cpp $(LIBPROXYSQLAR) $(MYCPPFLAGS) $(CPPFLAGS) $(LDIRS) $(LIBS) $(LDFLAGS) $(MYLIBS)

client4: client4.cpp
	$(CXX) -o $@ $@.cpp $(LIBPROXYSQLAR) $(MYCPPFLAGS) $(CPPFLAGS) $(LDIRS) $(LIBS) $(LDFLAGS) $(MYLIBS)

client5: client5.cpp
	$(CXX) -o $@ $@.cpp $(LIBPROXYSQLAR) $(MYCPPFLAGS) $(CPPFLAGS) $(LDIRS) $(LIBS) $(LDFLAGS) $(MYLIBS)

client6: client6.cpp
	$(CXX) -o $@ $@.cpp $(LIBPROXYSQLAR) $(MYCPPFLAGS) $(CPPFLAGS) $(LDIRS) $(LIBS) $(LDFLAGS) $(MYLIBS)

client7: client7.cpp
	$(CXX) -o $@ $@.cpp $(LIBPROXYSQLAR) $(MYCPPFLAGS) $(CPPFLAGS) $(LDIRS) $(LIBS) $(LDFLAGS) $(MYLIBS)

client8: client8.cpp
	$(CXX) -o $@ $@.cpp $(LIBPROXYSQLAR) $(MYCPPFLAGS) $(CPPFLAGS) $(LDIRS) $(LIBS) $(LDFLAGS) $(MYLIBS)

client9: client9.cpp
	$(CXX) -o $@ $@.cpp $(LIBPROXYSQLAR) $(MYCPPFLAGS) $(CPPFLAGS) $(LDIRS) $(LIBS) $(LDFLAGS) $(MYLIBS)


default: $(EXECUTABLE)

clean:
	rm -f *~ core $(default)

