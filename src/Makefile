



DEPS_PATH=../deps

MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include
MARIADB_LDIR=$(MARIADB_PATH)/libmariadb


DAEMONPATH=$(DEPS_PATH)/libdaemon/libdaemon
DAEMONPATH_IDIR=$(DAEMONPATH)
DAEMONPATH_LDIR=$(DAEMONPATH)/libdaemon/.libs

#LIBEVENT_PATH=$(DEPS_PATH)/libevent/libevent
#LIBEVENT_IDIR=$(LIBEVENT_PATH)/include
#LIBEVENT_LDIR=$(LIBEVENT_PATH)/.libs

JEMALLOC_PATH=$(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR=$(JEMALLOC_PATH)/include/jemalloc
JEMALLOC_LDIR=$(JEMALLOC_PATH)/lib

#GLIB_PATH=$(DEPS_PATH)/glib/glib
#GLIB_IDIRS=-I$(GLIB_PATH) -I$(GLIB_PATH)/glib
#GLIB_LDIRS=-L$(GLIB_PATH)/glib/.libs -L$(GLIB_PATH)/gthread/.libs
#GLIB_LIB=-pthread -lgthread-2.0 -lglib-2.0
#GLIB_LDIRS=-L$(GLIB_PATH)/glib/.libs -L$(GLIB_PATH)/gthread/.libs -L$(GLIB_PATH)/gmodule/.libs
#GLIB_LIB=-pthread -lgmodule-2.0 -lgthread-2.0 -lglib-2.0

LIBCONFIG_PATH=$(DEPS_PATH)/libconfig/libconfig-1.4.9
LIBCONFIG_IDIR=-I$(LIBCONFIG_PATH)/lib
LIBCONFIG_LDIR=-L$(LIBCONFIG_PATH)/lib/.libs

INJECTION_PATH=$(DEPS_PATH)/libinjection
INJECTION_IDIR=$(INJECTION_PATH)

LIBEVENT_PATH=$(DEPS_PATH)/libevent/libevent
LIBEVENT_IDIR=$(LIBEVENT_PATH)/include
LIBEVENT_LDIR=$(LIBEVENT_PATH)/.libs

RE2_PATH=$(DEPS_PATH)/re2/re2
RE2_IDIR=$(RE2_PATH)

IDIR=../include
LDIR=../lib
#IDIRS=-I$(IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) -I$(LIBEVENT_IDIR) $(GLIB_IDIRS) $(LIBCONFIG_IDIR)
#LDIRS=-L$(LDIR) -L$(JEMALLOC_LDIR) -L$(MARIADB_LDIR) -L$(LIBEVENT_LDIR) $(GLIB_LDIRS) $(LIBCONFIG_LDIR)
IDIRS=-I$(IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) $(LIBCONFIG_IDIR) -I$(DAEMONPATH_IDIR)
LDIRS=-L$(LDIR) -L$(JEMALLOC_LDIR) $(LIBCONFIG_LDIR) -L$(RE2_PATH)/obj -L$(INJECTION_PATH) -L$(LIBEVENT_LDIR) -L$(MARIADB_LDIR) -L$(DAEMONPATH_LDIR)
#LDIRS=-L$(LDIR) -L$(JEMALLOC_LDIR) -L$(MARIADB_LDIR) $(GLIB_LDIRS) $(LIBCONFIG_LDIR)


CFLAGS=-std=c++0x -D_GLIBCXX_USE_C99 $(IDIRS) $(OPTZ) $(DEBUG)
#LIBS=-rdynamic -Wl,-Bstatic -lconfig -lproxysql -ldaemon -ljemalloc -lconfig++ -lre2 -linjection -levent -lmariadbclient -Wl,-Bdynamic -lpthread -lm -lz -lrt -ldl -lcrypto -lssl $(EXTRALINK)
LIBS=-rdynamic -Wl,-Bstatic -lconfig -lproxysql -ldaemon -ljemalloc -lconfig++ -lre2 -linjection -levent -lmariadbclient -Wl,-Bdynamic -lpthread -lm -lz -lrt -lc -lc++ -lcrypto -lssl $(EXTRALINK)
#LIBS=-rdynamic -Wl,-Bstatic -lproxysql -ljemalloc -levent $(GLIB_LIB) -Wl,-Bdynamic -ldl -lpthread -lm -lz -lrt

LIBPROXYSQLAR=$(LDIR)/libproxysql.a

ODIR= obj

#CC=gcc
CC=g++48
#CC=clang


EXECUTABLE=proxysql

_OBJ = main.o proxysql_global.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.cpp
	$(CC) -c -o $@ $< $(CFLAGS) -Wall



proxysql: $(ODIR) $(OBJ) $(LIBPROXYSQLAR)
	$(CC) -o $@ $(OBJ) $(LIBPROXYSQLAR) $(CFLAGS) $(LDIRS) $(LIBS)

$(ODIR):
	mkdir $(ODIR)

$(LIBPROXYSQLAR):
	cd $(LDIR) && gmake

default: $(EXECUTABLE)

clean:
	rm -f *.pid $(ODIR)/*.o *~ core $(EXECUTABLE)

