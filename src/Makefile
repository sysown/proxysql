



DEPS_PATH=../deps

MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include
#MARIADB_LDIR=$(MARIADB_PATH)/libmariadb


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



IDIR=../include
LDIR=../lib
#IDIRS=-I$(IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) -I$(LIBEVENT_IDIR) $(GLIB_IDIRS) $(LIBCONFIG_IDIR)
#LDIRS=-L$(LDIR) -L$(JEMALLOC_LDIR) -L$(MARIADB_LDIR) -L$(LIBEVENT_LDIR) $(GLIB_LDIRS) $(LIBCONFIG_LDIR)
IDIRS=-I$(IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) $(LIBCONFIG_IDIR)
LDIRS=-L$(LDIR) -L$(JEMALLOC_LDIR) $(LIBCONFIG_LDIR)
#LDIRS=-L$(LDIR) -L$(JEMALLOC_LDIR) -L$(MARIADB_LDIR) $(GLIB_LDIRS) $(LIBCONFIG_LDIR)


CFLAGS=-std=c++0x $(IDIRS) $(OPTZ) $(DEBUG)
LIBS=-rdynamic -Wl,-Bstatic -lconfig -lproxysql -ljemalloc -lconfig++ -Wl,-Bdynamic -lpthread -lm -lz -lrt -ldl -lcrypto -lssl $(EXTRALINK)
#LIBS=-rdynamic -Wl,-Bstatic -lproxysql -ljemalloc -levent $(GLIB_LIB) -Wl,-Bdynamic -ldl -lpthread -lm -lz -lrt

LIBPROXYSQLAR=$(LDIR)/libproxysql.a

ODIR= obj

#CC=gcc
CC=g++
#CC=clang


EXECUTABLE=proxysql

_OBJ = main.o proxysql_global.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.cpp
	$(CC) -c -o $@ $< $(CFLAGS) -Wall



proxysql: $(ODIR) $(OBJ) $(LIBPROXYSQLAR)
	$(CC) -o $@ $(OBJ) $(CFLAGS) $(LDIRS) $(LIBS)

$(ODIR):
	mkdir $(ODIR)

$(LIBPROXYSQLAR):
	cd $(LDIR) && make

default: $(EXECUTABLE)

clean:
	rm -f *.pid $(ODIR)/*.o *~ core $(EXECUTABLE)

