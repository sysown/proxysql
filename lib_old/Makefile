



DEPS_PATH=../deps


MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include

LIBEVENT_PATH=$(DEPS_PATH)/libevent/libevent
LIBEVENT_IDIR=$(LIBEVENT_PATH)/include


JEMALLOC_PATH=$(DEPS_PATH)/jemalloc/jemalloc
JEMALLOC_IDIR=$(JEMALLOC_PATH)/include/jemalloc

GLIB_PATH=$(DEPS_PATH)/glib/glib
GLIB_IDIRS=-I$(GLIB_PATH) -I$(GLIB_PATH)/glib

IDIR=../include

IDIRS=-I$(IDIR) -I$(JEMALLOC_IDIR) -I$(MARIADB_IDIR) -I$(LIBEVENT_IDIR) $(GLIB_IDIRS) 

#LDIRS=-L$(JEMALLOC_PATH)/lib

#LIBS=-rdynamic -Wl,-Bstatic -ljemalloc -Wl,-Bdynamic -ldl -lpthread -lm -lz -lrt


ODIR= obj

CC=gcc
#CC=g++
#CC=clang

DEBUG=-ggdb -DDEBUG
O0=-O0
O2=-O2
O1=-O1
O3=-O3 -mtune=native
OPTZ=$(O2)
CFLAGS=$(IDIRS) $(OPTZ) $(DEBUG)

default: libproxysql.a

#_OBJ = mysql_protocol.o debug.o global_variables.o mysql_data_stream.o network.o proxysql_global.o
_OBJ = mysql_protocol.o debug.o global_variables.o network.o proxysql_global.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))
_OBJ_CPP = mysql_thread.oo mysql_data_stream.oo mysql_session.oo mysql_backend.oo
OBJ_CPP = $(patsubst %,$(ODIR)/%,$(_OBJ_CPP))

$(ODIR)/%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) -Wall

$(ODIR)/%.oo: %.cpp
	g++ -c -o $@ $< $(CFLAGS) -Wall

#mysql_data_stream.oo: mysql_data_stream.cpp
#	g++ -c -o mysql_data_stream.oo mysql_data_stream.cpp $(CFLAGS) -Wall
	

libproxysql.a: $(ODIR) $(OBJ) $(OBJ_CPP)
	ar rcs $@ $(OBJ) $(OBJ_CPP)

$(ODIR):
	mkdir $(ODIR)

#all: $(EXECUTABLE)


clean:
	rm -f *.pid $(ODIR)/*.oo $(ODIR)/*.o *~ core $(EXECUTABLE)

