MARIADBLIBPATH=../../mariadb-native-client
DAEMONPATH=../../libdaemon-0.14
GLIBPATH=../../glib-2.40.0
JEMALLOCPATH=../../jemalloc-3.6.0
GLIB_IDIRS=-I$(GLIBPATH) -I$(GLIBPATH)/glib
GLIB_LDIRS=-L$(GLIBPATH)/glib/.libs -L$(GLIBPATH)/gthread/.libs
GLIB_LIB=-pthread -lgthread-2.0 -lglib-2.0
ODIR= obj
LDIR=../lib
IDIR=../include
IDIRS=-I../include -I../sqlite3 -I$(MARIADBLIBPATH)/include -I$(DAEMONPATH) -I$(JEMALLOCPATH)/include $(GLIB_IDIRS)
LDIRS=-L$(MARIADBLIBPATH)/libmysql -L$(DAEMONPATH)/libdaemon/.libs -L$(JEMALLOCPATH)/lib $(GLIB_LDIRS)
CC=gcc
#CC=clang
MARIADBAR=$(MARIADBLIBPATH)/libmysql/libmariadbclient.a
DAEMONAR=$(DAEMONPATH)/libdaemon/.libs/libdaemon.a
GLIBAR=$(GLIBPATH)/glib/.libs/libglib-2.0.a $(GLIBPATH)/gthread/.libs/libgthread-2.0.a
JEMALLOCAR=$(JEMALLOCPATH)/lib/libjemalloc.a
DEBUG=#-ggdb -DDEBUG
O0=-O0
O2=-O2
O1=-O1
O3=-O3 -mtune=native
OPTZ=$(O2)
CFLAGS=$(IDIRS) $(OPTZ) $(DEBUG)
LIBS=-rdynamic -Wl,-Bstatic -lmariadbclient -ldaemon -ljemalloc -lssl -lcrypto $(GLIB_LIB) -Wl,-Bdynamic -lkrb5 -ldl -lpthread -lm -lz -lrt
SQLITEOBJ=../sqlite3/sqlite3.o
EXECUTABLE=proxysql

_OBJ = tokenizer.o utils.o l_utils.o mysql_session.o mysql_data_stream.o mysql_backend.o main.o debug.o fundadb_hash.o global_variables.o mysql_connpool.o mysql_protocol.o mysql_handler.o network.o threads.o admin.o admin_sqlite.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) -Wall


proxysql: $(ODIR) $(OBJ) $(SQLITEOBJ) $(MARIADBAR) $(DAEMONAR) $(GLIBAR) $(JEMALLOCAR)
	gcc -o $@ $(MARIADBAR) $(DAEMONAR) $(GLIBAR) $(SQLITEOBJ) $(OBJ) $(CFLAGS) $(LDIRS) $(LIBS)

$(SQLITEOBJ): ../sqlite3/sqlite3.c
	$(CC) -c -o $@ $(CFLAGS) ../sqlite3/sqlite3.c

$(ODIR):
	mkdir $(ODIR)

all: $(EXECUTABLE)

.PHONY: clean resetdb clean_sqlite3 cleanall


cleanall: clean clean_sqlite3

clean:
	rm -f *.pid $(ODIR)/*.o *~ core $(INCDIR)/*~ $(EXECUTABLE)

clean_sqlite3:
	rm -f ../sqlite3/*.o

resetdb:
	rm -rf $(EXECUTABLE).db*
