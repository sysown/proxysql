MARIADBLIBPATH=../../mariadb-native-client
DAEMONPATH=../../libdaemon-0.14
GLIB_CFLAGS=`pkg-config --cflags gthread-2.0`
GLIB_LIB=`pkg-config --libs gthread-2.0`
ODIR= obj
LDIR=../lib
IDIR=../include
IDIRS=-I../include -I../sqlite3 -I$(MARIADBLIBPATH)/include -I$(DAEMONPATH) $(GLIB_CFLAGS)
LDIRS=-L$(MARIADBLIBPATH)/libmysql -L$(DAEMONPATH)/libdaemon/.libs $(GLIB_CFLAGS)
CC=gcc
MARIADBAR=$(MARIADBLIBPATH)/libmysql/libmariadbclient.a
DAEMONAR=$(DAEMONPATH)/libdaemon/.libs/libdaemon.a
DEBUG=-ggdb -DDEBUG
O0=-O0
O2=-O2
O1=-O1
O3=-O3 -mtune=native
OPTZ=$(O0)
CFLAGS=$(IDIRS) -rdynamic $(OPTZ) $(DEBUG)
LIBS=-Wl,-Bstatic -lmariadbclient -ldaemon -lcrypto -Wl,-Bdynamic -lssl -ldl -lpthread -lm -lz $(GLIB_LIB)
SQLITEOBJ=../sqlite3/sqlite3.o
EXECUTABLE=proxysql

_OBJ = tokenizer.o utils.o l_utils.o mysql_session.o mysql_data_stream.o mysql_backend.o main.o debug.o fundadb_hash.o global_variables.o mysql_connpool.o mysql_protocol.o mysql_handler.o network.o threads.o admin.o admin_sqlite.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) -Wall


proxysql: $(ODIR) $(OBJ) $(SQLITEOBJ) $(MARIADBAR) $(DAEMONAR)
	gcc -o $@ $(MARIADBAR) $(DAEMONAR) $(SQLITEOBJ) $(OBJ) $(CFLAGS) $(LDIRS) $(LIBS)

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
