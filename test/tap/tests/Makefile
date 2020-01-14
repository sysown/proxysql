DEPS_PATH=../../../deps

MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include
MARIADB_LDIR=$(MARIADB_PATH)/libmariadb

INCLUDEDIR=../tap
LIBDIR=../tap

PROXYSQL_PATH=../../..
PROXYSQL_IDIR=$(PROXYSQL_PATH)/include

SQLITE3_DIR=$(DEPS_PATH)/sqlite3/sqlite3

STATIC_LIBS=$(MARIADB_LDIR)/libmariadbclient.a

.PHONY: all
all: tests

.PHONY: clean
clean:
	rm -f basic-t set_character_set-t charset_unsigned_int-t select_config_file-t sqlite3-t || true

OPT=-O2

SRC=basic-t.cpp set_character_set-t.cpp charset_unsigned_int-t.cpp select_config_file-t.cpp sqlite3-t.cpp

tests: basic-t set_character_set-t charset_unsigned_int-t select_config_file-t sqlite3-t

sqlite3-t: $(LIBDIR)/libtap.a sqlite3-t.cpp
	g++ sqlite3-t.cpp -I$(INCLUDEDIR) -I$(PROXYSQL_IDIR) -I$(MARIADB_IDIR) -I$(SQLITE3_DIR) -L$(LIBDIR) $(OPT) ../../../lib/libproxysql.a -lpthread -ldl -std=c++11 -ltap -o sqlite3-t

basic-t: $(LIBDIR)/libtap.a
	g++ basic-t.cpp -I$(INCLUDEDIR) -L$(LIBDIR) $(OPT) -std=c++11 -ltap -o basic-t

set_character_set-t: set_character_set-t.cpp $(LIBDIR)/libtap.a
	g++ set_character_set-t.cpp -I$(INCLUDEDIR) -I$(MARIADB_IDIR) -L$(LIBDIR) $(OPT) -std=c++11 $(STATIC_LIBS) -ltap -lssl -lcrypto -ldl -lpthread -o set_character_set-t

charset_unsigned_int-t: charset_unsigned_int-t.cpp $(LIBDIR)/libtap.a
	g++ charset_unsigned_int-t.cpp -I$(INCLUDEDIR) -I$(MARIADB_IDIR) -L$(LIBDIR) $(OPT) -std=c++11 $(STATIC_LIBS) -ltap -lssl -lcrypto -ldl -lpthread -o charset_unsigned_int-t

select_config_file-t: select_config_file-t.cpp $(LIBDIR)/libtap.a
	g++ select_config_file-t.cpp -I$(INCLUDEDIR) -L$(LIBDIR) -std=c++11 `mysql_config --include --libs` -lmysqlclient -ltap -o select_config_file-t

