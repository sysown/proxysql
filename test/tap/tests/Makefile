DEPS_PATH=../../../deps

MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include
MARIADB_LDIR=$(MARIADB_PATH)/libmariadb

INCLUDEDIR=../tap
LIBDIR=../tap

STATIC_LIBS=$(MARIADB_LDIR)/libmariadbclient.a

.PHONY: all
all: tests

.PHONY: clean
clean:
	rm -f basic-t set_character_set-t charset_unsigned_int-t || true

OPT=-O2

SRC=basic-t.cpp set_character_set-t.cpp charset_unsigned_int-t.cpp

tests: basic-t set_character_set-t charset_unsigned_int-t

basic-t: $(LIBDIR)/libtap.a
	g++ basic-t.cpp -I$(INCLUDEDIR) -L$(LIBDIR) -std=c++11 -ltap -o basic-t

set_character_set-t: set_character_set-t.cpp $(LIBDIR)/libtap.a
	g++ set_character_set-t.cpp -I$(INCLUDEDIR) -I$(MARIADB_IDIR) -L$(LIBDIR) -std=c++11 $(STATIC_LIBS) -ltap -lssl -lcrypto -ldl -lpthread -o set_character_set-t

charset_unsigned_int-t: charset_unsigned_int-t.cpp $(LIBDIR)/libtap.a
	g++ charset_unsigned_int-t.cpp -I$(INCLUDEDIR) -I$(MARIADB_IDIR) -L$(LIBDIR) -std=c++11 $(STATIC_LIBS) -ltap -lssl -lcrypto -ldl -lpthread -o charset_unsigned_int-t

