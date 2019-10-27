INCLUDEDIR=../tap
LIBDIR=../tap

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
	g++ set_character_set-t.cpp -I$(INCLUDEDIR) -L$(LIBDIR) -std=c++11 `mysql_config --include --libs` -lmysqlclient -ltap -o set_character_set-t

charset_unsigned_int-t: charset_unsigned_int-t.cpp $(LIBDIR)/libtap.a
	g++ charset_unsigned_int-t.cpp -I$(INCLUDEDIR) -L$(LIBDIR) -std=c++11 `mysql_config --include --libs` -lmysqlclient -ltap -o charset_unsigned_int-t

