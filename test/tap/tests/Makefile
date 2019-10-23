INCLUDEDIR=../tap
LIBDIR=../tap

.PHONY: all
all: tests

.PHONY: clean
clean:
	rm basic-t set_character_set-t

OPT=-O2

SRC=basic-t.cpp set_character_set-t.cpp

tests: basic-t set_character_set-t

basic-t: $(LIBDIR)/libtap.a
	g++ basic-t.cpp -I$(INCLUDEDIR) -L$(LIBDIR) -std=c++11 -ltap -o basic-t

set_character_set-t: set_character_set-t.cpp set_character_set-t.cpp $(LIBDIR)/libtap.a
	g++ set_character_set-t.cpp -I$(INCLUDEDIR) -L$(LIBDIR) -std=c++11 `mysql_config --include --libs` -lmysqlclient -ltap -o set_character_set-t


