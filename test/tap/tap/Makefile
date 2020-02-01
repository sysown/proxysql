DEPS_PATH=../../../deps

JSON_IDIR=$(DEPS_PATH)/json
MARIADB_PATH=$(DEPS_PATH)/mariadb-client-library/mariadb_client
MARIADB_IDIR=$(MARIADB_PATH)/include
MARIADB_LDIR=$(MARIADB_PATH)/libmariadb

.PHONY: all
all: libtap.a

.PHONY: clean
clean:
	rm -f *.o libtap.a || true

OPT=-O2

libtap.a: tap.cpp tap.h command_line.cpp command_line.h utils.cpp utils.h
	g++ -c tap.cpp command_line.cpp utils.cpp -std=c++11 -I$(JSON_IDIR) -I$(MARIADB_IDIR) $(OPT)
	ar rcs libtap.a tap.o command_line.o utils.o

