INCLUDE=../../../deps/json

.PHONY: all
all: libtap.a

.PHONY: clean
clean:
	rm -f *.o libtap.a || true

OPT=-O2

libtap.a: tap.cpp tap.h command_line.cpp command_line.h
	g++ -c tap.cpp command_line.cpp  -std=c++11 -I$(INCLUDE) $(OPT)
	ar rcs libtap.a tap.o command_line.o

