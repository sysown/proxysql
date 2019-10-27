INCLUDE=../../../deps/json

.PHONY: all
all: tap

.PHONY: clean
clean:
	rm *.o libtap.a


OPT=-O2

tap: tap.cpp tap.h command_line.cpp command_line.h
	g++ -c tap.cpp command_line.cpp  -std=c++11 -I$(INCLUDE)
	ar rcs libtap.a tap.o command_line.o


