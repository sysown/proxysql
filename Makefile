ALL_DEBUG=-ggdb -DDEBUG
NO_DEBUG=
DEBUG=${ALL_DEBUG}
O0=-O0
O2=-O2
O1=-O1
O3=-O3 -mtune=native
OPTZ=$(O0)
EXTRALINK=-pg
export DEBUG
export OPTZ
export EXTRALINK

default: deps lib src
.PHONY: default

.PHONY: deps
deps:
	cd deps && make

.PHONY: lib
lib:
	cd lib && make -j 5

.PHONY: src
src:
	cd src && make

.PHONY: clean
clean:
	cd lib && make clean
	cd src && make clean

.PHONY: cleanall
cleanall:
	cd deps && make cleanall
	cd lib && make clean
	cd src && make clean
