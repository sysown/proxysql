O0=-O0
O2=-O2
O1=-O1
O3=-O3 -mtune=native
#OPTZ=$(O2)
EXTRALINK=#-pg
ALL_DEBUG=-ggdb -DDEBUG
NO_DEBUG=
DEBUG=${ALL_DEBUG}
#export DEBUG
#export OPTZ
export EXTRALINK

all:
	OPTZ="${O2}" make default

.PHONY: default
default:
	make deps
	make lib
	make src

.PHONY: debug
debug:
	OPTZ="${O0}" DEBUG="${ALL_DEBUG}" make default

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
