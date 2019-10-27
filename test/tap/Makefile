
.PHONY: all
all: tap tests

.PHONY: clean
clean:
	cd tap && ${MAKE} clean
	cd tests && ${MAKE} clean

OPT=-O2

.PHONY: tap
tap: 
	cd tap && OPTZ="${O0} -ggdb " CC=${CC} CXX=${CXX} ${MAKE}

tests: tap
	cd tests && OPTZ="${O0} -ggdb " CC=${CC} CXX=${CXX} ${MAKE}


