#!/bin/make -f


.DEFAULT: all
.PHONY: all
all: tap test_deps
	${MAKE} tests
	${MAKE} tests_with_deps

.PHONY: debug
debug: tap test_deps
	${MAKE} tests
	${MAKE} tests_with_deps


.PHONY: test_deps
test_deps:
	cd ../deps && CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: tap
tap:
	cd tap && CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: tests
tests:
	cd tests && CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: tests_with_deps
tests_with_deps:
	cd tests_with_deps && CC=${CC} CXX=${CXX} ${MAKE}


.PHONY: clean
.SILENT: clean
clean:
	cd ../deps && ${MAKE} -s clean
	cd tap && ${MAKE} -s clean
	cd tests && ${MAKE} -s clean
	cd tests_with_deps && ${MAKE} -s clean
