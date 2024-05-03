#!/bin/make -f


.DEFAULT: all
.PHONY: all
all: tests tests_with_deps

.PHONY: debug
debug: tests tests_with_deps

.PHONY: test_deps
test_deps:
	cd ../deps && CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: tap
tap: test_deps
	cd tap && CC=${CC} CXX=${CXX} ${MAKE}

.PHONY: tests
tests: tap test_deps
	cd tests && CC=${CC} CXX=${CXX} ${MAKE} $(MAKECMDGOALS)

.PHONY: tests_with_deps
tests_with_deps: tap test_deps
	cd tests_with_deps && CC=${CC} CXX=${CXX} ${MAKE} $(MAKECMDGOALS)


.PHONY: clean_utils
.SILENT: clean_utils
clean_utils:
	cd tap && ${MAKE} -s clean_utils

.PHONY: clean
.SILENT: clean
clean:
	cd tap && ${MAKE} -s clean
	cd tests && ${MAKE} -s clean
	cd tests_with_deps && ${MAKE} -s clean

.PHONY: cleanall
.SILENT: cleanall
cleanall:
	cd ../deps && ${MAKE} -s clean
	cd tap && ${MAKE} -s clean
	cd tests && ${MAKE} -s clean
	cd tests_with_deps && ${MAKE} -s clean
