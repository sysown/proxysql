.PHONY: all
all: deps build_internal_tap_tests

.PHONY: clean
clean:
	cd deps && ${MAKE} clean
	cd internal_tap_tests && ${MAKE} clean

.PHONY: deps
deps:
	cd deps && CC=${CC} CXX=${CXX} $(MAKE)

build_internal_tap_tests: deps
	cd internal_tap_tests && CC=${CC} CXX=${CXX} ${MAKE}

build_internal_tap_tests_debug: deps
	cd internal_tap_tests && CC=${CC} CXX=${CXX} ${MAKE} debug

