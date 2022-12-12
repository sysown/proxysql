.PHONY: all
all: tap tests tests_with_deps

.PHONY: clean
clean:
	cd tap && ${MAKE} clean
	cd tests && ${MAKE} clean
	cd tests_with_deps && ${MAKE} clean

debug: tap tests tests_with_deps

.PHONY: tap
tap: 
	cd tap && CC=${CC} CXX=${CXX} ${MAKE} $(MAKECMDGOALS)

tests: tap
	cd tests && CC=${CC} CXX=${CXX} ${MAKE} $(MAKECMDGOALS)

tests_with_deps: tap tests
	cd tests_with_deps && CC=${CC} CXX=${CXX} ${MAKE} $(MAKECMDGOALS)
