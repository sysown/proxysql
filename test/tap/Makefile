.PHONY: all
all: tap tests

.PHONY: clean
clean:
	cd tap && ${MAKE} clean
	cd tests && ${MAKE} clean

debug: tap tests

.PHONY: tap
tap: 
	cd tap && CC=${CC} CXX=${CXX} ${MAKE} $(MAKECMDGOALS)

tests: tap
	cd tests && CC=${CC} CXX=${CXX} ${MAKE} $(MAKECMDGOALS)

