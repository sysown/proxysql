.PHONY: all
all: deprecate_eof_support

.PHONY: clean
clean:
	cd deprecate_eof_support && ${MAKE} clean

.PHONY: debug
debug: deprecate_eof_support

.PHONY: deprecate_eof_support
deprecate_eof_support:
	cd deprecate_eof_support && CC=${CC} CXX=${CXX} ${MAKE} $(MAKECMDGOALS)
