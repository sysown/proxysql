
AR=ar r
CC=cc
LD=ld
LDSHARED=ld -shared
CFLAGS=-Wall -Werror -ansi -g -O3 -fPIC

# MAC
#AR=libtool -static

INSTALL=install
PREFIX=/usr/local
INCLUDE_DIR=${PREFIX}/include
LIB_DIR=${PREFIX}/lib

LIBNAME=injection
STATICLIB_SUFFIX=a
STATICLIB=lib${LIBNAME}.${STATICLIB_SUFFIX}

SHAREDLIB_SUFFIX=so
SHAREDLIB=lib${LIBNAME}.${SHAREDLIB_SUFFIX}

HEADERS=libinjection.h libinjection_sqli.h libinjection_sqli_data.h libinjection_html5.h libinjection_xss.h

SOURCES=libinjection_sqli.c \
	libinjection_html5.c \
	libinjection_xss.c

OBJECTS=libinjection_sqli.o \
	libinjection_html5.o \
	libinjection_xss.o

SAMPLES=html5 sqli fptool
TESTDRIVERS=reader testdriver testspeedxss testspeedsqli

#all: ${SHAREDLIB} ${STATICLIB}
all: ${STATICLIB}

samples: ${SAMPLES}
.PHONY: samples

sqlparse_data.json: sqlparse_map.py fingerprints.txt
	./sqlparse_map.py > sqlparse_data.json

libinjection_sqli_data.h: sqlparse2c.py sqlparse_data.json
	./sqlparse2c.py < sqlparse_data.json > libinjection_sqli_data.h

libinjection_sqli.o: libinjection.h libinjection_sqli.c libinjection_sqli.h libinjection_sqli_data.h
	${CC} ${CFLAGS} -c -o libinjection_sqli.o libinjection_sqli.c

libinjection_xss.o: libinjection.h libinjection_xss.c libinjection_xss.h libinjection_html5.h
	${CC} ${CFLAGS} -c -o libinjection_xss.o libinjection_xss.c

libinjection_html5.o: libinjection.h libinjection_html5.c libinjection_html5.h
	${CC} ${CFLAGS} -c -o libinjection_html5.o libinjection_html5.c

${SHAREDLIB}: ${OBJECTS}
	${LD} -shared -o ${SHAREDLIB} ${OBJECTS} -lc

${STATICLIB}: ${OBJECTS}
	rm -f ${STATICLIB}
	${AR} ${STATICLIB} ${OBJECTS}

check: ${TESTDRIVERS}
	@./test-driver.sh test-unit.sh
	@./test-driver.sh test-samples-sqli-negative.sh
	@./test-driver.sh test-samples-sqli-positive.sh
	@./test-driver.sh test-samples-xss-positive.sh
	@./test-driver.sh test-speed-xss.sh
	@./test-driver.sh test-speed-sqli.sh

test: check
.PHONY: check test

reader: reader.c ${STATICLIB}
	${CC} ${CFLAGS} -o reader reader.c -L. ${STATICLIB}

sqli: sqli_cli.c ${STATICLIB}
	${CC} ${CFLAGS} -o sqli sqli_cli.c -L. ${STATICLIB}

html5: html5_cli.c ${STATICLIB}
	${CC} ${CFLAGS} -o html5 html5_cli.c -L. ${STATICLIB}

testdriver: testdriver.c ${STATICLIB}
	${CC} ${CFLAGS} -o testdriver testdriver.c -L. ${STATICLIB}

testspeedsqli: test_speed_sqli.c ${STATICLIB}
	${CC} ${CFLAGS} -o testspeedsqli test_speed_sqli.c -L. ${STATICLIB}

testspeedxss: test_speed_xss.c ${STATICLIB}
	${CC} ${CFLAGS} -o testspeedxss test_speed_xss.c -L. ${STATICLIB}

fptool: fptool.c ${STATICLIB}
	${CC} ${CFLAGS} -o fptool fptool.c -L. ${STATICLIB}

install: ${STATICLIB}
	${INSTALL} -d ${INCLUDE_DIR}
	${INSTALL} -c ${HEADERS} ${INCLUDE_DIR}
	${INSTALL} -d ${LIB_DIR}
	${INSTALL} -c ${STATICLIB} ${LIB_DIR}

.PHONY: install

clean:
	rm -f *.so *.a *.o *.dylib *.lo
	rm -f *~
	rm -f *.log
	rm -f ${SAMPLES} ${TESTDRIVERS}
	rm -f *.gcno
	rm -rf *.dSYM
