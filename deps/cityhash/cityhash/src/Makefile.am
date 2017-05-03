# library
lib_LTLIBRARIES = libcityhash.la
libcityhash_la_SOURCES = city.cc
if SSE42
include_HEADERS = city.h citycrc.h
else
include_HEADERS = city.h
endif

# test
cityhash_unittest_SOURCES = city-test.cc
cityhash_unittest_LDADD = libcityhash.la
TESTS = cityhash_unittest
noinst_PROGRAMS = $(TESTS)
