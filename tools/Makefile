#!/bin/make -f


PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk


IDIRS := -I$(JSON_IDIR)


eventslog_reader_sample: eventslog_reader_sample.cpp
	$(CXX) -ggdb -o eventslog_reader_sample eventslog_reader_sample.cpp

# Build target for eventlog_reader_to_json
eventlog_reader_to_json: eventlog_reader_to_json.cpp
	$(CXX) -std=c++17 -ggdb -o $@ $<  $(IDIRS)


bench_connect: bench_connect.c
	$(CC) -O2 -o $@ $< -I$(POSTGRESQL_IDIR) -L$(POSTGRESQL_PATH)/interfaces/libpq -L$(POSTGRESQL_PATH)/common -L$(POSTGRESQL_PATH)/port -lpq -lpgcommon -lpgport -lm -lpthread

.PHONY: clean
clean:
	rm -f eventlog_reader_to_json eventslog_reader_sample bench_connect
