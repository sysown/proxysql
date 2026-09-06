#!/bin/make -f

PROXYSQL_PATH := $(abspath ../..)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk

test_rag_schema: test_rag_schema.cpp $(PROXYSQL_LDIR)/obj/sha256crypt.oo $(OPENSSL_STATIC_LIBS)
	$(CXX) -ggdb test_rag_schema.cpp $(SQLITE3_LDIR)/libsqlite3$(SHLIB_EXT) \
		$(PROXYSQL_LDIR)/obj/sha256crypt.oo -o test_rag_schema \
		-I$(SQLITE3_IDIR) $(OPENSSL_STATIC_LIBS)

clean:
	rm -f test_rag_schema

.PHONY: clean
