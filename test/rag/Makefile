#!/bin/make -f

test_rag_schema: test_rag_schema.cpp
	g++ -ggdb test_rag_schema.cpp ../../deps/sqlite3/sqlite3/libsqlite3.so  -o test_rag_schema -I../../deps/sqlite3/sqlite3 -lssl -lcrypto

clean:
	rm -f test_rag_schema

.PHONY: clean
