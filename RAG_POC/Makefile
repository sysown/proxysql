CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2

ROOT_DIR := ..

INCLUDES := \
	-I$(ROOT_DIR)/deps/json \
	-I$(ROOT_DIR)/deps/mariadb-client-library/mariadb_client/include \
	-I$(ROOT_DIR)/deps/sqlite3/sqlite-amalgamation-3500400

LIBDIRS := \
	-L$(ROOT_DIR)/deps/mariadb-client-library/mariadb_client/libmariadb

SQLITE3_OBJ := $(ROOT_DIR)/deps/sqlite3/sqlite-amalgamation-3500400/sqlite3.o

LIBS := -lmariadbclient -lssl -lcrypto -lcrypt -ldl -lpthread

TARGET := rag_ingest
SOURCES := rag_ingest.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(LIBDIRS) $(SQLITE3_OBJ) $^ -o $@ $(LIBS)

clean:
	rm -f $(TARGET)
