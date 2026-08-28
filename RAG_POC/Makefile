CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2

ROOT_DIR := ..

INCLUDES := \
	-I$(ROOT_DIR)/deps/json \
	-I$(ROOT_DIR)/deps/mariadb-client-library/mariadb_client/include \
	-I$(ROOT_DIR)/deps/curl/curl/include

LIBDIRS := \
	-L$(ROOT_DIR)/deps/mariadb-client-library/mariadb_client/libmariadb

# Use static libcurl
CURL_STATIC_LIB := $(ROOT_DIR)/deps/curl/curl/lib/.libs/libcurl.a

LIBS := -lmariadbclient -lssl -lcrypto -lcrypt -ldl -lpthread $(CURL_STATIC_LIB) -lz

TARGET := rag_ingest
SOURCES := rag_ingest.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(LIBDIRS) $^ -o $@ $(LIBS)

clean:
	rm -f $(TARGET)
