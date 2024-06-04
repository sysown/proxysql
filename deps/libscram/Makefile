CC ?= gcc
CFLAGS_common = -Wall -Iinclude
CFLAGS_DEBUG = -g -O0
CFLAGS_RELEASE = -O3
SRC_DIR = src
OBJ_DIR_DEBUG = obj/debug
OBJ_DIR_RELEASE = obj/release
LIB_DIR = lib
TARGET_DEBUG = $(LIB_DIR)/libscram.a
TARGET_RELEASE = $(LIB_DIR)/libscram.a

# Library directory passed as a parameter
LIBUSUAL_DIR ?= /path/to/libusual

# OpenSSL dir
LIBOPENSSL_DIR ?= /path/to/openssl

# PostgreSQL dir
POSTGRESQL_DIR ?= /path/to/postgresql
POSTGRESQL_INCLUDE_DIR = $(POSTGRESQL_DIR)/src/include/

# List all source files
SRC_FILES := $(wildcard $(SRC_DIR)/*.c)

# Generate object file names
OBJ_FILES_DEBUG := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR_DEBUG)/%.o,$(SRC_FILES))
OBJ_FILES_RELEASE := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR_RELEASE)/%.o,$(SRC_FILES))

# Check if ASAN is enabled
ifdef ASAN
CFLAGS_DEBUG += -fsanitize=address
endif

# Define default target
all: $(TARGET_RELEASE)

DEBUG: $(TARGET_DEBUG)

RELEASE: $(TARGET_RELEASE)

$(OBJ_DIR_DEBUG)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_common) $(CFLAGS_DEBUG) -I$(LIBUSUAL_DIR) -I$(LIBOPENSSL_DIR) -I$(POSTGRESQL_INCLUDE_DIR) -c $< -o $@

$(OBJ_DIR_RELEASE)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_common) $(CFLAGS_RELEASE) -I$(LIBUSUAL_DIR) -I$(LIBOPENSSL_DIR) -I$(POSTGRESQL_INCLUDE_DIR) -c $< -o $@

$(TARGET_DEBUG): $(OBJ_FILES_DEBUG)
	@mkdir -p $(@D)
	ar rcs $@ $^

$(TARGET_RELEASE): $(OBJ_FILES_RELEASE)
	@mkdir -p $(@D)
	ar rcs $@ $^

clean:
	rm -rf $(OBJ_DIR_DEBUG)/* $(OBJ_DIR_RELEASE)/* $(LIB_DIR)/*

.PHONY: all DEBUG RELEASE clean
