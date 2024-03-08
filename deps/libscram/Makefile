CC ?= gcc
CFLAGS_common = -Wall -Iinclude -Iinclude/common
CFLAGS_DEBUG = -g -O0
CFLAGS_RELEASE = -O3
SRC_DIR = src
COMMON_SRC_DIR = src/common
OBJ_DIR_DEBUG = obj/debug
OBJ_DIR_RELEASE = obj/release
LIB_DIR = lib
TARGET_DEBUG = $(LIB_DIR)/libscram.a
TARGET_RELEASE = $(LIB_DIR)/libscram.a

# Library directory passed as a parameter
LIBUSUAL_DIR ?= /path/to/libusual

# OpenSSL dir
LIBOPENSSL_DIR ?= /path/to/openssl

# List all source files
SRC_FILES := $(wildcard $(SRC_DIR)/*.c)
COMMON_SRC_FILES := $(wildcard $(COMMON_SRC_DIR)/*.c)

# Generate object file names
OBJ_FILES_DEBUG := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR_DEBUG)/%.o,$(SRC_FILES))
COMMON_OBJ_FILES_DEBUG := $(patsubst $(COMMON_SRC_DIR)/%.c,$(OBJ_DIR_DEBUG)/%.o,$(COMMON_SRC_FILES))
OBJ_FILES_RELEASE := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR_RELEASE)/%.o,$(SRC_FILES))
COMMON_OBJ_FILES_RELEASE := $(patsubst $(COMMON_SRC_DIR)/%.c,$(OBJ_DIR_RELEASE)/%.o,$(COMMON_SRC_FILES))

# Define default target
all: $(TARGET_DEBUG)

DEBUG: $(TARGET_DEBUG)

RELEASE: $(TARGET_RELEASE)

$(OBJ_DIR_DEBUG)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_common) $(CFLAGS_DEBUG) -I$(LIBUSUAL_DIR) -I$(LIBOPENSSL_DIR) -c $< -o $@

$(OBJ_DIR_DEBUG)/%.o: $(COMMON_SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_common) $(CFLAGS_DEBUG) -I$(LIBUSUAL_DIR) -I$(LIBOPENSSL_DIR) -c $< -o $@

$(OBJ_DIR_RELEASE)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_common) $(CFLAGS_RELEASE) -I$(LIBUSUAL_DIR) -I$(LIBOPENSSL_DIR) -c $< -o $@

$(OBJ_DIR_RELEASE)/%.o: $(COMMON_SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS_common) $(CFLAGS_RELEASE) -I$(LIBUSUAL_DIR) -I$(LIBOPENSSL_DIR) -c $< -o $@

$(TARGET_DEBUG): $(OBJ_FILES_DEBUG) $(COMMON_OBJ_FILES_DEBUG)
	@mkdir -p $(@D)
	ar rcs $@ $^

$(TARGET_RELEASE): $(OBJ_FILES_RELEASE) $(COMMON_OBJ_FILES_RELEASE)
	@mkdir -p $(@D)
	ar rcs $@ $^

clean:
	rm -rf $(OBJ_DIR_DEBUG)/* $(OBJ_DIR_RELEASE)/* $(LIB_DIR)/*

.PHONY: all DEBUG RELEASE clean
