OPENSSL_VERSION := 3.5.7

DEPS_PATH ?= $(PROXYSQL_PATH)/deps
SSL_PATH := $(DEPS_PATH)/libssl/openssl
SSL_IDIR := $(SSL_PATH)/include
SSL_LDIR := $(SSL_PATH)
LIB_SSL_PATH := $(SSL_LDIR)/libssl.a
LIB_CRYPTO_PATH := $(SSL_LDIR)/libcrypto.a
OPENSSL_STATIC_LIBS := $(LIB_SSL_PATH) $(LIB_CRYPTO_PATH)

ifeq ($(UNAME_S),Darwin)
EXECUTABLE_EXPORT_FLAGS := -Wl,-export_dynamic
force_load_archives = $(foreach archive,$(1),-Wl,-force_load,$(archive))
else
EXECUTABLE_EXPORT_FLAGS := -Wl,--export-dynamic
force_load_archives = -Wl,--whole-archive $(1) -Wl,--no-whole-archive
endif

OPENSSL_FORCE_LOAD_LIBS := $(call force_load_archives,$(OPENSSL_STATIC_LIBS))
