OPENSSL_VERSION := 3.5.7

DEPS_PATH ?= $(PROXYSQL_PATH)/deps
SSL_PATH := $(DEPS_PATH)/libssl/openssl
SSL_IDIR := $(SSL_PATH)/include
SSL_LDIR := $(SSL_PATH)
LIB_SSL_PATH := $(SSL_LDIR)/libssl.a
LIB_CRYPTO_PATH := $(SSL_LDIR)/libcrypto.a
OPENSSL_STATIC_LIBS := $(LIB_SSL_PATH) $(LIB_CRYPTO_PATH)

ifeq ($(UNAME_S),Darwin)
OPENSSL_EXPORT_LIBS := -Wl,-force_load,$(LIB_SSL_PATH) \
	-Wl,-force_load,$(LIB_CRYPTO_PATH)
else
OPENSSL_EXPORT_LIBS := -Wl,--whole-archive $(OPENSSL_STATIC_LIBS) \
	-Wl,--no-whole-archive
endif
