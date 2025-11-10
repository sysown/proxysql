CUSTOM_OPENSSL_PATH ?=

OPENSSL_PACKAGE := openssl

ifeq ($(DISTRO),almalinux)
ifeq ($(CENTOSVER),8)
    OPENSSL_PACKAGE := openssl3
endif
endif

$(info OPENSSL_PACKAGE: $(OPENSSL_PACKAGE))

# Use pkg-config to get the compiler and linker flags for OpenSSL if CUSTOM_OPENSSL_PATH is not set
ifeq ($(CUSTOM_OPENSSL_PATH),)
    $(info No custom path specified.)
    ifeq ($(OPENSSL_PACKAGE),openssl3)
        SSL_IDIR := $(shell pkg-config --cflags $(OPENSSL_PACKAGE) | sed -n 's/.*-I\([^ ]*\).*/\1/p')
        SSL_LDIR := $(shell pkg-config --variable=libdir $(OPENSSL_PACKAGE))
        LIB_SSL_PATH := $(shell find $(SSL_LDIR) -name "libssl.so.3" 2>/dev/null | head -n 1)
        LIB_CRYPTO_PATH := $(shell find $(SSL_LDIR) -name "libcrypto.so.3" 2>/dev/null | head -n 1)
    else
        SSL_IDIR := $(shell export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1; export PKG_CONFIG_ALLOW_SYSTEM_LIBS=1; pkg-config --cflags $(OPENSSL_PACKAGE) | sed 's/-I//g')
        SSL_LDIR := $(shell pkg-config --variable=libdir $(OPENSSL_PACKAGE))
        LIB_SSL_PATH := $(shell find $(SSL_LDIR) -name "libssl.so" 2>/dev/null | head -n 1)
        LIB_CRYPTO_PATH := $(shell find $(SSL_LDIR) -name "libcrypto.so" 2>/dev/null | head -n 1)
    endif
else
    SSL_IDIR := $(CUSTOM_OPENSSL_PATH)/include
    SSL_LDIR := $(CUSTOM_OPENSSL_PATH)/lib64
    LIB_SSL_PATH := $(shell find $(SSL_LDIR) -name "libssl.so" 2>/dev/null | head -n 1)
    LIB_CRYPTO_PATH := $(shell find $(SSL_LDIR) -name "libcrypto.so" 2>/dev/null | head -n 1)	
    $(info Using custom OpenSSL path: $(CUSTOM_OPENSSL_PATH))
endif

# Check if required flags are set and provide feedback
ifneq ($(SSL_IDIR),)
ifneq ($(SSL_LDIR),)
    $(info SSL_IDIR: $(SSL_IDIR))
    $(info SSL_LDIR: $(SSL_LDIR))
    $(info LIB_SSL_PATH: $(LIB_SSL_PATH))
    $(info LIB_CRYPTO_PATH: $(LIB_CRYPTO_PATH))
else
    $(error Warning: OpenSSL libraries directory (SSL_LDIR) not found. Exiting. Please ensure the correct path is set or install OpenSSL version 3.)
endif
else
    $(error Warning: OpenSSL headers (SSL_IDIR) not found. Exiting. Please install OpenSSL version 3.)
endif
