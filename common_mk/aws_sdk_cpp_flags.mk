AWS_SDK_CPP_VERSION := 1.11.869
AWS_SDK_CPP_BUNDLE_DIR := $(PROXYSQL_PATH)/deps/aws-sdk-cpp
AWS_SDK_CPP_ARCHIVE := aws-sdk-cpp/aws-sdk-cpp-$(AWS_SDK_CPP_VERSION)-with-crt.tar.xz
AWS_SDK_CPP_ARCHIVE_PATH := $(PROXYSQL_PATH)/deps/$(AWS_SDK_CPP_ARCHIVE)
AWS_SDK_CPP_SOURCE_DIR := $(AWS_SDK_CPP_BUNDLE_DIR)/aws-sdk-cpp-$(AWS_SDK_CPP_VERSION)
AWS_SDK_CPP_INSTALL_DIR := $(PROXYSQL_PATH)/deps/aws-sdk-cpp/aws-sdk-cpp-$(AWS_SDK_CPP_VERSION)/install
AWS_SDK_CPP_IDENTITY_DIR := $(AWS_SDK_CPP_BUNDLE_DIR)/.build-identities

ifeq ($(PROXYSQL40),1)
AWS_SDK_CPP_SHARED := 0
AWS_SDK_CPP_LIB_DIR := $(AWS_SDK_CPP_INSTALL_DIR)/lib
AWS_SDK_CPP_CPPFLAGS := -I$(AWS_SDK_CPP_INSTALL_DIR)/include
AWS_SDK_CPP_CURL_INCLUDE_DIR := $(PROXYSQL_PATH)/deps/curl/curl/include
AWS_SDK_CPP_CURL_TARGET := curl/curl/lib/.libs/libcurl.a
AWS_SDK_CPP_CURL_LIB := $(PROXYSQL_PATH)/deps/curl/curl/lib/.libs/libcurl.a
AWS_SDK_CPP_CORE_LIB := $(AWS_SDK_CPP_LIB_DIR)/libaws-cpp-sdk-core.a
AWS_SDK_CPP_RDS_LIB := $(AWS_SDK_CPP_LIB_DIR)/libaws-cpp-sdk-rds.a
AWS_SDK_CPP_COMPILER_ID := $(shell { printf '%s\n' 'CC=$(CC)' 'CXX=$(CXX)'; $(CC) --version; $(CXX) --version; cmake --version; uname -srm; } 2>/dev/null | cksum | awk '{print $$1 "-" $$2}')
AWS_SDK_CPP_INPUT_ID := $(shell { sed -n '1p' "$(AWS_SDK_CPP_BUNDLE_DIR)/aws-sdk-cpp-$(AWS_SDK_CPP_VERSION)-with-crt.sha256"; cksum "$(AWS_SDK_CPP_BUNDLE_DIR)/aws-sdk-cpp-$(AWS_SDK_CPP_VERSION)-sources.json"; cksum "$(AWS_SDK_CPP_BUNDLE_DIR)/build-sdk.cmake"; printf '%s\n' '$(AWS_SDK_CPP_COMPILER_ID)' '$(SSL_IDIR)' '$(SSL_LDIR)' '$(LIB_SSL_PATH)' '$(LIB_CRYPTO_PATH)' 'RelWithDebInfo;static;PIC;core;rds;BUILD_DEPS;UNITY;NO_SUBMODULE_CHECK'; } 2>/dev/null | cksum | awk '{print $$1 "-" $$2}')
AWS_SDK_CPP_IDENTITY_STAMP := $(AWS_SDK_CPP_IDENTITY_DIR)/$(AWS_SDK_CPP_INPUT_ID)
AWS_SDK_CPP_BUILD_DIR := $(AWS_SDK_CPP_SOURCE_DIR)/build-$(AWS_SDK_CPP_INPUT_ID)
AWS_SDK_CPP_STATIC_ARCHIVES := \
	$(AWS_SDK_CPP_LIB_DIR)/libaws-cpp-sdk-rds.a \
	$(AWS_SDK_CPP_LIB_DIR)/libaws-cpp-sdk-core.a \
	$(AWS_SDK_CPP_LIB_DIR)/libaws-crt-cpp.a \
	$(AWS_SDK_CPP_LIB_DIR)/libaws-c-s3.a \
	$(AWS_SDK_CPP_LIB_DIR)/libaws-c-auth.a \
	$(AWS_SDK_CPP_LIB_DIR)/libaws-c-mqtt.a \
	$(AWS_SDK_CPP_LIB_DIR)/libaws-c-http.a \
	$(AWS_SDK_CPP_LIB_DIR)/libaws-c-event-stream.a \
	$(AWS_SDK_CPP_LIB_DIR)/libaws-c-compression.a \
	$(AWS_SDK_CPP_LIB_DIR)/libaws-c-io.a \
	$(AWS_SDK_CPP_LIB_DIR)/libaws-c-cal.a \
	$(AWS_SDK_CPP_LIB_DIR)/libaws-c-sdkutils.a \
	$(AWS_SDK_CPP_LIB_DIR)/libaws-checksums.a \
	$(AWS_SDK_CPP_LIB_DIR)/libaws-c-common.a \
	$(AWS_SDK_CPP_LIB_DIR)/libs2n.a
endif
