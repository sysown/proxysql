#!/bin/make -f

PROXYSQL_PATH := $(shell while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)

include $(PROXYSQL_PATH)/include/makefiles_vars.mk
include $(PROXYSQL_PATH)/include/makefiles_paths.mk
include $(PROXYSQL_PATH)/common_mk/aws_sdk_cpp_flags.mk

ifneq ($(filter clean,$(MAKECMDGOALS)),clean)
ifneq ($(PROXYSQL40),1)
$(error plugins/aws requires PROXYSQL40=1)
endif
endif

PLUGIN_DIR := $(PROXYSQL_PATH)/plugins/aws
ODIR := $(PLUGIN_DIR)/obj
PLUGIN_SO := $(PLUGIN_DIR)/ProxySQL_Aws_Plugin.so
.DEFAULT_GOAL := all

IDIRS := -I$(PROXYSQL_IDIR) -I$(PROMETHEUS_IDIR) -I$(SSL_IDIR) $(AWS_SDK_CPP_CPPFLAGS)

OPTZ ?= -O2 -ggdb
CXXFLAGS := $(STDCPP) -fPIC -fvisibility=hidden -fvisibility-inlines-hidden \
	$(OPTZ) $(WGCOV) $(WASAN) -pthread -DPROXYSQL40 -fstack-protector-strong

SRCS := $(PLUGIN_DIR)/src/aws_plugin.cpp
OBJS := $(ODIR)/aws_plugin.o $(ODIR)/Aws_Iam_Token_Manager.o
HEADERS := $(PROXYSQL_PATH)/include/Aws_Iam_Sdk.h \
	$(PROXYSQL_PATH)/include/Aws_Iam_Token_Manager.h \
	$(PROXYSQL_PATH)/include/ProxySQL_Plugin.h

PLUGIN_LDFLAGS :=
AWS_PLUGIN_SYSTEM_LIBS := -lssl -lcrypto -lcurl -lz -lpthread -lm
ifeq ($(UNAME_S),Darwin)
PLUGIN_LDFLAGS += -Wl,-undefined,dynamic_lookup
AWS_PLUGIN_LIBS := -Wl,-all_load $(AWS_SDK_CPP_STATIC_ARCHIVES)
else
AWS_PLUGIN_LIBS := -Wl,--start-group $(AWS_SDK_CPP_STATIC_ARCHIVES) -Wl,--end-group
AWS_PLUGIN_SYSTEM_LIBS += -ldl -lrt
endif

$(AWS_SDK_CPP_IDENTITY_STAMP):
	mkdir -p "$(AWS_SDK_CPP_IDENTITY_DIR)"
	touch "$@"

$(AWS_SDK_CPP_RDS_LIB): $(AWS_SDK_CPP_ARCHIVE_PATH) \
		$(AWS_SDK_CPP_BUNDLE_DIR)/aws-sdk-cpp-$(AWS_SDK_CPP_VERSION)-with-crt.sha256 \
		$(AWS_SDK_CPP_BUNDLE_DIR)/aws-sdk-cpp-$(AWS_SDK_CPP_VERSION)-sources.json \
		$(AWS_SDK_CPP_BUNDLE_DIR)/verify-bundle.bash \
		$(AWS_SDK_CPP_BUNDLE_DIR)/build-sdk.cmake \
		$(AWS_SDK_CPP_IDENTITY_STAMP)
	$(MAKE) -C $(PROXYSQL_PATH)/deps PROXYSQL40=1 $@
	@test -f $@ || { echo "ERROR: AWS SDK build did not produce $@" >&2; exit 1; }

$(filter-out $(AWS_SDK_CPP_RDS_LIB),$(AWS_SDK_CPP_STATIC_ARCHIVES)): | $(AWS_SDK_CPP_RDS_LIB)
	@test -f $@ || { echo "ERROR: AWS SDK build did not produce $@" >&2; exit 1; }

$(ODIR):
	mkdir -p $@

$(ODIR)/aws_plugin.o: $(PLUGIN_DIR)/src/aws_plugin.cpp $(HEADERS) $(AWS_SDK_CPP_STATIC_ARCHIVES) | $(ODIR)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(IDIRS)

$(ODIR)/Aws_Iam_Token_Manager.o: $(PROXYSQL_PATH)/lib/Aws_Iam_Token_Manager.cpp $(HEADERS) | $(ODIR)
	$(CXX) -c -o $@ $< $(CXXFLAGS) $(IDIRS)

$(PLUGIN_SO): $(OBJS) $(AWS_SDK_CPP_STATIC_ARCHIVES)
	$(CXX) -shared -o $@ $(OBJS) $(CXXFLAGS) $(PLUGIN_LDFLAGS) \
		$(AWS_PLUGIN_LIBS) $(AWS_PLUGIN_SYSTEM_LIBS)

.PHONY: all
all: $(PLUGIN_SO)

.PHONY: clean
clean:
	rm -rf $(ODIR) $(PLUGIN_SO)
