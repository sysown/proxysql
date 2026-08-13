AWS_IAM_MODE_STAMP := $(PROXYSQL_PATH)/deps/aws-sdk-cpp/.proxysql-build-mode
AWS_IAM_BUILD_MODE := disabled

ifeq ($(PROXYSQLAWSIAM),1)
AWS_IAM_SDK_VERSION := 1.11.869
AWS_IAM_SDK_SHARED := 0
AWS_IAM_INSTALL_DIR := $(PROXYSQL_PATH)/deps/aws-sdk-cpp/aws-sdk-cpp-$(AWS_IAM_SDK_VERSION)/install
AWS_IAM_LIB_DIR := $(AWS_IAM_INSTALL_DIR)/lib
AWS_IAM_CPPFLAGS := -I$(AWS_IAM_INSTALL_DIR)/include
AWS_IAM_LDFLAGS :=
AWS_IAM_STATIC_ARCHIVES := \
	$(AWS_IAM_LIB_DIR)/libaws-cpp-sdk-rds.a \
	$(AWS_IAM_LIB_DIR)/libaws-cpp-sdk-core.a \
	$(AWS_IAM_LIB_DIR)/libaws-crt-cpp.a \
	$(AWS_IAM_LIB_DIR)/libaws-c-s3.a \
	$(AWS_IAM_LIB_DIR)/libaws-c-auth.a \
	$(AWS_IAM_LIB_DIR)/libaws-c-mqtt.a \
	$(AWS_IAM_LIB_DIR)/libaws-c-http.a \
	$(AWS_IAM_LIB_DIR)/libaws-c-event-stream.a \
	$(AWS_IAM_LIB_DIR)/libaws-c-compression.a \
	$(AWS_IAM_LIB_DIR)/libaws-c-io.a \
	$(AWS_IAM_LIB_DIR)/libaws-c-cal.a \
	$(AWS_IAM_LIB_DIR)/libaws-c-sdkutils.a \
	$(AWS_IAM_LIB_DIR)/libaws-checksums.a \
	$(AWS_IAM_LIB_DIR)/libaws-c-common.a \
	$(AWS_IAM_LIB_DIR)/libs2n.a
AWS_IAM_LIBS := -Wl,--start-group $(AWS_IAM_STATIC_ARCHIVES) -Wl,--end-group
AWS_IAM_BUILD_MODE := enabled:$(AWS_IAM_SDK_VERSION):static
endif

# Update the mode stamp before make evaluates object freshness. Preserve its
# mtime when the feature mode is unchanged so dry-run and real no-op builds
# schedule no compilation, archive, or link commands.
AWS_IAM_MODE_STAMP_UPDATE := $(shell \
	mkdir -p "$(dir $(AWS_IAM_MODE_STAMP))"; \
	if [ ! -f "$(AWS_IAM_MODE_STAMP)" ] || \
		[ "$$(sed -n '1p' "$(AWS_IAM_MODE_STAMP)")" != "$(AWS_IAM_BUILD_MODE)" ]; then \
		mode_tmp=$$(mktemp "$(AWS_IAM_MODE_STAMP).tmp.XXXXXX") && \
		printf '%s\n' '$(AWS_IAM_BUILD_MODE)' > "$$mode_tmp" && \
		mv -f "$$mode_tmp" "$(AWS_IAM_MODE_STAMP)"; \
	fi)
