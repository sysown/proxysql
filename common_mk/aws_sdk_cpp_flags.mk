AWS_IAM_MODE_STAMP := $(PROXYSQL_PATH)/build/aws-sdk-cpp/build-mode
AWS_IAM_BUILD_MODE := disabled

ifeq ($(PROXYSQLAWSIAM),1)
AWS_IAM_BUILD_DIR := $(PROXYSQL_PATH)/build/aws-sdk-cpp

export AWS_SDK_CPP_ROOT
AWS_IAM_REQUEST_ID := $(shell \
	printf '%s' "$$AWS_SDK_CPP_ROOT" | \
	cmake -E sha256sum /dev/stdin | sed 's/[[:space:]].*//')
AWS_IAM_CONFIGURE_DIR := $(AWS_IAM_BUILD_DIR)/configure-$(AWS_IAM_REQUEST_ID)
AWS_IAM_DISCOVERY_ID := $(shell \
	if cmake \
		-DPROXYSQL_SOURCE_DIR="$(PROXYSQL_PATH)" \
		-DPROXYSQL_REQUEST_ID="$(AWS_IAM_REQUEST_ID)" \
		-P "$(PROXYSQL_PATH)/cmake/aws-sdk-cpp/DiscoverAwsSdk.cmake"; then \
		:; \
	else \
		printf '%s' failure; \
	fi)

ifeq ($(AWS_IAM_DISCOVERY_ID),failure)
$(error AWS SDK for C++ 1.9 or newer with core and rds is required)
endif

AWS_IAM_FLAGS_FILE := $(AWS_IAM_BUILD_DIR)/fragments/$(AWS_IAM_DISCOVERY_ID).mk
include $(AWS_IAM_FLAGS_FILE)
AWS_IAM_BUILD_MODE := enabled:$(AWS_IAM_DISCOVERY_ID)
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
