AWS_IAM_MODE_STAMP := $(PROXYSQL_PATH)/build/aws-sdk-cpp/build-mode
AWS_IAM_BUILD_MODE := disabled

ifeq ($(PROXYSQLAWSIAM),1)
AWS_IAM_BUILD_DIR := $(PROXYSQL_PATH)/build/aws-sdk-cpp
AWS_IAM_FLAGS_FILE := $(AWS_IAM_BUILD_DIR)/aws-sdk-cpp.mk

export AWS_SDK_CPP_ROOT
AWS_IAM_DISCOVERY_RESULT := $(shell \
	mkdir -p "$(AWS_IAM_BUILD_DIR)"; \
	cmake -E rm -f "$(AWS_IAM_BUILD_DIR)/CMakeCache.txt"; \
	cmake -E remove_directory "$(AWS_IAM_BUILD_DIR)/CMakeFiles"; \
	if cmake -S "$(PROXYSQL_PATH)/cmake/aws-sdk-cpp" \
		-B "$(AWS_IAM_BUILD_DIR)" >/dev/null; then \
		printf '%s' success; \
	else \
		printf '%s' failure; \
	fi)

ifneq ($(AWS_IAM_DISCOVERY_RESULT),success)
$(error AWS SDK for C++ 1.9 or newer with core and rds is required)
endif

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
		printf '%s\n' '$(AWS_IAM_BUILD_MODE)' > "$(AWS_IAM_MODE_STAMP).tmp"; \
		mv -f "$(AWS_IAM_MODE_STAMP).tmp" "$(AWS_IAM_MODE_STAMP)"; \
	fi)
