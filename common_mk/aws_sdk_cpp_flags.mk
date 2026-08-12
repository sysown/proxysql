AWS_IAM_BUILD_MODE = $(if $(filter 1,$(PROXYSQLAWSIAM)),enabled:$(AWS_IAM_DISCOVERY_ROOT):$(AWS_IAM_SDK_VERSION):$(AWS_IAM_SDK_SHARED),disabled)
AWS_IAM_MODE_STAMP := $(PROXYSQL_PATH)/build/aws-sdk-cpp/build-mode

ifeq ($(PROXYSQLAWSIAM),1)
AWS_IAM_BUILD_DIR := $(PROXYSQL_PATH)/build/aws-sdk-cpp
AWS_IAM_FLAGS_FILE := $(AWS_IAM_BUILD_DIR)/aws-sdk-cpp.mk
AWS_IAM_DISCOVERY_ROOT_REQUESTED := $(strip $(AWS_SDK_CPP_ROOT))

-include $(AWS_IAM_FLAGS_FILE)
ifneq ($(AWS_IAM_DISCOVERY_ROOT),$(AWS_IAM_DISCOVERY_ROOT_REQUESTED))
$(shell rm -f "$(AWS_IAM_FLAGS_FILE)")
endif

$(AWS_IAM_FLAGS_FILE): $(PROXYSQL_PATH)/cmake/aws-sdk-cpp/CMakeLists.txt
	@mkdir -p "$(AWS_IAM_BUILD_DIR)"
	@if [ -n "$(AWS_IAM_DISCOVERY_ROOT_REQUESTED)" ] && \
		[ -z "$$(find "$(AWS_IAM_DISCOVERY_ROOT_REQUESTED)" -type f -name AWSSDKConfig.cmake -print -quit 2>/dev/null)" ]; then \
		echo 'AWS SDK for C++ 1.9 or newer with core and rds is required' >&2; \
		exit 1; \
	fi
	@cmake -E rm -f "$(AWS_IAM_BUILD_DIR)/CMakeCache.txt"
	@cmake -E remove_directory "$(AWS_IAM_BUILD_DIR)/CMakeFiles"
	@cmake -S "$(PROXYSQL_PATH)/cmake/aws-sdk-cpp" -B "$(AWS_IAM_BUILD_DIR)" \
		-DPROXYSQL_AWS_REQUESTED_ROOT="$(AWS_IAM_DISCOVERY_ROOT_REQUESTED)" \
		$(if $(AWS_IAM_DISCOVERY_ROOT_REQUESTED),-DCMAKE_PREFIX_PATH="$(AWS_IAM_DISCOVERY_ROOT_REQUESTED)") \
		|| { echo 'AWS SDK for C++ 1.9 or newer with core and rds is required' >&2; exit 1; }

include $(AWS_IAM_FLAGS_FILE)
endif
