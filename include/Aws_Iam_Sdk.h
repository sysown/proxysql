#ifndef AWS_IAM_SDK_H
#define AWS_IAM_SDK_H

#include "Aws_Iam_Token_Manager.h"

#include <cstddef>
#include <memory>

struct AwsIamRuntimeConfig {
	size_t max_total_waiters;
	size_t max_waiters_per_key;
};

std::unique_ptr<AwsIamTokenSource> create_aws_iam_token_source(
	const AwsIamRuntimeConfig& config);

extern AwsIamTokenSource* GloAwsIamTokenSource;

#endif
