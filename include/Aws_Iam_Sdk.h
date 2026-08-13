#ifndef AWS_IAM_SDK_H
#define AWS_IAM_SDK_H

#include "Aws_Iam_Token_Manager.h"

#include <cstddef>
#include <memory>

struct AwsIamRuntimeConfig {
	size_t max_total_waiters;
	size_t max_waiters_per_key;
};

using AwsIamTokenSourceDestroyFn = void (*)(AwsIamTokenSource *);

class AwsIamTokenSourceLease {
public:
	AwsIamTokenSourceLease() = default;
	~AwsIamTokenSourceLease();
	AwsIamTokenSourceLease(AwsIamTokenSourceLease&& other) noexcept;
	AwsIamTokenSourceLease& operator=(AwsIamTokenSourceLease&& other) noexcept;

	AwsIamTokenSource *get() const { return source_; }
	AwsIamTokenSource *operator->() const { return source_; }
	explicit operator bool() const { return source_ != nullptr; }

	AwsIamTokenSourceLease(const AwsIamTokenSourceLease&) = delete;
	AwsIamTokenSourceLease& operator=(const AwsIamTokenSourceLease&) = delete;

private:
	explicit AwsIamTokenSourceLease(AwsIamTokenSource *source) : source_(source) {}
	void release();
	AwsIamTokenSource *source_ { nullptr };

	friend AwsIamTokenSourceLease acquire_global_aws_iam_token_source();
};

std::unique_ptr<AwsIamTokenSource> create_aws_iam_token_source(
	const AwsIamRuntimeConfig& config);

void publish_global_aws_iam_token_source(AwsIamTokenSource *source);
AwsIamTokenSourceLease acquire_global_aws_iam_token_source();
void shutdown_global_aws_iam_token_source();

// Transfers ownership of a provider created by a dynamically loaded plugin.
// `module_handle` is an extra dlopen() reference retained by core until every
// source lease has drained and `destroy` has run.
bool install_global_aws_iam_token_source(
	AwsIamTokenSource *source, AwsIamTokenSourceDestroyFn destroy, void *module_handle);

extern AwsIamTokenSource* GloAwsIamTokenSource;

#endif
