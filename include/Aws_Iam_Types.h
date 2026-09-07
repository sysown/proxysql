#ifndef AWS_IAM_TYPES_H
#define AWS_IAM_TYPES_H

#include <cstdint>
#include <string>

struct AwsIamTokenKey {
	std::string endpoint;
	uint16_t port;
	std::string region;
	std::string database_user;

	bool operator==(const AwsIamTokenKey& other) const {
		return endpoint == other.endpoint && port == other.port &&
			region == other.region && database_user == other.database_user;
	}
};

#endif // AWS_IAM_TYPES_H
