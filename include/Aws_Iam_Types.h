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

/** @brief Token-source slot: one per provider, so AWS and Azure can be installed together (#6649). */
enum class BackendTokenProvider : uint8_t {
	AWS_IAM = 0,
	AZURE_ENTRA = 1,
};

#endif // AWS_IAM_TYPES_H
