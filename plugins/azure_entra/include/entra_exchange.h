#ifndef AZURE_ENTRA_EXCHANGE_H
#define AZURE_ENTRA_EXCHANGE_H

#include "Aws_Iam_Provider.h"
#include "entra_config.h"

#include <chrono>
#include <functional>
#include <string>

struct HttpResponse {
	long status { 0 };
	std::string body;
};

/** POST an application/x-www-form-urlencoded body; status 0 means a transport failure. */
using HttpPostFn = std::function<HttpResponse(const std::string& url,
	const std::string& form_body, std::chrono::milliseconds timeout)>;

struct EntraTokenResponse {
	bool ok { false };
	SecureString access_token;
	std::chrono::seconds expires_in { 0 };
	// category: credential_provider_error (assertion unreadable) or provider_error;
	// aws_error_code: Entra 'error'; request_id: Entra 'correlation_id'. Never secrets.
	AwsIamRedactedFailure failure;
};

/** HTTP timeout: below the 5 s session token wait, so a session sees a provider error, not a timeout. */
constexpr std::chrono::milliseconds kEntraHttpTimeout { 4000 };

/**
 * @brief Exchange the projected service-account token (the client assertion) for
 *   an Entra access token, as AKS workload identity does.
 * @param read_assertion reads the federated token file; called on every exchange
 *   because kubelet rotates the file.
 */
EntraTokenResponse exchange_workload_identity(const EntraConfig& cfg,
	const std::function<bool(std::string&)>& read_assertion, const HttpPostFn& post);

#endif // AZURE_ENTRA_EXCHANGE_H
