#ifndef AZURE_ENTRA_CURL_TRANSPORT_H
#define AZURE_ENTRA_CURL_TRANSPORT_H

#include "entra_exchange.h"

/**
 * @brief libcurl POST for the Entra token endpoint: https only, peer and host
 *   verified, no redirects, response capped at 64 KiB. Status 0 on any
 *   transport error.
 */
HttpPostFn make_curl_post();

#endif // AZURE_ENTRA_CURL_TRANSPORT_H
