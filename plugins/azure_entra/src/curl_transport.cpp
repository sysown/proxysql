#include "curl_transport.h"

#include <curl/curl.h>

#include <memory>

namespace {

constexpr size_t kMaxResponseBytes = 64 * 1024;

size_t append_capped(char *data, size_t size, size_t count, void *user) {
	auto *body = static_cast<std::string *>(user);
	const size_t bytes = size * count;
	if (body->size() + bytes > kMaxResponseBytes) return 0; // aborts the transfer
	body->append(data, bytes);
	return bytes;
}

} // namespace

HttpPostFn make_curl_post() {
	return [](const std::string& url, const std::string& form_body, std::chrono::milliseconds timeout) {
		HttpResponse response;
		std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), &curl_easy_cleanup);
		if (!curl) return response;
		curl_slist *headers = curl_slist_append(nullptr,
			"Content-Type: application/x-www-form-urlencoded");
		CURL *h = curl.get();
		curl_easy_setopt(h, CURLOPT_URL, url.c_str());
		curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "https");
		curl_easy_setopt(h, CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2));
		curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);
		curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
		curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
		curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
		curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout.count()));
		curl_easy_setopt(h, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(h, CURLOPT_POSTFIELDS, form_body.c_str());
		curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, static_cast<long>(form_body.size()));
		curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, &append_capped);
		curl_easy_setopt(h, CURLOPT_WRITEDATA, &response.body);
		if (curl_easy_perform(h) == CURLE_OK) {
			curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &response.status);
		} else {
			response.status = 0;
			response.body.clear();
		}
		curl_slist_free_all(headers);
		return response;
	};
}
