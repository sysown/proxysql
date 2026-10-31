// Socket-level fixture for the vendored libhttpserver signed-request contract.
#include <httpserver.hpp>
#include <json.hpp>
#include <atomic>
#include <cstdlib>
#include <iostream>

class RawRequestResource : public httpserver::http_resource {
    std::atomic<unsigned> dispatched{0};
public:
    const std::shared_ptr<httpserver::http_response> render(
        const httpserver::http_request& request) override {
        // The management route must check overflow before dispatching a command.
        if (request.body_limit_exceeded()) {
            return std::make_shared<httpserver::string_response>(
                nlohmann::json{{"dispatched", dispatched.load()}}.dump(), 413,
                "application/json");
        }
        ++dispatched;
        nlohmann::json reply = {
            {"target", request.get_raw_request_target()},
            {"headers", request.get_raw_headers()},
            {"body", request.get_content()},
            {"path", request.get_path()},
            {"arg", request.get_arg("data")},
            {"method", request.get_method()},
            {"dispatched", dispatched.load()}
        };
        return std::make_shared<httpserver::string_response>(
            reply.dump(), 200, "application/json");
    }
};

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    RawRequestResource resource;
    httpserver::webserver server = httpserver::create_webserver()
        .bind_socket(std::atoi(argv[1])).content_size_limit(16)
        .start_method(httpserver::http::http_utils::INTERNAL_SELECT);
    server.register_resource("/aws/rds", &resource, true);
    server.start(false);
    if (!server.is_running()) return 3;
    std::cout << "ready" << std::endl;
    std::string done;
    std::getline(std::cin, done);
    server.stop();
}
