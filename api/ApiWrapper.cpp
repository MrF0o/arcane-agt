#include "ApiWrapper.h"
#include <spdlog/spdlog.h>
#include <boost/property_tree/ptree.hpp>
#include <sstream>
#include "scanner/Scanner.h"
#include <boost/property_tree/json_parser.hpp>
#include <boost/url.hpp>
#include <boost/json.hpp>

namespace json = boost::json;

namespace pt = boost::property_tree;
using namespace arcane::api;

std::string ApiWrapper::api_endpoint = "127.0.0.1";
int ApiWrapper::api_port = 8000;
bool ApiWrapper::isSSL;
std::string ApiWrapper::auth;
io_context ApiWrapper::io_context;
ssl::context ApiWrapper::ssl_context{ssl::context::sslv23_client};
tcp::resolver ApiWrapper::resolver{io_context};
std::unique_ptr<tcp::socket> ApiWrapper::socket = nullptr;
std::unique_ptr<ssl::stream<tcp::socket>> ApiWrapper::ssl_stream = nullptr;


void
ApiWrapper::log(std::string level, std::string message, std::string var_name, std::string var_kind, std::string value,
                std::string ip) {
    http::request<http::string_body> req;
    bool is_ip_banned = false;
//    std::string key = var_kind + ":" + var_name;
//    std::string match = R"({ ")" + key + R"(": ")" + value + R"(" })";
//
//    std::stringstream ss;
//    ss << R"({"message":")" << message << "\","
//       << "\"related_ip\":\"" << ip << "\","
//       << "\"ip_banned\":" << (is_ip_banned ? "true" : "false") << ","
//       << "\"match\":" << std::quoted(match) << "}";


    std::string key = var_kind + ":" + var_name;

    // Construct JSON object
    json::object jsonObject;
    jsonObject["message"] = message;
    jsonObject["domain"] = scanner::Scanner::webConfig.get<std::string>("domain");
    jsonObject["related_ip"] = ip;
    jsonObject["ip_banned"] = is_ip_banned;
    json::object matchObject;
    matchObject[key] = value;

    // Add 'match' object to the main JSON object
    jsonObject["match"] = boost::json::serialize(matchObject);

    // Convert JSON object to string
    std::string jsonString = boost::json::serialize(jsonObject);

    std::cout << jsonString << std::endl;
    req.body() = jsonString;
    auto res = post("/log", req);

    std::cout << res << std::endl;
}

bool ApiWrapper::isTokenValid(std::string token) {
    http::request<http::string_body> req;
    req.set(http::field::host, api_endpoint);
    req.set(http::field::accept, "application/json");
    req.set(http::field::user_agent, "Agent/1.0 " + std::string(BOOST_BEAST_VERSION_STRING));
    auto res = post("/verify", req);
    if (res.base().result() != http::status::ok) {
        return false;
    }

    pt::ptree root;
    std::stringstream ss;
    ss << res.body();
    pt::read_json(ss, root);
    spdlog::info("Your license is valid! current membership: " + root.get<std::string>("membership_name"));
    return true;
}

std::map<std::string, std::string> ApiWrapper::getWebConfig() {
    http::request<http::string_body> req;

    auto res = get("/config?domain=" + scanner::Scanner::config.get<std::string>("app.domain"));
    if (res.result() == http::status::ok) {
        std::stringstream ss;
        ss << res.body();
        std::cout << ss.str() << std::endl;
        pt::read_json(ss, scanner::Scanner::webConfig);
    } else {
        throw std::runtime_error("Invalid config: invalid domain! make sure to add the website to your account.");
    }

    return {};
}

bool ApiWrapper::connect() {
    try {
        spdlog::info("Trying to connect to the dashboard API");
        auto const results = resolver.resolve(api_endpoint, std::to_string(api_port));
        socket = std::make_unique<tcp::socket>(io_context);
        socket->connect(*results.begin());
        spdlog::info("Connected!");
        return true;
    } catch (const std::exception &e) {
        spdlog::error("Connection failed: " + std::string(e.what()));
        return false;
    }
}

bool ApiWrapper::connectSSL() {
    try {
        auto const results = resolver.resolve(api_endpoint, std::to_string(api_port));
        ssl_stream = std::make_unique<ssl::stream<tcp::socket>>(io_context, ssl_context);

        if (!SSL_set_tlsext_host_name(ssl_stream->native_handle(), api_endpoint.c_str())) {
            beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
            throw beast::system_error{ec};
        }

        tcp::endpoint endpoint = *results.begin();

        ssl_stream->lowest_layer().connect(endpoint);
        ssl_stream->handshake(ssl::stream_base::client);

        isSSL = true;

        return true;
    } catch (const std::exception &e) {
        std::cerr << "SSL connection failed: " << e.what() << std::endl;
        return false;
    }
}

bool ApiWrapper::verify_certificate(bool preverified, ssl::verify_context &ctx) {
    // Implement custom certificate verification if needed
    return preverified;
}

int ApiWrapper::sendTest() {
    try {
        if (!ssl_stream) {
            throw std::runtime_error("SSL stream is not initialized.");
        }

        http::request<http::string_body> req(http::verb::get, "/api/test", 11);
        req.set(http::field::host, api_endpoint);
        req.set(http::field::accept, "application/json");
        req.set(http::field::user_agent, "Agent/1.0 " + std::string(BOOST_BEAST_VERSION_STRING));
        http::write(*ssl_stream, req);

        // Read response
        flat_buffer buf;
        http::response<http::string_body> res;
        http::read(*ssl_stream, buf, res);
        std::cout << res.body() << std::endl;
        return 0;
    } catch (const std::exception &e) {
        spdlog::error("Request failed: " + std::string(e.what()));
        return -1;
    }
}

http::response<http::string_body> ApiWrapper::post(std::string path, http::request<http::string_body> req) {
    try {
        // Establish connection if necessary
        if (!ssl_stream) {
            connectSSL();
        }

        // Build URL
        std::string target = (isSSL ? "https://" : "http://") + api_endpoint + ":" + std::to_string(api_port) + "/api" + path;
        req.target(target);
        req.version(11);
        req.method(http::verb::post);
        req.set(http::field::host, api_endpoint);
        req.set(http::field::user_agent, "Agent/1.0 " + std::string(BOOST_BEAST_VERSION_STRING));
        req.set(http::field::content_type, "application/json");
        req.set(http::field::accept, "application/json");
        req.set(http::field::authorization, "Bearer " + auth);
        req.prepare_payload();
        // Send request
        http::write(*ssl_stream, req);

        // Read response
        flat_buffer buf;
        http::response<http::string_body> res;
        http::read(*ssl_stream, buf, res);
        return res;
    } catch (const std::exception &e) {
        std::cerr << "POST request failed: " << e.what() << std::endl;
        return {}; // Return empty response on failure
    }
}


http::response<http::string_body> ApiWrapper::get(std::string path) {
    http::request<http::empty_body> req(http::verb::get, "", 11);
    // Build url
    auto target = (isSSL ? "https://" : "http://") + api_endpoint + ":" + std::to_string(api_port) + "/api" + path;
    req.target(target);
    req.set(http::field::host, api_endpoint);
    req.set(http::field::user_agent, "Agent/1.0 " + std::string(BOOST_BEAST_VERSION_STRING));
    req.set(http::field::content_type, "application/json");
    req.set(http::field::authorization, "Bearer " + auth);
    http::write(*ssl_stream, req);

    try {
        // Establish connection
        if (!ssl_stream) {
            ApiWrapper::connectSSL();
        }

        // Send request
        http::write(*ssl_stream, req);

        // Read response
        flat_buffer buf;
        http::response<http::string_body> res;
        http::read(*ssl_stream, buf, res);
        return res;
    } catch (const std::exception &e) {
        std::cerr << "GET request failed: " << e.what() << std::endl;
        return {}; // Return empty response on failure
    }
}
