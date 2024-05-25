//
// Created by fathi on 3/12/2024.
//

#ifndef ARCANEAGT_APIWRAPPER_H
#define ARCANEAGT_APIWRAPPER_H

#include <string>
#include <boost/beast.hpp>
#include <map>
#include <boost/asio.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>

using namespace boost::beast;
using namespace boost;
using namespace boost::asio;
using namespace boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

namespace arcane {
    namespace api {

        class ApiWrapper {
        public:
            static std::string api_endpoint;
            static int api_port;
            static bool isSSL;
            static io_context io_context;
            static ssl::context ssl_context;
            static std::string auth;
            static tcp::resolver resolver;
            static std::unique_ptr<tcp::socket> socket;
            static std::unique_ptr<ssl::stream<tcp::socket>> ssl_stream;

            static void
            log(std::string level, std::string message, std::string var_name, std::string var_kind, std::string value,
                std::string ip);

            static bool isTokenValid(std::string token);

            static std::map<std::string, std::string> getWebConfig();

            static bool connect();

            static bool connectSSL();

            int sendTest();

            static http::response<http::string_body> post(std::string path, http::request<http::string_body> req);

            static http::response<http::string_body> get(std::string path);

        private:
            bool verify_certificate(bool preverified, ssl::verify_context &ctx);
        };

    } // api
} // arcane

#endif //ARCANEAGT_APIWRAPPER_H
