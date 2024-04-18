//
// Created by fathi on 3/12/2024.
//

#ifndef ARCANEAGT_APIWRAPPER_H
#define ARCANEAGT_APIWRAPPER_H

#include <string>
#include <boost/beast.hpp>
#include <boost/json.hpp>
#include <boost/asio.hpp>
#include <boost/beast/http/message.hpp>
#include <iostream>

using namespace boost::beast;
using namespace boost::asio;
using tcp = boost::asio::ip::tcp;
namespace arcane {
    namespace api {

        class ApiWrapper {
        public:
            static std::string api_endpoint;
            static int api_port;
            static tcp::socket socket;
            static tcp::resolver resolver;
            static io_context io_context;

            static void
            log(std::string level, std::string message, http::request<http::string_body> &msg);

            static void
            log(std::string level, std::string message, http::response<http::string_body> &msg);


            inline bool connect() {
                auto const endpoint = tcp::endpoint(ip::address::from_string(ApiWrapper::api_endpoint), ApiWrapper::api_port);

               ApiWrapper::socket.connect(endpoint);

                return true;
            }

            inline bool connectSSL();

            int sendTest() {
                http::request<http::string_body> req(http::verb::get, "/api/test", 11);
                req.set(http::field::host, "protectedsite.com");
                req.set(http::field::accept, "application/json");
                req.set(http::field::user_agent, "Agent/1.0 " + std::string(BOOST_BEAST_VERSION_STRING));
                http::write(ApiWrapper::socket, req);

                // read
                flat_buffer buf;
                http::response<http::string_body> res;
                http::read(ApiWrapper::socket, buf, res);
                std::cout << res.body();
                return 0; // returns bytes sent
            }
        };

    } // api
} // arcane

#endif //ARCANEAGT_APIWRAPPER_H
