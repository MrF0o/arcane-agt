//
// Created by fathi on 3/12/2024.
//

#ifndef ARCANEAGT_HTTPPROXY_H
#define ARCANEAGT_HTTPPROXY_H

#include "HttpClient.h"
#include "HttpServer.h"
#include <boost/beast.hpp>
#include <functional>
#include <boost/asio.hpp>

using namespace boost;
using namespace boost::asio;


namespace arcane {
    namespace net {
        class HttpProxy {
        public:
            HttpProxy(io_context &ctx);

            // forward the request back and forth
            void forward();

            void
            setBeforeForwardingToBackend(std::function<void(HttpProxy *, http::request<http::string_body> &)> pFunc);

            void setBeforeSendingToClient(std::function<void(HttpProxy *, http::response<http::string_body> &res)> pFunc);

        private:
            // used to connect to the protected webserver
            HttpClient client;
            // used to listen for the proxied request
            HttpServer server;
            // shared between the client and the server
            io_context &io_ctx;

            // backend server info
            std::string backendHost = "127.0.0.1";
            std::string backendPort = "8000";

            // Hooks
            std::function<void(HttpProxy *, http::request<http::string_body> &)> beforeForwardingToBackend;
            std::function<void(HttpProxy *, http::response<http::string_body> &)> beforeSendingToClient;
        };
    }
}


#endif //ARCANEAGT_HTTPPROXY_H
