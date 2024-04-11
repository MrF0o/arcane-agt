//
// Created by fathi on 3/12/2024.
//

#ifndef ARCANEAGT_HTTPCLIENT_H
#define ARCANEAGT_HTTPCLIENT_H

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <iostream>

using namespace boost::asio;
using namespace boost::beast;
using boost::asio::ip::tcp;

namespace arcane {
    namespace net {
        class HttpClient {

        public:

            HttpClient(io_context& ctx_) : ctx(ctx_), socket(ctx_) {}

            void connect(const std::string& host, const std::string& port);
            http::response<http::string_body> receive();
            void send(http::request<http::string_body>& request);

            void close();

        private:
            // the client socket
            tcp::socket socket;
            // response/request buffer
            flat_buffer buffer;
            // the io context
            io_context& ctx;
        };
    }
}

#endif //ARCANEAGT_HTTPCLIENT_H
