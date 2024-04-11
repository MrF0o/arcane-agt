//
// Created by fathi on 3/12/2024.
//

#ifndef ARCANEAGT_HTTPSERVER_H
#define ARCANEAGT_HTTPSERVER_H

#include <boost/asio.hpp>
#include <boost/beast.hpp>

using namespace boost;
using namespace boost::asio;
using namespace boost::beast;
using boost::asio::ip::tcp;

namespace arcane {
    namespace net {
        class HttpServer {
        public:
            HttpServer(io_context& ctx_, short port = 8080) :
            context(ctx_),
            acceptor(ctx_, tcp::endpoint(tcp::v4(), port)){}

            void listen(short port);
            void send(http::response<http::string_body>& response);
            http::request<http::string_body> receive();

            void close();

        private:
            io_context& context;
            tcp::acceptor acceptor;
            std::shared_ptr<tcp::socket> current_socket;
        };
    }
}

#endif //ARCANEAGT_HTTPSERVER_H
