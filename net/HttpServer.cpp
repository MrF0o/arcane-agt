//
// Created by fathi on 3/12/2024.
//

#include "HttpServer.h"
#include <iostream>

void arcane::net::HttpServer::listen(short port) {
    current_socket = std::make_shared<tcp::socket>(context);
    acceptor.accept(*current_socket);
}

void arcane::net::HttpServer::send(http::response<http::string_body>& response) {
    http::write(*current_socket, response);
}

void arcane::net::HttpServer::close() {
    current_socket->close();
}

http::request<http::string_body> arcane::net::HttpServer::receive() {
    http::request<http::string_body> req;
    beast::flat_buffer buf;
    http::read(*current_socket, buf, req);

    return req;
}
