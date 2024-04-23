//
// Created by fathi on 3/12/2024.
//

#include "HttpServer.h"
#include <iostream>
#include <utility>

void arcane::net::HttpServer::listen(short port) {
    current_socket = std::make_shared<tcp::socket>(context);
    acceptor.accept(*current_socket);
}

void arcane::net::HttpServer::send(http::response<http::string_body> &response) {
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

void arcane::net::HttpServer::addWebhook(const std::string& path,
                                         HookHandler pFunc) {

    hooks[path] = std::move(pFunc);
}

bool arcane::net::HttpServer::handleWebhook(http::request<http::string_body>& message) {
    if (message.base().method_string() == "POST") {
        auto target = message.base().target();
        if (hooks.contains(target)) {
            auto handler = hooks[target];
            handler(message, *this);
            return true;
        }
    }

    return false;
}

