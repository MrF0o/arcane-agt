//
// Created by fathi on 3/12/2024.
//

#include "HttpClient.h"

void arcane::net::HttpClient::connect(const std::string& host, const std::string& port) {
    auto ep = tcp::endpoint(boost::asio::ip::address::from_string(host), atoi(port.c_str()));
    socket.connect(ep);
}

http::response<http::string_body> arcane::net::HttpClient::receive() {
    http::response<http::string_body> res;

    http::read(socket, buffer, res);

    return res;
}

void arcane::net::HttpClient::send(http::request<http::string_body> &request) {
    auto v = http::write(socket, request);
}

void arcane::net::HttpClient::close() {
    socket.close();
}
