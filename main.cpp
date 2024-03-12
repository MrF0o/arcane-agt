#include <boost/beast.hpp>
#include <boost/asio.hpp>
#include <iostream>
#include <string>

int main() {
    HttpClient client;
    HttpServer server;
    HttpProxy proxy(client, server);

    proxy.addRequestScanner(std::make_unique<RequestScanner>());
    proxy.addResponseScanner(std::make_unique<ResponseScanner>());

    proxy.forward();

    return 0;
}