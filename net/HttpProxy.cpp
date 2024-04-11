//
// Created by fathi on 3/12/2024.
//

#include "HttpProxy.h"


void arcane::net::HttpProxy::forward() {
    try {
        server.listen(8080);
        auto req = server.receive();
        client.connect(backendHost, backendPort);
        beforeForwardingToBackend(this, req);

        // TODO: check if request is blocked and send a blocked page
        client.send(req);
        auto res = client.receive();
        beforeSendingToClient(this);

        // TODO: check if response is blocked and send a blocked page
        server.send(res);

        client.close();
        server.close();
    } catch (std::exception &e) {
        std::cout << e.what() << std::endl;
        // Close connections in case of error
        client.close();
        server.close();
    }
}

arcane::net::HttpProxy::HttpProxy(io_context& ctx)
    : io_ctx(ctx), client(ctx), server(ctx)
{

    std::cout << "[HttpProxy] Server and client started" << std::endl;
    std::cout << "[HttpProxy] The proxy is running" << std::endl;
}

void arcane::net::HttpProxy::setBeforeForwardingToBackend(std::function<void(HttpProxy*, http::request<http::string_body>&)> pFunc) {
    beforeForwardingToBackend = std::move(pFunc);
}

void arcane::net::HttpProxy::setBeforeSendingToClient(std::function<void(HttpProxy*)> pFunc) {
    beforeSendingToClient = std::move(pFunc);
}