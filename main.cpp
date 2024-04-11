#include "net/HttpProxy.h"
#include "scanner/Scanner.h"
#include <thread>

using namespace arcane;

int main() {
    scanner::Scanner sc;
    io_context context;
    arcane::net::HttpProxy proxy(context);

    proxy.setBeforeForwardingToBackend([&](arcane::net::HttpProxy* ctx, http::request<http::string_body>& req) {
        std::cout << "[HOOK] (setBeforeForwardingToBackend)" << std::endl;
        sc.scan_inbound(req);
    });


    proxy.setBeforeSendingToClient([&](arcane::net::HttpProxy* ctx) {
        auto res = http::response<http::string_body>();
        sc.scan_outbound(res);
    });

    std::thread thread([&]() {
        while (true) {
            proxy.forward();
        }
    });

    thread.join();

    return 0;
}