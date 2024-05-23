#define LIBINJECTION_VERSION 0

#include "net/HttpProxy.h"
#include "scanner/Scanner.h"
#include <thread>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <iostream>
#include <spdlog/spdlog.h>

namespace fs = std::filesystem;

using namespace arcane;
namespace pt = boost::property_tree;

pt::ptree read_config(const std::string &path) {
    pt::ptree root;
    pt::read_json(path, root);

    return root;
}

void print_banner() {
    spdlog::info("***************************************************");
    spdlog::info("| Arcane WAF Agent (SECURAS + ISGGB)              |");
    spdlog::info("| Started                                         |");
    spdlog::info("***************************************************");
    std::cout << std::endl;
}

std::string ssr(const std::string &path, std::streamoff start, std::streamoff end) {
    std::ifstream fin(path);

    if (!fin.is_open()) {
        std::cout << "Error reading file for portion\n";
        return "";
    }

    std::string portion;
    std::string line;
    fin.seekg(start, std::ios::beg);
    for (int i = 0; i <= end; i++) {
        if (i < start) {
            std::getline(fin, line);
        } else {
            std::getline(fin, line);
            portion += line;
        }
    }

    return portion;
}

int main() {
    print_banner();

    try {
        auto const config_root = read_config("../config.json");
        auto license_key = config_root.get<std::string>("license_key");

        if (license_key.empty()) {
            std::cout << "Invalid license key provided!" << std::endl;
            return -1;
        }
    } catch (std::exception &ex) {
        std::cout << "Invalid config file. please reinstall the agent or run the troubleshooter" << std::endl;
        return -1;
    }

    scanner::Scanner sc;
    io_context context;
    arcane::net::HttpProxy proxy(context);

    proxy.setBeforeForwardingToBackend([&](arcane::net::HttpProxy *ctx, http::request<http::string_body> &req) {
        sc.scan_inbound(req);
    });

    proxy.setBeforeSendingToClient([&](arcane::net::HttpProxy *ctx, http::response<http::string_body> &res) {
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