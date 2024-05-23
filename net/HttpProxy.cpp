//
// Created by fathi on 3/12/2024.
//

#include "HttpProxy.h"
#include <sstream>
#include <boost/json.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <filesystem>
#include <spdlog/spdlog.h>

namespace fs = std::filesystem;

namespace pt = boost::property_tree;

void arcane::net::HttpProxy::forward() {
    try {
        server.listen(8080);
        auto req = server.receive();

        // check if it's a webhook request

        if (server.handleWebhook(req)) {
            std::cout << "Webhook handled" << std::endl;
            return;
        }

        client.connect(backendHost, backendPort);
        beforeForwardingToBackend(this, req);

        // TODO: check if request is blocked and send a blocked page
        client.send(req);
        auto res = client.receive();
        beforeSendingToClient(this, res);

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

std::vector<std::string> ls(const fs::path& path = "c:/xampp/htdocs/test", std::string parent = "") {
    std::vector<std::string> entries;

    for (const auto& entry : fs::directory_iterator(path)) {
        if (fs::is_directory(entry.path())) {
            auto subdir_entries = ls(entry.path(), parent + entry.path().filename().string() + "/");
            entries.insert(entries.end(), subdir_entries.begin(), subdir_entries.end());
        } else {
            entries.push_back(parent + entry.path().filename().string());
        }
    }

    return entries;
}

std::string listdir(const fs::path& path = "c:/xampp/htdocs/test") {
    std::vector<std::string> entries = ls(path);

    std::string jsonArray = "[";
    bool isFirstEntry = true;
    for (const auto& entry : entries) {
        if (!isFirstEntry) {
            jsonArray += ",";
        } else {
            isFirstEntry = false;
        }
        jsonArray += "\"" + entry + "\"";
    }
    jsonArray += "]";
    return jsonArray;
}

std::string catfs(std::string pathFromRoot) {
    std::ifstream file(pathFromRoot);

    if (file.is_open()) {
        std::stringstream ss;
        ss << file.rdbuf();
        return ss.str();
    }

    return "";
}

std::string readSnippets(const std::string& path, std::streamoff start, std::streamoff end) {
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

arcane::net::HttpProxy::HttpProxy(io_context &ctx)
        : io_ctx(ctx), client(ctx), server(ctx) {

    server.addWebhook("/_getFileContent", [&](http::request<http::string_body> &req, net::HttpServer &res) {
        if (req.base().at("Content-Type") == "application/json") {
            // our server needs json
            pt::ptree root;
            std::stringstream ss;
            ss << req.body();
            pt::read_json(ss, root);

            http::response<http::string_body> res_;
            res_.set("User-Agent", "Arcane Agent");
            // res_.set("Content-Type", "application/json");
            std::string file_content = catfs("C:/xampp/htdocs/test/" + root.get<std::string>("file_path"));
            res_.body() = file_content;
            std::cout << res_.body() << std::endl;
            res.send(res_);
            std::cout << "Webhook handled" << std::endl;
        }
    });

    server.addWebhook("/_listDocumentRoot", [&](http::request<http::string_body> &req, net::HttpServer &res) {
        if (req.base().at("Content-Type") == "application/json") {
            // our server needs json
            pt::ptree root;
            std::stringstream ss;
            ss << req.body();
            pt::read_json(ss, root);

            http::response<http::string_body> res_;
            res_.set("User-Agent", "Arcane Agent");
            res_.set("Content-Type", "application/json");
            res_.body() = std::string(R"({"files": )") + listdir(root.get<std::string>("doc_root")) + R"(})";
            res.send(res_);
        }
    });

    server.addWebhook("/_fileSnippets", [&](http::request<http::string_body> &req, net::HttpServer &res) {
        if (req.base().at("Content-Type") == "application/json") {
            // our server needs json
            pt::ptree root;
            std::stringstream ss;
            ss << req.body();
            pt::read_json(ss, root);


            http::response<http::string_body> res_;
            res_.set("User-Agent", "Arcane Agent");
            // res_.set("Content-Type", "application/json");
            int start = root.get<int>("start_offset");
            int end = root.get<int>("start_offset");
            auto path = "C:/xampp/htdocs/test/" + root.get<std::string>("file_path");
            std::string snippets = readSnippets(path, start, end);
            std::cout << "_________________________________" <<std::endl;
            std::cout << snippets << std::endl;
            std::cout << "\n";
            res_.body() = snippets;
            res.send(res_);
        }
    });

    spdlog::info("[HttpProxy] Server and client started");
    spdlog::info("[HttpProxy] The proxy is running");

    spdlog::warn("SQL Injection detected; user ip: 192.168.10.5");
    spdlog::warn("XSS detected; user ip: 192.168.10.5");
}

void arcane::net::HttpProxy::setBeforeForwardingToBackend(
        std::function<void(HttpProxy * , http::request<http::string_body> & )> pFunc) {
    beforeForwardingToBackend = std::move(pFunc);
}

void arcane::net::HttpProxy::setBeforeSendingToClient(std::function<void(HttpProxy *, http::response<http::string_body> &res)> pFunc) {
    beforeSendingToClient = std::move(pFunc);
}