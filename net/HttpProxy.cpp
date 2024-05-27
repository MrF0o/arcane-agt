//
// Created by fathi on 3/12/2024.
//

#include "HttpProxy.h"
#include <sstream>
#include <boost/json.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <filesystem>
#include <boost/regex.hpp>
#include "api/ApiWrapper.h"
#include "scanner/Scanner.h"
#include <spdlog/spdlog.h>

namespace fs = std::filesystem;

namespace pt = boost::property_tree;

void arcane::net::HttpProxy::forward() {
    try {
        server.listen(8080);
        auto req = server.receive();
        this->currentReq = req;
        // check if it's a webhook request
        if (server.handleWebhook(req)) {
            return;
        }

        client.connect(backendHost, backendPort);
        beforeForwardingToBackend(this, req);

        // for the request
        if (scanner::Scanner::isBlocked) {
            scanner::Scanner::isBlocked = false;
            this->sendBlockedPage();
            client.close();
            server.close();
            return;
        }

        client.send(req);
        auto res = client.receive();
        beforeSendingToClient(this, res);

        // for the response
        if (scanner::Scanner::isBlocked) {
            scanner::Scanner::isBlocked = false;
            this->sendBlockedPage();
            client.close();
            server.close();
            return;
        }

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

std::vector<std::string> ls(const fs::path &path = "c:/xampp/htdocs/test", std::string parent = "") {
    std::vector<std::string> entries;

    for (const auto &entry: fs::directory_iterator(path)) {
        if (fs::is_directory(entry.path())) {
            auto subdir_entries = ls(entry.path(), parent + entry.path().filename().string() + "/");
            entries.insert(entries.end(), subdir_entries.begin(), subdir_entries.end());
        } else {
            entries.push_back(parent + entry.path().filename().string());
        }
    }

    return entries;
}

std::string listdir(const fs::path &path = "c:/xampp/htdocs/test") {
    std::vector<std::string> entries = ls(path);

    std::string jsonArray = "[";
    bool isFirstEntry = true;
    for (const auto &entry: entries) {
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

std::string readSnippets(const std::string &path, std::streamoff start, std::streamoff end) {
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
        : io_ctx(ctx), client(ctx), server(ctx, this->serverPort) {

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
            res_.body() = snippets;
            res.send(res_);
        }
    });

    server.addWebhook("/_updateWebConfig", [&](http::request<http::string_body> &req, net::HttpServer &res) {
        if (req.base().at("Content-Type") == "application/json") {
            arcane::api::ApiWrapper::getWebConfig();
        }
    });

    spdlog::info("[HttpProxy] Server and client started");
    spdlog::info("[HttpProxy] The proxy is listening on port " + std::to_string(this->serverPort));
}

void arcane::net::HttpProxy::setBeforeForwardingToBackend(
        std::function<void(HttpProxy * , http::request<http::string_body> & )> pFunc) {
    beforeForwardingToBackend = std::move(pFunc);
}

void arcane::net::HttpProxy::setBeforeSendingToClient(
        std::function<void(HttpProxy * , http::response<http::string_body> & res)> pFunc) {
    beforeSendingToClient = std::move(pFunc);
}

void arcane::net::HttpProxy::sendBlockedPage() {
    std::ifstream file("../static/blocked.html");
    std::stringstream ss;
    ss << file.rdbuf();
    std::string content = ss.str();
    boost::regex_replace(content, boost::regex("\\{ip\\}"), this->currentReq.at("X-Forwarded-For"));

    this->currentRes.body() = content;
    this->currentRes.set(http::field::content_type, "text/html");
    server.send(this->currentRes);
}
