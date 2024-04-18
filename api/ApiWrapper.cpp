//
// Created by fathi on 3/12/2024.
//

#include "ApiWrapper.h"
#include <iostream>

namespace arcane {
    namespace api {
        std::string ApiWrapper::api_endpoint = "192.168.1.3";
        int ApiWrapper::api_port = 8000;
        io_context ApiWrapper::io_context;
        tcp::resolver ApiWrapper::resolver(ApiWrapper::io_context);
        tcp::socket ApiWrapper::socket(ApiWrapper::io_context);

        void ApiWrapper::log(std::string level, std::string message, http::request<http::string_body> &msg) {
            std::cout << "logged request" << std::endl;
        }

        void ApiWrapper::log(std::string level, std::string message, http::response<http::string_body> &msg) {
            std::cout << "Logged response" << std::endl;
        }
    } // api
} // arcane