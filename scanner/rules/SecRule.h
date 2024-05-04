//
// Created by fathi on 4/5/2024.
//

#ifndef ARCANEAGT_SECRULE_H
#define ARCANEAGT_SECRULE_H

#include <string>
#include <vector>
#include <sstream>
#include <boost/beast.hpp>
#include <boost/regex.hpp>

#include "scanner/Scanner.h"
using namespace boost::beast;



#define CRIT_VALUE  5
#define WARN_VALUE  4

using request = http::request<http::string_body>;
using response = http::response<http::string_body>;



    namespace arcane::scanner {


        namespace rules {

            class SecRule {
            public:
                SecRule(Scanner* ctx) : ctx(ctx) {}

                virtual void exec(request& req) {
                    std::cout << "Unimplemented rule encountered" << std::endl;
                };
                virtual void exec(response& req) {
                    std::cout << "Unimplemented rule encountered" << std::endl;
                }

            protected:
                // rules are managed by this
                // we need this to set the vars
                arcane::scanner::Scanner* ctx;
                std::string msg;
                int phase;
                bool block;
                bool capture;
                std::string logData;
                std::vector<std::string> tags;
                std::string version;
                bool expectsRequest = true;

            protected:
                std::string request_line(request& req) {
                    std::stringstream s;
                    s << req;
                    std::string line;

                    if (std::getline(s, line)) {
                        return line;
                    }

                    return "";
                }
            };
        }
    }

// arcane

#endif //ARCANEAGT_SECRULE_H
