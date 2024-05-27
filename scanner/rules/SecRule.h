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
#include <spdlog/spdlog.h>

#include "scanner/Scanner.h"
#include "api/ApiWrapper.h"

using namespace boost::beast;


#define CRIT_VALUE  5
#define WARN_VALUE  4

using request = http::request<http::string_body>;
using response = http::response<http::string_body>;

struct RegRun {
    std::string matched_var = "";
    std::string matched_varname = "";
    std::string matched_value = "";
};

namespace arcane::scanner::rules {

    class SecRule {
    public:
        SecRule(Scanner *ctx) : ctx(ctx) {}

        virtual void exec(request &req) {
            std::cout << "Unimplemented rule encountered" << std::endl;
        };

        virtual void exec(response &req) {
            std::cout << "Unimplemented rule encountered" << std::endl;
        }

    protected:
        // rules are managed by this
        // we need this to set the vars
        arcane::scanner::Scanner *ctx;
        std::string msg;
        int phase;
        bool block;
        bool capture;
        std::string logData;
        std::vector<std::string> tags;
        std::string version;
        bool expectsRequest = true;

    protected:
        ::request* current_req = nullptr;
        std::string request_line(request &req) {
            std::stringstream s;
            s << req;
            std::string line;
            std::cout << s.str() << std::endl;
            if (std::getline(s, line)) {
                return line;
            }

            return "";
        }

        std::vector<std::string> request_cookies(request &req) {
            std::vector<std::string> cookies;
            if (req.base().count(http::field::cookie)) {
                std::string cookieHeader = req.base().at(http::field::cookie);

                size_t pos = 0;
                while ((pos = cookieHeader.find("; ")) != std::string::npos) {
                    std::string cookie = cookieHeader.substr(0, pos);
                    size_t eqPos = cookie.find('=');
                    if (eqPos != std::string::npos) {
                        cookie = cookie.substr(eqPos + 1);
                        cookies.push_back(cookie);
                    }
                    cookieHeader.erase(0, pos + 2);
                }
                size_t eqPos = cookieHeader.find('=');
                if (eqPos != std::string::npos) {
                    std::string cookie = cookieHeader.substr(eqPos + 1);
                    cookies.push_back(cookie);
                }
            }
            return cookies;
        }

        std::vector<std::string> request_cookies_names(request &req) {
            std::vector<std::string> cookies_names;
            if (req.base().count(http::field::cookie)) {
                std::string cookieHeader = req.base().at(http::field::cookie);

                size_t pos = 0;
                while ((pos = cookieHeader.find("; ")) != std::string::npos) {
                    std::string cookie = cookieHeader.substr(0, pos);

                    size_t eqPos = cookie.find('=');
                    if (eqPos != std::string::npos) {
                        std::string cookieName = cookie.substr(0, eqPos);
                        cookies_names.push_back(cookieName);
                    }
                    cookieHeader.erase(0, pos + 2);
                }

                size_t eqPos = cookieHeader.find('=');
                if (eqPos != std::string::npos) {
                    std::string cookieName = cookieHeader.substr(0, eqPos);
                    cookies_names.push_back(cookieName);
                }
            }
            return cookies_names;
        }
        std::vector<std::string> request_args_names(request &req) {
            std::vector<std::string> args_names;
            std::string target = req.target();
            // Parse the target URL to extract request parameters
            size_t pos = target.find('?');
            if (pos != std::string::npos) {
                std::string queryString = target.substr(pos + 1);
                // Split the queryString to extract parameter names
                size_t prevPos = 0;
                while ((pos = queryString.find('&', prevPos)) != std::string::npos) {
                    std::string arg = queryString.substr(prevPos, pos - prevPos);
                    size_t eqPos = arg.find('=');
                    if (eqPos != std::string::npos) {
                        std::string argName = arg.substr(0, eqPos);
                        args_names.push_back(argName);
                    }
                    prevPos = pos + 1; // Move past the current parameter and delimiter
                }
                // Process the last parameter
                std::string lastArg = queryString.substr(prevPos);
                size_t eqPos = lastArg.find('=');
                if (eqPos != std::string::npos) {
                    std::string argName = lastArg.substr(0, eqPos);
                    args_names.push_back(argName);
                }
            }
            return args_names;
        }
        std::vector<std::string> request_args(request &req) {
            std::vector<std::string> args;
            std::string target = req.target();
            size_t pos = target.find('?');
            if (pos != std::string::npos) {
                std::string queryString = target.substr(pos + 1);
                size_t prevPos = 0;
                while ((pos = queryString.find('&', prevPos)) != std::string::npos) {
                    std::string arg = queryString.substr(prevPos, pos - prevPos);
                    size_t eqPos = arg.find('=');
                    if (eqPos != std::string::npos) {
                        arg = arg.substr(eqPos + 1);
                        args.push_back(arg);
                    }
                    prevPos = pos + 1;
                }

                std::string lastArg = queryString.substr(prevPos);
                size_t eqPos = lastArg.find('=');
                if (eqPos != std::string::npos) {
                    std::string arg = lastArg.substr(eqPos + 1);
                    args.push_back(arg);
                }
            }
            return args;
        }


    };
}


// arcane

#endif //ARCANEAGT_SECRULE_H
