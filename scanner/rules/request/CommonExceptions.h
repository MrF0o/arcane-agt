//
// Created by fathi on 4/5/2024.
//

#ifndef ARCANEAGT_COMMONEXCEPTIONS_H
#define ARCANEAGT_COMMONEXCEPTIONS_H

#include "scanner/rules/SecRule.h"
#include <boost/beast.hpp>

using namespace boost::beast;

#include <iostream>


namespace arcane::scanner::rules::request {
    class CommonExceptions : public SecRule {

    public:
        CommonExceptions(Scanner* ctx) : SecRule(ctx) {}

        void exec(::request& req) override {
            auto ip = req.base().at("X-Forwarded-For");
            auto user_agent = req.base().at("User-Agent");
            if (request_line(req) == "GET /") {
                if (ip == "127.0.0.1" || ip == "::1") {
                    ctx->passRequest();
                    return;
                }
            }

            if ((ip == "127.0.0.1" || ip == "::1") && (user_agent.ends_with("(internal dummy connection)"))) {
                static const auto re = "/^(?:GET /|OPTIONS \\*) HTTP/[12]\\.[01]$/gm";
                boost::regex base_reg(re);
                boost::match_results<std::string::const_iterator> matches;

                if (boost::regex_match(request_line(req), matches, base_reg)) {
                    ctx->passRequest();
                    // pass: no need to scan
                }
            }
        }
    };
}


#endif //ARCANEAGT_COMMONEXCEPTIONS_H
