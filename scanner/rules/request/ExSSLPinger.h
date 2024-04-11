//
// Created by fathi on 4/5/2024.
//

#ifndef ARCANEAGT_EXSSLPINGER_H
#define ARCANEAGT_EXSSLPINGER_H

#include "scanner/rules/SecRule.h"
#include <boost/beast.hpp>

using namespace boost::beast;

#include <iostream>


namespace arcane::scanner::rules::request {
    class ExSSLPinger : public SecRule {
    public:
        void exec(::request& req) override {
            if (request_line(req) == "GET /") {

            }
        }
    };
}


#endif //ARCANEAGT_EXSSLPINGER_H
