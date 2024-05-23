//
// Created by fathi on 5/4/2024.
//

#ifndef ARCANEAGT_ATTACKSQLI_H
#define ARCANEAGT_ATTACKSQLI_H

#include "scanner/rules/SecRule.h"
#include <boost/beast.hpp>

using namespace boost::beast;

#include <iostream>


namespace arcane::scanner::rules::request {
    class AttackSQLi : public SecRule {

    public:
        AttackSQLi(Scanner *ctx) :
                SecRule(ctx) {}

        void exec(::request& req) {
            request_cookies(req);
        }
    };
}
#endif //ARCANEAGT_ATTACKSQLI_H
