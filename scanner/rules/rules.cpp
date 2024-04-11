//
// Created by fathi on 4/5/2024.
//


#include "scanner/rules/rules.h"

std::vector<SecRule*> rs = {
        // REQUEST-COMMON-EXCEPTIONS
        new request::ExSSLPinger()
};