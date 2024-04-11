//
// Created by fathi on 4/5/2024.
//

#ifndef ARCANEAGT_RULES_H
#define ARCANEAGT_RULES_H

#endif //ARCANEAGT_RULES_H

#include "scanner/rules/SecRule.h"
#include "scanner/rules/request/ExSSLPinger.h"
#include "scanner/rules/request/ExApacheInterConn.h"

using namespace arcane::scanner::rules;

extern std::vector<SecRule*> rs;