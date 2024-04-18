//
// Created by fathi on 4/5/2024.
//

#ifndef ARCANEAGT_RULES_H
#define ARCANEAGT_RULES_H

#endif //ARCANEAGT_RULES_H

#include "scanner/rules/SecRule.h"
#include "scanner/rules/request/CommonExceptions.h"
#include "scanner/rules/request/MethodEnforcement.h"
#include "scanner/rules/request/ScannerDetection.h"

using namespace arcane::scanner;

extern std::vector<rules::SecRule*> rs(Scanner* ctx);