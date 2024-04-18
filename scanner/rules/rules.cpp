//
// Created by fathi on 4/5/2024.
//


#include "scanner/rules/rules.h"

std::vector<rules::SecRule*> rs(Scanner* ctx) {
        return {
                // REQUEST-COMMON-EXCEPTIONS
                new rules::request::CommonExceptions(ctx),
                // REQUEST-METHOD-ENFORCEMENT
                new rules::request::MethodEnforcement(ctx),
                // REQUEST-SCANNER-DETECTION
                new rules::request::ScannerDetection(ctx),
        };
};