//
// Created by fathi on 4/5/2024.
//


#include "scanner/rules/rules.h"

std::vector<rules::SecRule *> rs_in(Scanner *ctx) {
    return {
            // REQUEST-COMMON-EXCEPTIONS
            new rules::request::CommonExceptions(ctx),
            // REQUEST-METHOD-ENFORCEMENT
            new rules::request::MethodEnforcement(ctx),
            // REQUEST-SCANNER-DETECTION
            new rules::request::ScannerDetection(ctx),
            // REQUEST-PROTOCOL-ENFORCEMENT
            new rules::request::ProtocolEnforcement(ctx),
            // REQUEST-ATTACK-SQLI
            new rules::request::SQLInjection(ctx),
            // REQUEST-ATTACK-XSS
            new rules::request::XSSInjection(ctx)
    };
};

std::vector<rules::SecRule *> rs_out(Scanner *ctx) {
    return {
            // ======================
            // Response specific rules
            // ======================
            new rules::response::WebShells(ctx),
    };
};

