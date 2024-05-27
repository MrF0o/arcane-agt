//
// Created by fathi on 4/11/2024.
//

#ifndef ARCANEAGT_METHODENFORCEMENT_H
#define ARCANEAGT_METHODENFORCEMENT_H

#include "scanner/Scanner.h"
#include "scanner/ScannerConfig.h"
#include "api/ApiWrapper.h"

using namespace arcane::scanner;
using namespace arcane::api;

namespace arcane::scanner::rules::request {
    class MethodEnforcement : public SecRule {
    public:
        MethodEnforcement(Scanner *ctx) : SecRule(ctx) {}

        void exec(::request &req) override {
            // check paranoia
            if (ctx->get_detection_paranoia_level() >= 1) {
                if (ScannerConfig::allowed_methods.find(req.method_string()) == std::string::npos) {
                    scanner::Scanner::isBlocked = true;
                    spdlog::warn("A request method is not allowed by policy");
                    ApiWrapper::log("CRITICAL", "Method is not allowed by policy", "request_method", "base",
                                    req.method_string(),
                                    req.at("X-Forwarded-For"));
                    ctx->add_inbound_anomaly_score(CRIT_VALUE);
                }
            }
        }
    };
}
#endif //ARCANEAGT_METHODENFORCEMENT_H
