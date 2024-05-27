//
// Created by fathi on 5/3/2024.
//

#ifndef ARCANEAGT_PROTOCOLENFORCEMENT_H
#define ARCANEAGT_PROTOCOLENFORCEMENT_H

#include "scanner/Scanner.h"
#include "scanner/ScannerConfig.h"
#include "api/ApiWrapper.h"
#include <fstream>
#include <boost/algorithm/string.hpp>

using namespace arcane::scanner;
using namespace arcane::api;

namespace arcane::scanner::rules::request {
    class ProtocolEnforcement : public SecRule {
    public:
        ProtocolEnforcement(Scanner *ctx) : SecRule(ctx) {}

        void exec(::request &req) override {
            validateRequestLine(req);
        }

        bool validateRequestLine(::request &req) {
            boost::regex rx(
                    R"((?i)^(?:get /[^#\?]*(?:\?[^\s\x0b#]*)?(?:#[^\s\x0b]*)?|(?:connect (?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}\.?(?::[0-9]+)?|[\--9A-Z_a-z]+:[0-9]+)|options \*|[a-z]{3,10}[\s\x0b]+(?:[0-9A-Z_a-z]{3,7}?://[\--9A-Z_a-z]*(?::[0-9]+)?)?/[^#\?]*(?:\?[^\s\x0b#]*)?(?:#[^\s\x0b]*)?)[\s\x0b]+[\.-9A-Z_a-z]+))");

            if (!boost::regex_match(request_line(req), rx)) {
                ApiWrapper::log("CRITICAL", "Got a request with an invalid HTTP Request Line", "Request-Line", "base", request_line(req), req.base().at("X-Forwarded-For"));
                spdlog::warn("Got a request with an invalid HTTP Request Line");
                scanner::Scanner::isBlocked = true;
                // ctx->add_inbound_anomaly_score(WARN_VALUE);
                return true;
            }

            return false;
        }
    };
}

#endif //ARCANEAGT_PROTOCOLENFORCEMENT_H
