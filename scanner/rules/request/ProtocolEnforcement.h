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

        }

        bool validateRequestLine(const std::string& requestLine) {
            boost::regex rx(
                    "(?i)^(?:get /[^#\?]*(?:\?[^\s\x0b#]*)?(?:#[^\s\x0b]*)?|(?:connect (?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}\.?(?::[0-9]+)?|[\--9A-Z_a-z]+:[0-9]+)|options \*|[a-z]{3,10}[\s\x0b]+(?:[0-9A-Z_a-z]{3,7}?://[\--9A-Z_a-z]*(?::[0-9]+)?)?/[^#\?]*(?:\?[^\s\x0b#]*)?(?:#[^\s\x0b]*)?)[\s\x0b]+[\.-9A-Z_a-z]+)");

            if (boost::regex_match(requestLine, rx)) {
                std::cout << "Invalid HTTP Request Line" << std::endl;
                // ctx->add_inbound_anomaly_score(WARN_VALUE);
                return true;
            }

            return false;
        }

        bool nameEvadedFormData() {
            return false;
        }

        bool verifyContentLength() {
            return false;
        }

        bool verifyMethodBodyExists() {
            return false;
        }

        bool verifyContentLengthOrTransferEncoding() {
            return false;
        }

        bool verifyDuplicateConnectionHeaders() {
            return false;
        }

        bool verifyUrlEncoding() {

        }

        bool verifyArguments() {

        }

        bool verifyAllowedFileExtensions() {

        }

    };
}

#endif //ARCANEAGT_PROTOCOLENFORCEMENT_H
