//
// Created by fathi on 4/13/2024.
//

#ifndef ARCANEAGT_SCANNERDETECTION_H
#define ARCANEAGT_SCANNERDETECTION_H

#include "scanner/Scanner.h"
#include "scanner/ScannerConfig.h"
#include "api/ApiWrapper.h"
#include <fstream>
#include <boost/algorithm/string.hpp>

using namespace arcane::scanner;
using namespace arcane::api;

namespace arcane::scanner::rules::request {
    class ScannerDetection : public SecRule {
    public:
        ScannerDetection(Scanner *ctx) : SecRule(ctx) {}

        void exec(::request &req) {
            if (ctx->get_detection_paranoia_level() >= 1) {
                std::ifstream scannerDat("../coreruleset/rules/scanners-user-agents.data");
                std::string line = "";

                try {
                    auto userAgent = (std::string)req.at("User-Agent");

                    while (std::getline(scannerDat, line)) {
                        boost::trim(line);
                        boost::trim(userAgent);
                        if (line[0] != '#') {
                            if (line == userAgent) {
                                spdlog::warn("Found User-Agent associated with security scanner");
                                ApiWrapper::log("WARNING", "Found User-Agent associated with security scanner", "User-Agent", "header", userAgent, req.base().at("X-Forwarded-For"));
                                scanner::Scanner::isBlocked = true;
                            }
                        }
                    }

                } catch (std::out_of_range &exc) {
                    spdlog::warn("Got a request without a User-Agent string");
                    ApiWrapper::log("WARNING", "Got a request without a User-Agent string", "User-Agent", "header", "", req.base().at("X-Forwarded-For"));
                    scanner::Scanner::isBlocked = true;
                }

            }
        }
    };
}
#endif //ARCANEAGT_SCANNERDETECTION_H
