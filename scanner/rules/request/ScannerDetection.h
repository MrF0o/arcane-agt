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
                                std::cout << "Found User-Agent associated with security scanner" << std::endl;
                                ctx->add_inbound_anomaly_score(CRIT_VALUE);
                                // block the bot by calling ctx
                            }
                        }
                    }

                } catch (std::out_of_range &exc) {
                    std::cout << "Get a request without a user-agent string" << std::endl;
                }

            }
        }
    };
}
#endif //ARCANEAGT_SCANNERDETECTION_H
