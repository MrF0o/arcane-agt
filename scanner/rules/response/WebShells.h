//
// Created by fathi on 5/4/2024.
//

#ifndef ARCANEAGT_WEBSHELLS_H
#define ARCANEAGT_WEBSHELLS_H

#include "scanner/Scanner.h"
#include "scanner/ScannerConfig.h"
#include "api/ApiWrapper.h"

using namespace arcane::scanner;
using namespace arcane::api;


namespace arcane::scanner::rules::response {
    class WebShells: public SecRule {
    public:
        explicit WebShells(Scanner* ctx) : SecRule(ctx) {
            this->expectsRequest = false;
        }

        // this rule is intended for php webshells
        void exec(::response& res) {
            if (ctx->get_detection_paranoia_level() >= 1) {
                std::cout << res.base();
                if (res.find("Content-Type")->value().contains("text/html")) {
                    std::cout << "yess";
                    std::ifstream shells("../coreruleset/rules/web-shells-php.data");
                    if  (shells.is_open()) {
                        std::cout << "opened shells" << std::endl;
                        std::string line = "";

                        while (std::getline(shells, line)) {
                            boost::algorithm::trim(line);
                            if ((line[0] != '#') && !line.empty() && (res.body().find(line) != std::string::npos)) {
                                std::cout << "webshell detected: " << line << std::endl;
                                // TODO: Log data
                            }
                        }
                    }
                }
            }
        }
    };
}

#endif //ARCANEAGT_WEBSHELLS_H
