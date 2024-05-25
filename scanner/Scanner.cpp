//
// Created by fathi on 3/12/2024.
//

#include "Scanner.h"
#include <iostream>
#include "rules/rules.h"


namespace arcane {
    namespace scanner {
        pt::ptree Scanner::config;
        pt::ptree Scanner::webConfig;
        bool Scanner::isBlocked = false;

        bool Scanner::scan_inbound(http::request<http::string_body>& request) {
            for (auto rule: rs_in(this)) {
                if (shouldPassRequest) break;

                rule->exec(request);

                if (isBlocked) {
                    return true;
                }
            }

            shouldPassRequest = false;
            return false;
        }

        bool Scanner::scan_outbound(http::response<http::string_body>& response) {
            for (auto rule: rs_out(this)) {
                if (shouldPassRequest) break;

                rule->exec(response);

                if (isBlocked) {
                    return true;
                }
            }

            shouldPassRequest = false;

            return false;
        }

        bool Scanner::passRequest() {
            shouldPassRequest = true;

            return shouldPassRequest;
        }

        void Scanner::add_inbound_anomaly_score(int i) {
            inbound_anomaly += i;
        }
    } // scanner
} // arcane