//
// Created by fathi on 3/12/2024.
//

#include "Scanner.h"
#include <iostream>
#include "rules/rules.h"


namespace arcane {
    namespace scanner {
        api::ApiWrapper Scanner::api;

        std::unique_ptr<ScanResult> Scanner::scan_inbound(http::request<http::string_body>& request) {
            std::cout << "[Scanner] Scanning request" << std::endl;
            for (auto rule: rs(this)) {
                if (shouldPassRequest) break;

                rule->exec(request);
            }

            shouldPassRequest = false;
            return std::unique_ptr<ScanResult>();
        }

        std::unique_ptr<ScanResult> Scanner::scan_outbound(http::response<http::string_body>& response) {
            return std::unique_ptr<ScanResult>();
        }

        bool Scanner::passRequest() {
            shouldPassRequest = true;
        }

        void Scanner::add_inbound_anomaly_score(int i) {
            inbound_anomaly += i;
        }
    } // scanner
} // arcane