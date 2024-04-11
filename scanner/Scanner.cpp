//
// Created by fathi on 3/12/2024.
//

#include "Scanner.h"
#include <iostream>


namespace arcane {
    namespace scanner {
        std::unique_ptr<ScanResult> Scanner::scan_inbound(http::request<http::string_body>& request) {
            std::cout << "[Scanner] Scanning request" << std::endl;
            for (auto rule: rs) {
                rule->exec(request);
            }
            return std::unique_ptr<ScanResult>();
        }

        std::unique_ptr<ScanResult> Scanner::scan_outbound(http::response<http::string_body>& response) {
            return std::unique_ptr<ScanResult>();
        }
    } // scanner
} // arcane