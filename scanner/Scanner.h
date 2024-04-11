//
// Created by fathi on 3/12/2024.
//

#ifndef ARCANEAGT_SCANNER_H
#define ARCANEAGT_SCANNER_H

#include <memory>
#include <boost/beast.hpp>
#include "ScanResult.h"
#include "scanner/rules/SecRule.h"
#include "rules/rules.h"

using namespace boost::beast;

namespace arcane {
    namespace scanner {

        class Scanner {
        public:
            std::unique_ptr<ScanResult> scanTextAsHttpContent();
            std::unique_ptr<ScanResult> validateRequestHeaders();
            std::unique_ptr<ScanResult> validateResponseHeaders();

            std::unique_ptr<ScanResult> scan_inbound(http::request<http::string_body>& request);
            std::unique_ptr<ScanResult> scan_outbound(http::response<http::string_body>& response);

        private:
            unsigned int inbound_threshold;
            unsigned int outbound_threshold;
        };
    } // scanner
} // arcane

#endif //ARCANEAGT_SCANNER_H
