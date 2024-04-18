//
// Created by fathi on 4/13/2024.
//

#ifndef ARCANEAGT_SCANNERDETECTION_H
#define ARCANEAGT_SCANNERDETECTION_H
#include "scanner/Scanner.h"
#include "scanner/ScannerConfig.h"
#include "api/ApiWrapper.h"

using namespace arcane::scanner;
using namespace arcane::api;

namespace arcane::scanner::rules::request {
    class ScannerDetection : public SecRule {
    public:
        ScannerDetection(Scanner* ctx) : SecRule(ctx) {}

        void exec(::request& req) {}
    };
}
#endif //ARCANEAGT_SCANNERDETECTION_H
