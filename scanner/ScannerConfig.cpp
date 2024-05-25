//
// Created by fathi on 4/12/2024.
//

#include "scanner/ScannerConfig.h"

using namespace arcane::scanner;

// HTTP methods that a client is allowed to use.
std::string ScannerConfig::allowed_methods = "GET HEAD POST OPTIONS PATCH DELETE PUT";