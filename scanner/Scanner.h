//
// Created by fathi on 3/12/2024.
//

#ifndef ARCANEAGT_SCANNER_H
#define ARCANEAGT_SCANNER_H

#include <memory>
#include <boost/beast.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "ScanResult.h"

using namespace boost::beast;
namespace pt = boost::property_tree;

namespace arcane::scanner {
    class SecRule;

    class Scanner {
    public:
        static pt::ptree config;
        static pt::ptree webConfig;
        static bool isBlocked;

        bool scan_inbound(http::request<http::string_body> &request);

        bool scan_outbound(http::response<http::string_body> &response);

        inline int get_detection_paranoia_level() const { return detection_paranoia_level; }

        bool passRequest();

        void add_inbound_anomaly_score(int i);

    private:
        unsigned int inbound_threshold = 5;
        unsigned int outbound_threshold = 5;
        unsigned int inbound_anomaly = 0;
        unsigned int detection_paranoia_level = 2;
        bool shouldPassRequest = false;
    };
} // scanner
// arcane

#endif //ARCANEAGT_SCANNER_H
