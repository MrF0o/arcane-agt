//
// Created by fathi on 4/5/2024.
//

#ifndef ARCANEAGT_SECRULE_H
#define ARCANEAGT_SECRULE_H

#include <string>
#include <vector>
#include <sstream>
#include <boost/beast.hpp>
using namespace boost::beast;

using request = http::request<http::string_body>;

namespace arcane {

    namespace scanner {

        class Scanner;

        namespace rules {

            enum severity {
                SV_UNSPEC,
                SV_NOTICE = 2,
                SV_WARNING,
                SV_ERROR,
                SV_CRITICAL,
            };

            enum Scans {
                SCAN_NOSCAN,
                SCAN_INBOUND,
                SCAN_OUTBOUND
            };

            class SecRule {
            public:

                virtual void exec(request& req) = 0;
            private:
                // rules are managed by this
                // we need this to set the vars
                Scanner* ctx;
                int severity_level  = SV_UNSPEC;
                int scans = SCAN_NOSCAN;
                std::string msg;
                int phase;
                bool block;
                bool capture;
                std::string logData;
                std::vector<std::string> tags;
                std::string version;

            protected:
                std::string request_line(request& req) {
                    std::stringstream s;
                    s << req;
                    std::string line;

                    if (std::getline(s, line)) {
                        return line;
                    }

                    return "";
                }

                bool ip_match(std::string, ...) {
                    return false;
                }
            };
        }
    }

} // arcane

#endif //ARCANEAGT_SECRULE_H
