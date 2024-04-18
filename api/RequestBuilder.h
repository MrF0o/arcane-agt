//
// Created by fathi on 4/18/2024.
//

#ifndef ARCANEAGT_REQUESTBUILDER_H
#define ARCANEAGT_REQUESTBUILDER_H

#include <boost/beast.hpp>
using namespace boost::beast;

namespace arcane::api {
    class RequestBuilder {
    public:
        http::request<http::string_body> buildPost() {}

        http::request<http::empty_body> buildGet() {}

        http::request<http::string_body> buildOAuthCheckRequest() {

        }
    };
}

#endif //ARCANEAGT_REQUESTBUILDER_H
