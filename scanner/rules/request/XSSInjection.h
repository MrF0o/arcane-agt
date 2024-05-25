//
// Created by fathi on 5/24/2024.
//

#ifndef ARCANEAGT_XSSINJECTION_H
#define ARCANEAGT_XSSINJECTION_H


#include "scanner/Scanner.h"
#include "scanner/ScannerConfig.h"
#include "api/ApiWrapper.h"
#include <fstream>
#include <boost/algorithm/string.hpp>
#include <boost/url.hpp>
#include "libinjection.h"
#include "libinjection_xss.h"

using namespace arcane::scanner;
using namespace arcane::api;
using namespace boost;

namespace arcane::scanner::rules::request {
    class XSSInjection : public SecRule {
    public:
        XSSInjection(Scanner *ctx) : SecRule(ctx) {}

        void exec(::request &req) override {
            this->current_req = &req;
            std::stringstream ss;
            ss << req;

            auto cookies = request_cookies(req);
            auto cookie_names = request_cookies_names(req);
            // auto args = request_args(req);
            // auto args_names = request_args_names(req);
            urls::url_view u(req.target());

            for (int i = 0; i < cookies.size(); i++) {
                if (runOnString("cookie", cookie_names[i], cookie_names[i])) {
                    warn();
                }

                if (runOnString("cookie", cookie_names[i], cookies[i])) {
                    warn();
                }

                if (libinjection_is_xss(cookie_names[i].c_str(), cookie_names[i].size(), FLAG_NONE)) {
                    warnLibInject();
                }

                if (libinjection_is_xss(cookies[i].c_str(), cookies[i].size(), FLAG_NONE)) {
                    warnLibInject();
                }
            }

            for (auto arg: u.params()) {
                auto a = arg.key + "=" + arg.value;
                if (runOnString("arg", arg.key, arg.key) || runOnString("arg", arg.key, arg.value)) {
                    warn();
                }

                if (libinjection_is_xss(a.c_str(), a.size(), FLAG_NONE)) {
                    warnLibInject();
                }
            }

            auto body = req.body();

            // request body
            if (runOnString("body", body, body)) {
                warn();
            }

            if (libinjection_is_xss(body.c_str(), body.size(), FLAG_NONE)) {
                warnLibInject();
            }
        }

        void warn() {
            spdlog::warn(
                    "XSS Injection detected; user ip: " + std::string(this->current_req->base().at("X-Forwarded-For")));
        }

        void warnLibInject() {
            spdlog::warn("[LibInjection] {} {}", "XSS Injection detected; user ip: ",
                         std::string(this->current_req->base().at("X-Forwarded-For")));
        }

        bool runOnString(const std::string &varkind, const std::string &var_name, const std::string &var_value) {
            std::vector<std::string> patterns = {
                    R"((?i)<script[^>]*>[\s\S]*?)",
                    R"((?i).(?:\b(?:x(?:link:href|html|mlns)|data:text/html|formaction|pattern\b.*?=)|!ENTITY[\s\x0b]+(?:%[\s\x0b]+)?[^\s\x0b]+[\s\x0b]+(?:SYSTEM|PUBLIC)|@import|;base64)\b)",
                    R"((?i)[a-z]+=(?:[^:=]+:.+;)*?[^:=]+:url\(javascript)",
                    R"((?i)<[^0-9<>A-Z_a-z]*(?:[^\s\x0b\"'<>]*:)?[^0-9<>A-Z_a-z]*[^0-9A-Z_a-z]*?(?:s[^0-9A-Z_a-z]*?(?:c[^0-9A-Z_a-z]*?r[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?p[^0-9A-Z_a-z]*?t|t[^0-9A-Z_a-z]*?y[^0-9A-Z_a-z]*?l[^0-9A-Z_a-z]*?e|v[^0-9A-Z_a-z]*?g|e[^0-9A-Z_a-z]*?t[^0-9>A-Z_a-z])|f[^0-9A-Z_a-z]*?o[^0-9A-Z_a-z]*?r[^0-9A-Z_a-z]*?m|d[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?a[^0-9A-Z_a-z]*?l[^0-9A-Z_a-z]*?o[^0-9A-Z_a-z]*?g|m[^0-9A-Z_a-z]*?(?:a[^0-9A-Z_a-z]*?r[^0-9A-Z_a-z]*?q[^0-9A-Z_a-z]*?u[^0-9A-Z_a-z]*?e[^0-9A-Z_a-z]*?e|e[^0-9A-Z_a-z]*?t[^0-9A-Z_a-z]*?a[^0-9>A-Z_a-z])|(?:l[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?n[^0-9A-Z_a-z]*?k|o[^0-9A-Z_a-z]*?b[^0-9A-Z_a-z]*?j[^0-9A-Z_a-z]*?e[^0-9A-Z_a-z]*?c[^0-9A-Z_a-z]*?t|e[^0-9A-Z_a-z]*?m[^0-9A-Z_a-z]*?b[^0-9A-Z_a-z]*?e[^0-9A-Z_a-z]*?d|a[^0-9A-Z_a-z]*?(?:p[^0-9A-Z_a-z]*?p[^0-9A-Z_a-z]*?l[^0-9A-Z_a-z]*?e[^0-9A-Z_a-z]*?t|u[^0-9A-Z_a-z]*?d[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?o|n[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?m[^0-9A-Z_a-z]*?a[^0-9A-Z_a-z]*?t[^0-9A-Z_a-z]*?e)|p[^0-9A-Z_a-z]*?a[^0-9A-Z_a-z]*?r[^0-9A-Z_a-z]*?a[^0-9A-Z_a-z]*?m|i?[^0-9A-Z_a-z]*?f[^0-9A-Z_a-z]*?r[^0-9A-Z_a-z]*?a[^0-9A-Z_a-z]*?m[^0-9A-Z_a-z]*?e|b[^0-9A-Z_a-z]*?(?:a[^0-9A-Z_a-z]*?s[^0-9A-Z_a-z]*?e|o[^0-9A-Z_a-z]*?d[^0-9A-Z_a-z]*?y|i[^0-9A-Z_a-z]*?n[^0-9A-Z_a-z]*?d[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?n[^0-9A-Z_a-z]*?g[^0-9A-Z_a-z]*?s)|i[^0-9A-Z_a-z]*?m[^0-9A-Z_a-z]*?a?[^0-9A-Z_a-z]*?g[^0-9A-Z_a-z]*?e?|v[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?d[^0-9A-Z_a-z]*?e[^0-9A-Z_a-z]*?o)[^0-9>A-Z_a-z])|(?:<[0-9A-Z_a-z].*[\s\x0b/]|[\"'](?:.*[\s\x0b/])?)(?:background|formaction|lowsrc|on(?:a(?:bort|ctivate|d(?:apteradded|dtrack)|fter(?:print|(?:scriptexecu|upda)te)|lerting|n(?:imation(?:cancel|end|iteration|start)|tennastatechange)|ppcommand|u(?:dio(?:end|process|start)|xclick))|b(?:e(?:fore(?:(?:(?:(?:de)?activa|scriptexecu)t|toggl)e|c(?:opy|ut)|editfocus|input|p(?:aste|rint)|u(?:nload|pdate))|gin(?:Event)?)|l(?:ocked|ur)|oun(?:ce|dary)|roadcast|usy)|c(?:a(?:(?:ch|llschang)ed|nplay(?:through)?|rdstatechange)|(?:ell|fstate)change|h(?:a(?:rging(?:time)?cha)?nge|ecking)|l(?:ick|ose)|o(?:m(?:mand(?:update)?|p(?:lete|osition(?:end|start|update)))|n(?:nect(?:ed|ing)|t(?:extmenu|rolselect))|py)|u(?:echange|t))|d(?:ata(?:(?:availabl|chang)e|error|setc(?:hanged|omplete))|blclick|e(?:activate|livery(?:error|success)|vice(?:found|light|(?:mo|orienta)tion|proximity))|i(?:aling|s(?:abled|c(?:hargingtimechange|onnect(?:ed|ing))))|o(?:m(?:a(?:ctivate|ttrmodified)|(?:characterdata|subtree)modified|focus(?:in|out)|mousescroll|node(?:inserted(?:intodocument)?|removed(?:fromdocument)?))|wnloading)|r(?:ag(?:drop|e(?:n(?:d|ter)|xit)|(?:gestur|leav)e|over|start)|op)|urationchange)|e(?:mptied|n(?:abled|d(?:ed|Event)?|ter)|rror(?:update)?|xit)|f(?:ailed|i(?:lterchange|nish)|o(?:cus(?:in|out)?|rm(?:change|input))|ullscreenchange)|g(?:amepad(?:axismove|button(?:down|up)|(?:dis)?connected)|et)|h(?:ashchange|e(?:adphoneschange|l[dp])|olding)|i(?:cc(?:cardlockerror|infochange)|n(?:coming|put|valid))|key(?:down|press|up)|l(?:evelchange|o(?:ad(?:e(?:d(?:meta)?data|nd)|start)?|secapture)|y)|m(?:ark|essage|o(?:use(?:down|enter|(?:lea|mo)ve|o(?:ut|ver)|up|wheel)|ve(?:end|start)?|z(?:a(?:fterpaint|udioavailable)|(?:beforeresiz|orientationchang|t(?:apgestur|imechang))e|(?:edgeui(?:c(?:ancel|omplet)|start)e|network(?:down|up)loa)d|fullscreen(?:change|error)|m(?:agnifygesture(?:start|update)?|ouse(?:hittest|pixelscroll))|p(?:ointerlock(?:change|error)|resstapgesture)|rotategesture(?:start|update)?|s(?:crolledareachanged|wipegesture(?:end|start|update)?))))|no(?:match|update)|o(?:(?:bsolet|(?:ff|n)lin)e|pen|verflow(?:changed)?)|p(?:a(?:ge(?:hide|show)|int|(?:st|us)e)|lay(?:ing)?|o(?:inter(?:down|enter|(?:(?:lea|mo)v|rawupdat)e|o(?:ut|ver)|up)|p(?:state|up(?:hid(?:den|ing)|show(?:ing|n))))|ro(?:gress|pertychange))|r(?:atechange|e(?:adystatechange|ceived|movetrack|peat(?:Event)?|quest|s(?:et|ize|u(?:lt|m(?:e|ing)))|trieving)|ow(?:e(?:nter|xit)|s(?:delete|inserted)))|s(?:croll(?:end)?|e(?:arch|ek(?:complete|ed|ing)|lect(?:ionchange|start)?|n(?:ding|t)|t)|how|(?:ound|peech)(?:end|start)|t(?:a(?:lled|rt|t(?:echange|uschanged))|k(?:comma|sessione)nd|op)|u(?:bmit|ccess|spend)|vg(?:abort|error|(?:un)?load|resize|scroll|zoom))|t(?:ext|ime(?:out|update)|o(?:ggle|uch(?:cancel|en(?:d|ter)|(?:lea|mo)ve|start))|ransition(?:cancel|end|run|start))|u(?:n(?:derflow|handledrejection|load)|p(?:dateready|gradeneeded)|s(?:erproximity|sdreceived))|v(?:ersion|o(?:ic|lum)e)change|w(?:a(?:it|rn)ing|ebkit(?:animation(?:end|iteration|start)|transitionend)|heel)|zoom)|ping|s(?:rc|tyle))[\x08-\n\f\r ]*?=)",
                    R"((?i)(?:\W|^)(?:javascript:(?:[\s\S]+[=\x5c\(\[\.<]|[\s\S]*?(?:\bname\b|\x5c[ux]\d))|data:(?:(?:[a-z]\w+/\w[\w+-]+\w)?[;,]|[\s\S]*?;[\s\S]*?\b(?:base64|charset=)|[\s\S]*?,[\s\S]*?<[\s\S]*?\w[\s\S]*?>))|@\W*?i\W*?m\W*?p\W*?o\W*?r\W*?t\W*?(?:/\*[\s\S]*?)?(?:[\"']|\W*?u\W*?r\W*?l[\s\S]*?\()|[^-]*?-\W*?m\W*?o\W*?z\W*?-\W*?b\W*?i\W*?n\W*?d\W*?i\W*?n\W*?g[^:]*?:\W*?u\W*?r\W*?l[\s\S]*?\()",
                    R"((?i:<style.*?>.*?(?:@[i\x5c]|(?:[:=]|&#x?0*(?:58|3A|61|3D);?).*?(?:[(\x5c]|&#x?0*(?:40|28|92|5C);?))))",
                    R"((?i:<.*[:]?vmlframe.*?[\s/+]*?src[\s/+]*=))",
                    R"((?i)(?:j|&#(?:0*(?:74|106)|x0*[46]A);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:a|&#(?:0*(?:65|97)|x0*[46]1);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:v|&#(?:0*(?:86|118)|x0*[57]6);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:a|&#(?:0*(?:65|97)|x0*[46]1);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:s|&#(?:0*(?:115|83)|x0*[57]3);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:c|&#(?:x0*[46]3|0*(?:99|67));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:r|&#(?:x0*[57]2|0*(?:114|82));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:i|&#(?:x0*[46]9|0*(?:105|73));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:p|&#(?:x0*[57]0|0*(?:112|80));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:t|&#(?:x0*[57]4|0*(?:116|84));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?::|&(?:#(?:0*58|x0*3A);?|colon;)).)",
                    R"((?i)(?:v|&#(?:0*(?:118|86)|x0*[57]6);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:b|&#(?:0*(?:98|66)|x0*[46]2);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:s|&#(?:0*(?:115|83)|x0*[57]3);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:c|&#(?:x0*[46]3|0*(?:99|67));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:r|&#(?:x0*[57]2|0*(?:114|82));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:i|&#(?:x0*[46]9|0*(?:105|73));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:p|&#(?:x0*[57]0|0*(?:112|80));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:t|&#(?:x0*[57]4|0*(?:116|84));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?::|&(?:#(?:0*58|x0*3A);?|colon;)).)",
                    R"((?i)<EMBED[\s/+].*?(?:src|type).*?=)",
                    R"(<[?]?import[\s/+\S]*?implementation[\s/+]*?=)",
                    R"((?i:<META[\s/+].*?http-equiv[\s/+]*=[\s/+]*[\"'`]?(?:(?:c|&#x?0*(?:67|43|99|63);?)|(?:r|&#x?0*(?:82|52|114|72);?)|(?:s|&#x?0*(?:83|53|115|73);?))))",
                    R"((?i:<META[\s/+].*?charset[\s/+]*=))",
                    R"((?i)<LINK[\s/+].*?href[\s/+]*=)",
                    R"((?i)<BASE[\s/+].*?href[\s/+]*=)",
                    R"((?i)<APPLET[\s/+>])",
                    R"((?i)<OBJECT[\s/+].*?(?:type|codetype|classid|code|data)[\s/+]*=)",
                    R"((?:\xbc\s*/\s*[^\xbe>]*[\xbe>])|(?:<\s*/\s*[^\xbe]*\xbe))",
                    R"(\+ADw-.*(?:\+AD4-|>)|<.*\+AD4-)",
                    R"(![!+ ]\[\])",
                    R"((?:self|document|this|top|window)\s*(?:/\*|[\[)]).+?(?:\]|\*/))",
                    R"((?i)\b(?:eval|set(?:timeout|interval)|new[\s\x0b]+Function|a(?:lert|tob)|btoa|prompt|confirm)[\s\x0b]*\()",
                    R"(((?:\[[^\]]*\][^.]*\.)|Reflect[^.]*\.).*(?:map|sort|apply)[^.]*\..*call[^`]*`.*`)",
                    R"((?i)[\s\"'`;/0-9=\x0B\x09\x0C\x3B\x2C\x28\x3B]on[a-zA-Z]{3,25}[\s\x0B\x09\x0C\x3B\x2C\x28\x3B]*?=[^=])",
                    R"((?i)\b(?:s(?:tyle|rc)|href)\b[\s\S]*?=)",
                    R"(<(?:a|abbr|acronym|address|applet|area|audioscope|b|base|basefront|bdo|bgsound|big|blackface|blink|blockquote|body|bq|br|button|caption|center|cite|code|col|colgroup|comment|dd|del|dfn|dir|div|dl|dt|em|embed|fieldset|fn|font|form|frame|frameset|h1|head|hr|html|i|iframe|ilayer|img|input|ins|isindex|kdb|keygen|label|layer|legend|li|limittext|link|listing|map|marquee|menu|meta|multicol|nobr|noembed|noframes|noscript|nosmartquotes|object|ol|optgroup|option|p|param|plaintext|pre|q|rt|ruby|s|samp|script|select|server|shadow|sidebar|small|spacer|span|strike|strong|style|sub|sup|table|tbody|td|textarea|tfoot|th|thead|title|tr|tt|u|ul|var|wbr|xml|xmp)\W)",
                    R"((?i:[\"'][ ]*(?:[^a-z0-9~_:' ]|in).*?(?:(?:l|\x5cu006C)(?:o|\x5cu006F)(?:c|\x5cu0063)(?:a|\x5cu0061)(?:t|\x5cu0074)(?:i|\x5cu0069)(?:o|\x5cu006F)(?:n|\x5cu006E)|(?:n|\x5cu006E)(?:a|\x5cu0061)(?:m|\x5cu006D)(?:e|\x5cu0065)|(?:o|\x5cu006F)(?:n|\x5cu006E)(?:e|\x5cu0065)(?:r|\x5cu0072)(?:r|\x5cu0072)(?:o|\x5cu006F)(?:r|\x5cu0072)|(?:v|\x5cu0076)(?:a|\x5cu0061)(?:l|\x5cu006C)(?:u|\x5cu0075)(?:e|\x5cu0065)(?:O|\x5cu004F)(?:f|\x5cu0066)).*?=))",
                    R"((?i)[\"\'][ ]*(?:[^a-z0-9~_:\' ]|in).+?[.].+?=)",
                    R"({{.*?}})",
            };

            for (const auto &pattern: patterns) {
                boost::regex regex(pattern);
                boost::smatch match;
                if (boost::regex_search(var_value, match, regex)) {
                    scanner::Scanner::isBlocked = true;
                    ApiWrapper::log("CRITICAL", "XSS Attempt blocked", var_name, varkind,
                                    std::string(match[0].first, match[0].second),
                                    this->current_req->at("X-Forwarded-For"));
                    return true;
                }
            }

            return false;

        }
    };
}

#endif //ARCANEAGT_XSSINJECTION_H
