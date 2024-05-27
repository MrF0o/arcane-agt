//
// Created by fathi on 4/16/2024.
//

#ifndef ARCANEAGT_SQLINJECTION_H
#define ARCANEAGT_SQLINJECTION_H

#include "scanner/Scanner.h"
#include "scanner/ScannerConfig.h"
#include "api/ApiWrapper.h"
#include <fstream>
#include <boost/algorithm/string.hpp>
#include <boost/url.hpp>
#include "libinjection.h"
#include "libinjection_sqli.h"

using namespace arcane::scanner;
using namespace arcane::api;
using namespace boost;

namespace arcane::scanner::rules::request {
    class SQLInjection : public SecRule {
    public:
        SQLInjection(Scanner *ctx) : SecRule(ctx) {}

        void exec(::request &req) {
            this->current_req = &req;
            std::stringstream ss;
            ss << req;

            auto cookies = request_cookies(req);
            auto cookie_names = request_cookies_names(req);
            // auto args = request_args(req);
            // auto args_names = request_args_names(req);
            urls::url_view u(req.target());

            for (auto &cookie: cookies) {
                libinjection_sqli_state state;
                libinjection_sqli_init(&state, cookie.c_str(), cookie.size(), FLAG_NONE);

                if (runOnString("cookie", cookie, cookie)) {
                    spdlog::warn("SQL Injection detected; user ip: " + std::string(req.base().at("X-Forwarded-For")));
                }

                if (libinjection_is_sqli(&state)) {
                    spdlog::warn("[LibInjection] {} {}", "SQL Injection detected; user ip: ",
                                 std::string(req.base().at("X-Forwarded-For")));
                }
            }

            for (auto &cname: cookie_names) {
                libinjection_sqli_state state;
                libinjection_sqli_init(&state, cname.c_str(), cname.size(), FLAG_NONE);

                if (runOnString("cookie_name", cname, cname)) {
                    spdlog::warn("SQL Injection detected; user ip: " + std::string(req.base().at("X-Forwarded-For")));
                }

                if (libinjection_is_sqli(&state)) {
                    spdlog::warn("[LibInjection] {} {}", "SQL Injection detected; user ip: ",
                                 std::string(req.base().at("X-Forwarded-For")));
                }
            }

            for (auto arg: u.params()) {
                auto a = arg.key + "=" + arg.value;
                if (runOnString("arg", arg.key, arg.key) || runOnString("arg_name", arg.key, arg.value)) {
                    spdlog::warn("SQL Injection detected; user ip: " + std::string(req.base().at("X-Forwarded-For")));
                }

                libinjection_sqli_state state;
                libinjection_sqli_init(&state, a.c_str(), a.size(), FLAG_NONE);

                if (libinjection_is_sqli(&state)) {
                    spdlog::warn("[LibInjection] {} {}", "SQL Injection detected; user ip: ",
                                 std::string(req.base().at("X-Forwarded-For")));
                }
            }

            auto body = req.body();
            libinjection_sqli_state state;
            libinjection_sqli_init(&state, body.c_str(), body.size(), FLAG_NONE);

            // request body
            if (runOnString("body", body, body)) {
                spdlog::warn("SQL Injection detected; user ip: " + std::string(req.base().at("X-Forwarded-For")));
            }

            if (libinjection_is_sqli(&state)) {
                spdlog::warn("[LibInjection] {} {}", "SQL Injection detected; user ip: ",
                             std::string(req.base().at("X-Forwarded-For")));
            }


        }

        bool runOnString(std::string varkind, const std::string &var_name, const std::string &var_value) {
            std::vector<std::string> patterns = {
                    R"((?i)\b(?:database\W*\(|db_name\W*\(|information_schema|master\.\.sysdatabases|msdb|sys\.database_name|sysaux|northwind|pg_(?:catalog|toast)|tempdb|schema(?:_name\b|\W*\()|sqlite_(?:temp_)?master)\b)",
                    R"((?i)\b(?:a(?:dd(?:dat|tim)e|es_(?:de|en)crypt|s(?:cii(?:str)?|in)|tan2?)|b(?:enchmark|i(?:n_to_num|t_(?:and|count|length|x?or)))|c(?:har(?:acter)?_length|iel(?:ing)?|o(?:alesce|ercibility|llation|(?:mpres)?s|n(?:cat(?:_ws)?|nection_id|v(?:ert(?:_tz)?)?)|t)|r32|ur(?:(?:dat|tim)e|rent_(?:date|setting|time(?:stamp)?|user)))|d(?:a(?:t(?:abase(?:_to_xml)?|e(?:_(?:add|format|sub)|diff))|y(?:name|of(?:month|week|year)))|count|e(?:code|grees|s_(?:de|en)crypt)|ump)|e(?:lt|n(?:c(?:ode|rypt)|ds_?with)|x(?:p(?:ort_set)?|tract(?:value)?))|f(?:i(?:el|n)d_in_set|ound_rows|rom_(?:base64|days|unixtime))|g(?:e(?:ometrycollection|t(?:_(?:format|lock)|pgusername))|(?:r(?:eates|oup_conca)|tid_subse)t)|hex(?:toraw)?|i(?:fnull|n(?:et6?_(?:aton|ntoa)|s(?:ert|tr)|terval)|s(?:_(?:(?:free|used)_lock|ipv(?:4(?:_(?:compat|mapped))?|6)|n(?:ot(?:_null)?|ull)|superuser)|null))|json(?:_(?:a(?:gg|rray(?:_(?:elements(?:_text)?|length))?)|build_(?:array|object)|e(?:ac|xtract_pat)h(?:_text)?|object(?:_(?:agg|keys))?|populate_record(?:set)?|strip_nulls|t(?:o_record(?:set)?|ypeof))|b(?:_(?:array(?:_(?:elements(?:_text)?|length))?|build_(?:array|object)|object(?:_(?:agg|keys))?|e(?:ac|xtract_pat)h(?:_text)?|insert|p(?:ath_(?:(?:exists|match)(?:_tz)?|query(?:_(?:(?:array|first)(?:_tz)?|tz))?)|opulate_record(?:set)?|retty)|s(?:et(?:_lax)?|trip_nulls)|t(?:o_record(?:set)?|ypeof)))?|path)?|l(?:ast_(?:day|inser_id)|case|e(?:as|f)t|i(?:kel(?:ihood|y)|nestring)|o(?:_(?:from_bytea|put)|ad_file|ca(?:ltimestamp|te)|g(?:10|2)|wer)|pad|trim)|m(?:a(?:ke(?:_set|date)|ster_pos_wait)|d5|i(?:crosecon)?d|onthname|ulti(?:linestring|po(?:int|lygon)))|n(?:ame_const|ot_in|ullif)|o(?:ct(?:et_length)?|(?:ld_passwo)?rd)|p(?:eriod_(?:add|diff)|g_(?:client_encoding|(?:databas|read_fil)e|l(?:argeobject|s_dir)|sleep|user)|o(?:(?:lyg|siti)on|w)|rocedure_analyse)|qu(?:arter|ery_to_xml|ote)|r(?:a(?:dians|nd|wtohex)|elease_lock|ow_(?:count|to_json)|pad|trim)|s(?:chema|e(?:c_to_time|ssion_user)|ha[12]?|in|oundex|pace|q(?:lite_(?:compileoption_(?:get|used)|source_id)|rt)|t(?:arts_?with|d(?:dev_(?:po|sam)p)?|r(?:_to_date|cmp))|ub(?:(?:dat|tim)e|str(?:ing(?:_index)?)?)|ys(?:date|tem_user))|t(?:ime(?:_(?:format|to_sec)|diff|stamp(?:add|diff)?)|o(?:_(?:base64|jsonb?)|n?char|(?:day|second)s)|r(?:im|uncate))|u(?:case|n(?:compress(?:ed_length)?|hex|i(?:str|x_timestamp)|likely)|(?:pdatexm|se_json_nul)l|tc_(?:date|time(?:stamp)?)|uid(?:_short)?)|var(?:_(?:po|sam)p|iance)|we(?:ek(?:day|ofyear)|ight_string)|xmltype|yearweek)[^0-9A-Z_a-z]*\()",
                    R"((?i:sleep\(\s*?\d*?\s*?\)|benchmark\(.*?\,.*?\)))",
                    R"((?i)(?:select|;)[\s\x0b]+(?:benchmark|if|sleep)[\s\x0b]*?\([\s\x0b]*?\(?[\s\x0b]*?[0-9A-Z_a-z]+)",
                    R"((?i)[\"'`](?:[\s\x0b]*![\s\x0b]*[\"'0-9A-Z_-z]|;?[\s\x0b]*(?:having|select|union\b[\s\x0b]*(?:all|(?:distin|sele)ct))\b[\s\x0b]*[^\s\x0b])|\b(?:(?:(?:c(?:onnection_id|urrent_user)|database|schema|user)[\s\x0b]*?|select.*?[0-9A-Z_a-z]?user)\(|exec(?:ute)?[\s\x0b]+master\.|from[^0-9A-Z_a-z]+information_schema[^0-9A-Z_a-z]|into[\s\x0b\+]+(?:dump|out)file[\s\x0b]*?[\"'`]|union(?:[\s\x0b]select[\s\x0b]@|[\s\x0b\(0-9A-Z_a-z]*?select))|[\s\x0b]*?exec(?:ute)?.*?[^0-9A-Z_a-z]xp_cmdshell|[^0-9A-Z_a-z]iif[\s\x0b]*?\()",
                    "^(?i:-0000023456|4294967295|4294967296|2147483648|2147483647|0000012345|-2147483648|-2147483649|0000023456|2.2250738585072007e-308|2.2250738585072011e-308|1e309)$",
                    R"((?i)[\s\x0b\(\)]case[\s\x0b]+when.*?then|\)[\s\x0b]*?like[\s\x0b]*?\(|select.*?having[\s\x0b]*?[^\s\x0b]+[\s\x0b]*?[^\s\x0b0-9A-Z_a-z]|if[\s\x0b]?\([0-9A-Z_a-z]+[\s\x0b]*?[<->~])",
                    R"((?i)alter[\s\x0b]*?[0-9A-Z_a-z]+.*?char(?:acter)?[\s\x0b]+set[\s\x0b]+[0-9A-Z_a-z]+|[\"'`](?:;*?[\s\x0b]*?waitfor[\s\x0b]+(?:time|delay)[\s\x0b]+[\"'`]|;.*?:[\s\x0b]*?goto))",
                    R"((?i:merge.*?using\s*?\(|execute\s*?immediate\s*?[\"'`]|match\s*?[\w(),+-]+\s*?against\s*?\())",
                    "(?i)union.*?select.*?from",
                    R"((?i)select[\s\x0b]*?pg_sleep|waitfor[\s\x0b]*?delay[\s\x0b]?[\"'`]+[\s\x0b]?[0-9]|;[\s\x0b]*?shutdown[\s\x0b]*?(?:[#;\{]|/\*|--))",
                    R"((?i)\[?\$(?:n(?:e|in?|o[rt])|e(?:q|xists|lemMatch)|l(?:te?|ike)|mod|a(?:ll|nd)|(?:s(?:iz|lic)|wher)e|t(?:ype|ext)|x?or|div|between|regex|jsonSchema)\]?)",
                    R"((?i)create[\s\x0b]+(?:function|procedure)[\s\x0b]*?[0-9A-Z_a-z]+[\s\x0b]*?\([\s\x0b]*?\)[\s\x0b]*?-|d(?:eclare[^0-9A-Z_a-z]+[#@][\s\x0b]*?[0-9A-Z_a-z]+|iv[\s\x0b]*?\([\+\-]*[\s\x0b\.0-9]+,[\+\-]*[\s\x0b\.0-9]+\))|exec[\s\x0b]*?\([\s\x0b]*?@|(?:lo_(?:impor|ge)t|procedure[\s\x0b]+analyse)[\s\x0b]*?\(|;[\s\x0b]*?(?:declare|open)[\s\x0b]+[\-0-9A-Z_a-z]+|::(?:b(?:igint|ool)|double[\s\x0b]+precision|int(?:eger)?|numeric|oid|real|(?:tex|smallin)t))",
                    R"((?i)create[\s\x0b]+function[\s\x0b].+[\s\x0b]returns|;[\s\x0b]*?(?:alter|(?:(?:cre|trunc|upd)at|renam)e|d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load)\b[\s\x0b]*?[\(\[]?[0-9A-Z_a-z]{2,})",
                    R"((?i)\b(?:(?:alter|(?:(?:cre|trunc|upd)at|renam)e|de(?:lete|sc)|(?:inser|selec)t|load)[\s\x0b]+(?:char|group_concat|load_file)\b[\s\x0b]*\(?|end[\s\x0b]*?\);)|[\s\x0b\(]load_file[\s\x0b]*?\(|[\"'`][\s\x0b]+regexp[^0-9A-Z_a-z]|[\"'0-9A-Z_-z][\s\x0b]+as\b[\s\x0b]*[\"'0-9A-Z_-z]+[\s\x0b]*\bfrom|^[^A-Z_a-z]+[\s\x0b]*?(?:(?:(?:(?:cre|trunc)at|renam)e|d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load)[\s\x0b]+[0-9A-Z_a-z]+|u(?:pdate[\s\x0b]+[0-9A-Z_a-z]+|nion[\s\x0b]*(?:all|(?:sele|distin)ct)\b)|alter[\s\x0b]*(?:a(?:(?:ggregat|pplication[\s\x0b]*rol)e|s(?:sembl|ymmetric[\s\x0b]*ke)y|u(?:dit|thorization)|vailability[\s\x0b]*group)|b(?:roker[\s\x0b]*priority|ufferpool)|c(?:ertificate|luster|o(?:l(?:latio|um)|nversio)n|r(?:edential|yptographic[\s\x0b]*provider))|d(?:atabase|efault|i(?:mension|skgroup)|omain)|e(?:(?:ndpoi|ve)nt|xte(?:nsion|rnal))|f(?:lashback|oreign|u(?:lltext|nction))|hi(?:erarchy|stogram)|group|in(?:dex(?:type)?|memory|stance)|java|l(?:a(?:ngua|r)ge|ibrary|o(?:ckdown|g(?:file[\s\x0b]*group|in)))|m(?:a(?:s(?:k|ter[\s\x0b]*key)|terialized)|e(?:ssage[\s\x0b]*type|thod)|odule)|(?:nicknam|queu)e|o(?:perator|utline)|p(?:a(?:ckage|rtition)|ermission|ro(?:cedur|fil)e)|r(?:e(?:mot|sourc)e|o(?:l(?:e|lback)|ute))|s(?:chema|e(?:arch|curity|rv(?:er|ice)|quence|ssion)|y(?:mmetric[\s\x0b]*key|nonym)|togroup)|t(?:able(?:space)?|ext|hreshold|r(?:igger|usted)|ype)|us(?:age|er)|view|w(?:ork(?:load)?|rapper)|x(?:ml[\s\x0b]*schema|srobject))\b))",
                    R"((?i)/\*[\s\x0b]*?[!\+](?:[\s\x0b\(\)\-0-9=A-Z_a-z]+)?\*/)",
                    R"(^(?:[^']*'|[^\"]*\"|[^`]*`)[\s\x0b]*;)",
                    R"((?i)1\.e[\(\),])",
                    R"([\"'`][\[\{].*[\]\}][\"'`].*(::.*jsonb?)?.*(?:(?:@|->?)>|<@|\?[&\|]?|#>>?|[<>]|<-)|(?:(?:@|->?)>|<@|\?[&\|]?|#>>?|[<>]|<-)[\"'`][\[\{].*[\]\}][\"'`]|json_extract.*\(.*\))",
                    // paranoia lvl 2
                    R"((?i)!=|&&|\|\||>[=>]|<(?:<|=>?|>(?:[\s\x0b]+binary)?)|\b(?:(?:xor|r(?:egexp|like)|i(?:snull|like)|notnull)\b|collate(?:[^0-9A-Z_a-z]*?(?:U&)?[\"'`]|[^0-9A-Z_a-z]+(?:(?:binary|nocase|rtrim)\b|[0-9A-Z_a-z]*?_))|(?:likel(?:ihood|y)|unlikely)[\s\x0b]*\()|r(?:egexp|like)[\s\x0b]+binary|not[\s\x0b]+between[\s\x0b]+(?:0[\s\x0b]+and|(?:'[^']*'|\"[^\"]*\")[\s\x0b]+and[\s\x0b]+(?:'[^']*'|\"[^\"]*\"))|is[\s\x0b]+null|like[\s\x0b]+(?:null|[0-9A-Z_a-z]+[\s\x0b]+escape\b)|(?:^|[^0-9A-Z_a-z])in[\s\x0b\+]*\([\s\x0b\"0-9]+[^\(\)]*\)|[!<->]{1,2}[\s\x0b]*all\b)",
                    R"((?i)[\s\x0b\"'-\)`]*?\b([0-9A-Z_a-z]+)\b[\s\x0b\"'-\)`]*?(?:=|<=>|(?:sounds[\s\x0b]+)?like|glob|r(?:like|egexp))[\s\x0b\"'-\)`]*?\b([0-9A-Z_a-z]+)\b)",
                    R"((?i)\b(?:json(?:_[0-9A-Z_a-z]+)?|a(?:bs|(?:cos|sin)h?|tan[2h]?|vg)|c(?:eil(?:ing)?|h(?:a(?:nges|r(?:set)?)|r)|o(?:alesce|sh?|unt)|ast)|d(?:e(?:grees|fault)|a(?:te|y))|exp|f(?:loor(?:avg)?|ormat|ield)|g(?:lob|roup_concat)|h(?:ex|our)|i(?:f(?:null)?|if|n(?:str)?)|l(?:ast(?:_insert_rowid)?|ength|ike(?:l(?:ihood|y))?|n|o(?:ad_extension|g(?:10|2)?|wer(?:pi)?|cal)|trim)|m(?:ax|in(?:ute)?|o(?:d|nth))|n(?:ullif|ow)|p(?:i|ow(?:er)?|rintf|assword)|quote|r(?:a(?:dians|ndom(?:blob)?)|e(?:p(?:lace|eat)|verse)|ound|trim|ight)|s(?:i(?:gn|nh?)|oundex|q(?:lite_(?:compileoption_(?:get|used)|offset|source_id|version)|rt)|u(?:bstr(?:ing)?|m)|econd|leep)|t(?:anh?|otal(?:_changes)?|r(?:im|unc)|ypeof|ime)|u(?:n(?:icode|likely)|(?:pp|s)er)|zeroblob|bin|v(?:alues|ersion)|week|year)[^0-9A-Z_a-z]*\()",
                    R"((?i)(?:/\*)+[\"'`]+[\s\x0b]?(?:--|[#\{]|/\*)?|[\"'`](?:[\s\x0b]*(?:(?:x?or|and|div|like|between)[\s\x0b\-0-9A-Z_a-z]+[\(\)\+-\-<->][\s\x0b]*[\"'0-9`]|[!=\|](?:[\s\x0b!\+\-0-9=]+.*?[\"'\(`].*?|[\s\x0b!0-9=]+.*?[0-9]+)$|(?:like|print)[^0-9A-Z_a-z]+[\"'\(0-9A-Z_-z]|;)|(?:[<>~]+|[\s\x0b]*[^\s\x0b0-9A-Z_a-z]?=[\s\x0b]*|[^0-9A-Z_a-z]*?[\+=]+[^0-9A-Z_a-z]*?)[\"'`])|[0-9][\"'`][\s\x0b]+[\"'`][\s\x0b]+[0-9]|^admin[\s\x0b]*?[\"'`]|[\s\x0b\"'\(`][\s\x0b]*?glob[^0-9A-Z_a-z]+[\"'\(0-9A-Z_-z]|[\s\x0b]is[\s\x0b]*?0[^0-9A-Z_a-z]|where[\s\x0b][\s\x0b,-\.0-9A-Z_a-z]+[\s\x0b]=)",
                    R"((?i),.*?[\"'\)0-9`-f][\"'`](?:[\"'`].*?[\"'`]|(?:\r?\n)?\z|[^\"'`]+)|[^0-9A-Z_a-z]select.+[^0-9A-Z_a-z]*?from|(?:alter|(?:(?:cre|trunc|upd)at|renam)e|d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load)[\s\x0b]*?\([\s\x0b]*?space[\s\x0b]*?\()",
                    R"((?i)(?:&&|\|\||and|between|div|like|n(?:and|ot)|(?:xx?)?or)[\s\x0b\(]+[0-9A-Z_a-z]+[\s\x0b\)]*?[!\+=]+[\s\x0b0-9]*?[\"'-\)=`]|[0-9](?:[\s\x0b]*?(?:and|between|div|like|x?or)[\s\x0b]*?[0-9]+[\s\x0b]*?[\+\-]|[\s\x0b]+group[\s\x0b]+by.+\()|/[0-9A-Z_a-z]+;?[\s\x0b]+(?:and|between|div|having|like|x?or|select)[^0-9A-Z_a-z]|(?:[#;]|--)[\s\x0b]*?(?:alter|drop|(?:insert|update)[\s\x0b]*?[0-9A-Z_a-z]{2,})|@.+=[\s\x0b]*?\([\s\x0b]*?select|[^0-9A-Z_a-z]SET[\s\x0b]*?@[0-9A-Z_a-z]+)",
                    R"((?i)[\"'`][\s\x0b]*?(?:(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between|\|\||&&)[\s\x0b]+[\s\x0b0-9A-Z_a-z]+=[\s\x0b]*?[0-9A-Z_a-z]+[\s\x0b]*?having[\s\x0b]+|like[^0-9A-Z_a-z]*?[\"'0-9`])|[0-9A-Z_a-z][\s\x0b]+like[\s\x0b]+[\"'`]|like[\s\x0b]*?[\"'`]%|select[\s\x0b]+?[\s\x0b\"'-\)\-.,0-9A-Z_-z]+from[\s\x0b]+)",
                    R"((?i)\)[\s\x0b]*?when[\s\x0b]*?[0-9]+[\s\x0b]*?then|[\"'`][\s\x0b]*?(?:[#\{]|--)|/\*![\s\x0b]?[0-9]+|\b(?:(?:binary|cha?r)[\s\x0b]*?\([\s\x0b]*?[0-9]|(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between|r(?:egexp|like))[\s\x0b]+[0-9A-Z_a-z]+\()|(?:\|\||&&)[\s\x0b]*?[0-9A-Z_a-z]+\()",
                    R"((?i)(?:\([\s\x0b]*?select[\s\x0b]*?[0-9A-Z_a-z]+|coalesce|order[\s\x0b]+by[\s\x0b]+if[0-9A-Z_a-z]*?)[\s\x0b]*?\(|\*/from|\+[\s\x0b]*?[0-9]+[\s\x0b]*?\+[\s\x0b]*?@|[0-9A-Z_a-z][\"'`][\s\x0b]*?(?:(?:[\+\-=@\|]+[\s\x0b]+?)+|[\+\-=@\|]+)[\(0-9]|@@[0-9A-Z_a-z]+[\s\x0b]*?[^\s\x0b0-9A-Z_a-z]|[^0-9A-Z_a-z]!+[\"'`][0-9A-Z_a-z]|[\"'`](?:;[\s\x0b]*?(?:if|while|begin)|[\s\x0b0-9]+=[\s\x0b]*?[0-9])|[\s\x0b\(]+case[0-9]*?[^0-9A-Z_a-z].+[tw]hen[\s\x0b\(])",
                    R"((?i)[\"'`][\s\x0b]*?\b(?:x?or|div|like|between|and)\b[\s\x0b]*?[\"'`]?[0-9]|\x5cx(?:2[37]|3d)|^(?:.?[\"'`]$|[\"'\x5c`]*?(?:[\"'0-9`]+|[^\"'`]+[\"'`])[\s\x0b]*?\b(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between|\|\||&&)\b[\s\x0b]*?[\"'0-9A-Z_-z][!&\(\)\+-\.@])|[^\s\x0b0-9A-Z_a-z][0-9A-Z_a-z]+[\s\x0b]*?[\-\|][\s\x0b]*?[\"'`][\s\x0b]*?[0-9A-Z_a-z]|@(?:[0-9A-Z_a-z]+[\s\x0b]+(?:and|x?or|div|like|between)\b[\s\x0b]*?[\"'0-9`]+|[\-0-9A-Z_a-z]+[\s\x0b](?:and|x?or|div|like|between)\b[\s\x0b]*?[^\s\x0b0-9A-Z_a-z])|[^\s\x0b0-:A-Z_a-z][\s\x0b]*?[0-9][^0-9A-Z_a-z]+[^\s\x0b0-9A-Z_a-z][\s\x0b]*?[\"'`].|[^0-9A-Z_a-z]information_schema|table_name[^0-9A-Z_a-z])",
                    R"((?i)in[\s\x0b]*?\(+[\s\x0b]*?select|(?:(?:N?AND|X?X?OR|DIV|LIKE|BETWEEN|NOT)[\s\x0b]+|(?:\|\||&&)[\s\x0b]*)[\s\x0b\+0-9A-Z_a-z]+(?:regexp[\s\x0b]*?\(|sounds[\s\x0b]+like[\s\x0b]*?[\"'`]|[0-9=]+x)|[\"'`](?:[\s\x0b]*?(?:[0-9][\s\x0b]*?(?:--|#)|is[\s\x0b]*?(?:[0-9].+[\"'`]?[0-9A-Z_a-z]|[\.0-9]+[\s\x0b]*?[^0-9A-Z_a-z].*?[\"'`]))|[%&<->\^]+[0-9][\s\x0b]*?(?:=|x?or|div|like|between|and)|(?:[^0-9A-Z_a-z]+[\+\-0-9A-Z_a-z]+[\s\x0b]*?=[\s\x0b]*?[0-9][^0-9A-Z_a-z]+|\|?[\-0-9A-Z_a-z]{3,}[^\s\x0b,\.0-9A-Z_a-z]+)[\"'`]|[\s\x0b]*(?:(?:N?AND|X?X?OR|DIV|LIKE|BETWEEN|NOT)[\s\x0b]+|(?:\|\||&&)[\s\x0b]*)(?:array[\s\x0b]*\[|[0-9A-Z_a-z]+(?:[\s\x0b]*!?~|[\s\x0b]+(?:not[\s\x0b]+)?similar[\s\x0b]+to[\s\x0b]+)|(?:tru|fals)e\b))|\bexcept[\s\x0b]+(?:select\b|values[\s\x0b]*?\())",
                    R"((?i:^[\W\d]+\s*?(?:alter|union)\b))",
                    R"((?i)(?:alter|(?:(?:cre|trunc|upd)at|renam)e|de(?:lete|sc)|(?:inser|selec)t|load)[\s\x0b]+(?:char|group_concat|load_file)[\s\x0b]?\(?|end[\s\x0b]*?\);|[\s\x0b\(]load_file[\s\x0b]*?\(|[\"'`][\s\x0b]+regexp[^0-9A-Z_a-z]|[^A-Z_a-z][\s\x0b]+as\b[\s\x0b]*[\"'0-9A-Z_-z]+[\s\x0b]*\bfrom|^[^A-Z_a-z]+[\s\x0b]*?(?:create[\s\x0b]+[0-9A-Z_a-z]+|(?:d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load|(?:renam|truncat)e|u(?:pdate|nion[\s\x0b]*(?:all|(?:sele|distin)ct))|alter[\s\x0b]*(?:a(?:(?:ggregat|pplication[\s\x0b]*rol)e|s(?:sembl|ymmetric[\s\x0b]*ke)y|u(?:dit|thorization)|vailability[\s\x0b]*group)|b(?:roker[\s\x0b]*priority|ufferpool)|c(?:ertificate|luster|o(?:l(?:latio|um)|nversio)n|r(?:edential|yptographic[\s\x0b]*provider))|d(?:atabase|efault|i(?:mension|skgroup)|omain)|e(?:(?:ndpoi|ve)nt|xte(?:nsion|rnal))|f(?:lashback|oreign|u(?:lltext|nction))|hi(?:erarchy|stogram)|group|in(?:dex(?:type)?|memory|stance)|java|l(?:a(?:ngua|r)ge|ibrary|o(?:ckdown|g(?:file[\s\x0b]*group|in)))|m(?:a(?:s(?:k|ter[\s\x0b]*key)|terialized)|e(?:ssage[\s\x0b]*type|thod)|odule)|(?:nicknam|queu)e|o(?:perator|utline)|p(?:a(?:ckage|rtition)|ermission|ro(?:cedur|fil)e)|r(?:e(?:mot|sourc)e|o(?:l(?:e|lback)|ute))|s(?:chema|e(?:arch|curity|rv(?:er|ice)|quence|ssion)|y(?:mmetric[\s\x0b]*key|nonym)|togroup)|t(?:able(?:space)?|ext|hreshold|r(?:igger|usted)|ype)|us(?:age|er)|view|w(?:ork(?:load)?|rapper)|x(?:ml[\s\x0b]*schema|srobject)))\b))",
                    R"((?i)\b(?:having\b(?:[\s\x0b]+(?:[0-9]{1,10}|'[^=]{1,10}')[\s\x0b]*?[<->]| ?(?:[0-9]{1,10} ?[<->]+|[\"'][^=]{1,10}[ \"'<-\?\[]+))|ex(?:ecute(?:\(|[\s\x0b]{1,5}[\$\.0-9A-Z_a-z]{1,5}[\s\x0b]{0,3})|ists[\s\x0b]*?\([\s\x0b]*?select\b)|(?:create[\s\x0b]+?table.{0,20}?|like[^0-9A-Z_a-z]*?char[^0-9A-Z_a-z]*?)\()|select.*?case|from.*?limit|order[\s\x0b]by|exists[\s\x0b](?:[\s\x0b]select|s(?:elect[^\s\x0b](?:if(?:null)?[\s\x0b]\(|top|concat)|ystem[\s\x0b]\()|\bhaving\b[\s\x0b]+[0-9]{1,10}|'[^=]{1,10}'))",
                    R"((?i)\b(?:or\b(?:[\s\x0b]?(?:[0-9]{1,10}|[\"'][^=]{1,10}[\"'])[\s\x0b]?[<->]+|[\s\x0b]+(?:[0-9]{1,10}|'[^=]{1,10}')(?:[\s\x0b]*?[<->])?)|xor\b[\s\x0b]+(?:[0-9]{1,10}|'[^=]{1,10}')(?:[\s\x0b]*?[<->])?)|'[\s\x0b]+x?or[\s\x0b]+.{1,20}[!\+\-<->])",
                    R"((?i)\band\b(?:[\s\x0b]+(?:[0-9]{1,10}[\s\x0b]*?[<->]|'[^=]{1,10}')| ?(?:[0-9]{1,10}|[\"'][^=]{1,10}[\"']) ?[<->]+))",
                    "(?i)autonomous_transaction|(?:current_use|n?varcha|tbcreato)r|db(?:a_users|ms_java)|open(?:owa_util|query|rowset)|s(?:p_(?:(?:addextendedpro|sqlexe)c|execute(?:sql)?|help|is_srvrolemember|makewebtask|oacreate|p(?:assword|repare)|replwritetovarbin)|ql_(?:longvarchar|variant))|utl_(?:file|http)|xp_(?:availablemedia|(?:cmdshel|servicecontro)l|dirtree|e(?:numdsn|xecresultset)|filelist|loginconfig|makecab|ntsec(?:_enumdomains)?|reg(?:addmultistring|delete(?:key|value)|enum(?:key|value)s|re(?:ad|movemultistring)|write)|terminate(?:_process)?)",
                    R"((?i)\b(?:(?:d(?:bms_[0-9A-Z_a-z]+\.|elete\b[^0-9A-Z_a-z]*?\bfrom)|(?:group\b.*?\bby\b.{1,100}?\bhav|overlay\b[^0-9A-Z_a-z]*?\(.*?\b[^0-9A-Z_a-z]*?plac)ing|in(?:ner\b[^0-9A-Z_a-z]*?\bjoin|sert\b[^0-9A-Z_a-z]*?\binto|to\b[^0-9A-Z_a-z]*?\b(?:dump|out)file)|load\b[^0-9A-Z_a-z]*?\bdata\b.*?\binfile|s(?:elect\b.{1,100}?\b(?:(?:.*?\bdump\b.*|(?:count|length)\b.{1,100}?)\bfrom|(?:data_typ|from\b.{1,100}?\bwher)e|instr|to(?:_(?:cha|numbe)r|p\b.{1,100}?\bfrom))|ys_context)|u(?:nion\b.{1,100}?\bselect|tl_inaddr))\b|print\b[^0-9A-Z_a-z]*?@@)|(?:collation[^0-9A-Z_a-z]*?\(a|@@version|;[^0-9A-Z_a-z]*?\b(?:drop|shutdown))\b|'(?:dbo|msdasql|s(?:a|qloledb))')",
                    R"(/\*!?|\*/|[';]--|--(?:[\s\x0b]|[^\-]*?-)|[^&\-]#.*?[\s\x0b]|;?\x00)",
                    // if above rule matches run this on each match "^ey[\\-0-9A-Z_a-z]+\\.ey[\\-0-9A-Z_a-z]+\\.[\\-0-9A-Z_a-z]+$"
                    R"((?i:\b0x[a-f\d]{3,}))",
                    R"((?:`(?:(?:[\w\s=_\-+{}()<@]){2,29}|(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)`))",
                    R"((?i)[\"'`][\s\x0b]*?(?:(?:is[\s\x0b]+not|not[\s\x0b]+(?:like|glob|(?:betwee|i)n|null|regexp|match)|mod|div|sounds[\s\x0b]+like)\b|[%&\*\+\-/<->\^\|]))",
                    R"((?i)^(?:[^']*?(?:'[^']*?'[^']*?)*?'|[^\"]*?(?:\"[^\"]*?\"[^\"]*?)*?\"|[^`]*?(?:`[^`]*?`[^`]*?)*?`)[\s\x0b]*([0-9A-Z_a-z]+)\b)",
                    // if above match group 1 also matches this "^(?:and|or)$" block request
                    R"(^.*?\x5c['\"`](?:.*?['\"`])?\s*(?:and|or)\b)",
                    // paranoia lvl 3
                    R"((?i)\W+\d*?\s*?\bhaving\b\s*?[^\s\-])",
            };

            for (const auto &pattern: patterns) {
                boost::regex regex(pattern);
                boost::smatch match;
                if (boost::regex_search(var_value, match, regex)) {
                    if (pattern ==
                        R"((?i)^(?:[^']*?(?:'[^']*?'[^']*?)*?'|[^\"]*?(?:\"[^\"]*?\"[^\"]*?)*?\"|[^`]*?(?:`[^`]*?`[^`]*?)*?`)[\s\x0b]*([0-9A-Z_a-z]+)\b)") {
                        if (boost::regex_search(var_value, match, boost::regex("^(?:and|or)$"))) {
                            log(var_name, varkind, match);
                            scanner::Scanner::isBlocked = true;
                            return true;
                        } else {
                            continue;
                        }
                    }
                    scanner::Scanner::isBlocked = true;
                    log(var_name, varkind, match);
                    return true;
                }
            }

            return false;
        }

        void log(std::string var_name, std::string var_kind, boost::smatch match) {
            ApiWrapper::log("CRITICAL", "SQL Injection Attempt Blocked", var_name, var_kind,
                            std::string(match[0].first, match[0].second),
                            this->current_req->at("X-Forwarded-For"));
        }
    };
}
#endif //ARCANEAGT_SQLINJECTION_H
