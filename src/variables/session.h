/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#include <iostream>
#include <string>
#include <vector>
#include <list>
#include <utility>

#ifndef SRC_VARIABLES_SESSION_H_
#define SRC_VARIABLES_SESSION_H_

#include "src/variables/variable.h"
#include "src/run_time_string.h"

namespace modsecurity {

class Transaction;
namespace Variables {


class Session_DictElement : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: SESSION

    \verbatim
    This variable is a collection that contains session information. It becomes
    available only after setsid is executed.

    The following example shows how to initialize SESSION using setsid, how to
    use setvar to increase the SESSION.score values, how to set the
    SESSION.blocked variable, and finally, how to deny the connection based on
    the SESSION:blocked value:

    = # Initialize session storage
    = SecRule REQUEST_COOKIES:PHPSESSID !^$ "phase:2,id:70,nolog,pass,setsid:%{REQUEST_COOKIES.PHPSESSID}"
    =
    = # Increment session score on attack
    = SecRule REQUEST_URI "^/cgi-bin/finger$" "phase:2,id:71,t:none,t:lowercase,t:normalizePath,pass,setvar:SESSION.score=+10"
    =
    = # Detect too many attacks in a session
    = SecRule SESSION:score "@gt 50" "phase:2,id:72,pass,setvar:SESSION.blocked=1"
    =
    = # Enforce session block
    = SecRule SESSION:blocked "@eq 1" "phase:2,id:73,deny,status:403"

    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit Session_DictElement(std::string dictElement)
        : Variable("SESSION"),
        m_dictElement(dictElement) { }

    void evaluate(Transaction *t,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        t->m_collections.m_session_collection->resolveMultiMatches(
            m_dictElement, t->m_collections.m_session_collection_key,
            t->m_rules->m_secWebAppId.m_value, l);
    }

    std::string m_dictElement;
};


class Session_NoDictElement : public Variable {
 public:
    Session_NoDictElement()
        : Variable("SESSION") { }

    void evaluate(Transaction *t,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        t->m_collections.m_session_collection->resolveMultiMatches(m_name,
            t->m_collections.m_session_collection_key,
            t->m_rules->m_secWebAppId.m_value, l);
    }
};


class Session_DictElementRegexp : public Variable {
 public:
    explicit Session_DictElementRegexp(std::string dictElement)
        : Variable("SESSION:regex(" + dictElement + ")"),
        m_r(dictElement),
        m_dictElement(dictElement) { }

    void evaluate(Transaction *t,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        t->m_collections.m_session_collection->resolveRegularExpression(m_dictElement,
            t->m_collections.m_session_collection_key,
            t->m_rules->m_secWebAppId.m_value, l);
    }

    Utils::Regex m_r;
    std::string m_dictElement;
};


class Session_DynamicElement : public Variable {
 public:
    explicit Session_DynamicElement(std::unique_ptr<RunTimeString> dictElement)
        : Variable("SESSION:dynamic"),
        m_string(std::move(dictElement)) { }

    void evaluate(Transaction *t,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        std::string string = m_string->evaluate(t);
        t->m_collections.m_session_collection->resolveMultiMatches(
            string,
            t->m_collections.m_session_collection_key, l);
    }

    void del(Transaction *t, std::string k) {
        t->m_collections.m_session_collection->del(k,
            t->m_collections.m_session_collection_key);
    }

    void storeOrUpdateFirst(Transaction *t, std::string var,
        std::string value) {
        t->m_collections.m_session_collection->storeOrUpdateFirst(
            var, t->m_collections.m_session_collection_key,
            value);
    }

    std::unique_ptr<RunTimeString> m_string;
};


}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_SESSION_H_
