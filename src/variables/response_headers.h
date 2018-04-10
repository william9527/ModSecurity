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

#ifndef SRC_VARIABLES_RESPONSE_HEADERS_H_
#define SRC_VARIABLES_RESPONSE_HEADERS_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class ResponseHeaders_DictElement : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: RESPONSE_HEADERS

    \verbatim
    This variable refers to response headers, in the same way as
    REQUEST_HEADERS does to request headers.

    = SecRule RESPONSE_HEADERS:X-Cache "MISS" "id:55"

    This variable may not have access to some headers when running in embedded
    mode. Headers such as Server, Date, Connection, and Content-Type could be
    added just prior to sending the data to the client. This data should be
    available in phase 5 or when deployed in proxy mode.
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit ResponseHeaders_DictElement(std::string dictElement)
        : Variable("RESPONSE_HEADERS" + std::string(":") +
            std::string(dictElement)),
        m_dictElement(dictElement) { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        transaction->m_variableResponseHeaders.resolve(m_dictElement, l);
    }

    std::string m_dictElement;
};


class ResponseHeaders_NoDictElement : public Variable {
 public:
    ResponseHeaders_NoDictElement()
        : Variable("RESPONSE_HEADERS") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        transaction->m_variableResponseHeaders.resolve(l);
    }
};


class ResponseHeaders_DictElementRegexp : public Variable {
 public:
    explicit ResponseHeaders_DictElementRegexp(std::string dictElement)
        : Variable("RESPONSE_HEADERS"),
        m_r(dictElement) { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        transaction->m_variableResponseHeaders.resolveRegularExpression(
            &m_r, l);
    }

    Utils::Regex m_r;
};


}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_RESPONSE_HEADERS_H_

