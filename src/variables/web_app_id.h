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

#ifndef SRC_VARIABLES_WEB_APP_ID_H_
#define SRC_VARIABLES_WEB_APP_ID_H_

#include "src/variables/variable.h"
#include "modsecurity/rule.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class WebAppId : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: WEBAPPID

    \verbatim
    This variable contains the current application name, which is set in
    configuration using SecWebAppId.

    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    WebAppId()
        : Variable("WEBAPPID") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override {
        const std::string name("WEBAPPID");
        const std::string rname = transaction->m_rules->m_secWebAppId.m_value;
        l->push_back(new VariableValue(&m_name, &rname));
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_WEB_APP_ID_H_
