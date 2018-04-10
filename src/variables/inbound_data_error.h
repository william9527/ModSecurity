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

#ifndef SRC_VARIABLES_INBOUND_DATA_ERROR_H_
#define SRC_VARIABLES_INBOUND_DATA_ERROR_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class InboundDataError : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: INBOUND_DATA_ERROR

    \verbatim
    This variable will be set to 1 when the request body size is above the
    setting configured by SecRequestBodyLimit directive. Your policies should
    always contain a rule to check this variable. Depending on the rate of
    false positives and your default policy you should decide whether to block
    or just warn when the rule is triggered.

    The best way to use this variable is as in the example below:

    = SecRule INBOUND_DATA_ERROR "@eq 1" "phase:1,id:24,t:none,log,pass,msg:'Request Body Larger than SecRequestBodyLimit Setting'"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    InboundDataError()
        : Variable("INBOUND_DATA_ERROR") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableInboundDataError.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_INBOUND_DATA_ERROR_H_
