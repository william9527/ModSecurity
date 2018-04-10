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

#ifndef SRC_VARIABLES_RESPONSE_PROTOCOL_H_
#define SRC_VARIABLES_RESPONSE_PROTOCOL_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class ResponseProtocol : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: RESPONSE_PROTOCOL

    \verbatim
    This variable holds the HTTP response protocol information.

    = SecRule RESPONSE_PROTOCOL "^HTTP\/0\.9" "phase:3,id:57,t:none"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    ResponseProtocol()
        : Variable("RESPONSE_PROTOCOL") { }
    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableResponseProtocol.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_RESPONSE_PROTOCOL_H_
