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

#ifndef SRC_VARIABLES_FULL_REQUEST_H_
#define SRC_VARIABLES_FULL_REQUEST_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class FullRequest : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: FULL_REQUEST

    \verbatim
    Contains the complete request: Request line, Request headers and Request
    body (if any). The last available only if SecRequestBodyAccess was set to
    On. Note that all properties of SecRequestBodyAccess will be respected
    here, such as: SecRequestBodyLimit.

    = SecRule FULL_REQUEST "User-Agent: ModSecurity Regression Tests" "id:21"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    FullRequest()
        : Variable("FULL_REQUEST") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableFullRequest.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_FULL_REQUEST_H_
