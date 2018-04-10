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

#ifndef SRC_VARIABLES_REQUEST_BODY_H_
#define SRC_VARIABLES_REQUEST_BODY_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class RequestBody : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: REQUEST_BODY

    \verbatim
    Holds the raw request body. This variable is available only if the
    URLENCODED request body processor was used, which will occur by default
    when the application/x-www-form-urlencoded content type is detected, or if
    the use of the URLENCODED request body parser was forced.

    = SecRule REQUEST_BODY "^username=\w{25,}\&password=\w{25,}\&Submit\=login$" "id:43"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    RequestBody()
        : Variable("REQUEST_BODY") { }
    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableRequestBody.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_REQUEST_BODY_H_
