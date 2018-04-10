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

#ifndef SRC_VARIABLES_REQUEST_PROTOCOL_H_
#define SRC_VARIABLES_REQUEST_PROTOCOL_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class RequestProtocol : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: REQUEST_PROTOCOL

    \verbatim
    This variable holds the request protocol version information.

    = SecRule REQUEST_PROTOCOL "!^HTTP/(0\.9|1\.0|1\.1)$" "id:51"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    RequestProtocol()
        : Variable("REQUEST_PROTOCOL") { }
    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableRequestProtocol.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_REQUEST_PROTOCOL_H_
