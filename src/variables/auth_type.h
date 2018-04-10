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

#ifndef SRC_VARIABLES_AUTH_TYPE_H_
#define SRC_VARIABLES_AUTH_TYPE_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class AuthType : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: AUTH_TYPE

    \verbatim
    This variable holds the authentication method used to validate a user, if
    any of the methods built into HTTP are used. In a reverse-proxy deployment,
    this information will not be available if the authentication is handled in
    the backend web server.

    = SecRule AUTH_TYPE "Basic" "id:14"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    AuthType()
        : Variable("AUTH_TYPE") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableAuthType.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_AUTH_TYPE_H_
