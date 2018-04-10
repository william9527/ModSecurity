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

#ifndef SRC_VARIABLES_USER_ID_H_
#define SRC_VARIABLES_USER_ID_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class UserID : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: USERID

    \verbatim
    This variable contains the value set with setuid.

    = # Initialize user tracking
    = SecAction "nolog,id:84,pass,setuid:%{REMOTE_USER}"
    =
    = # Is the current user the administrator?
    = SecRule USERID "admin" "id:85"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    UserID()
        : Variable("USERID") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableUserID.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_USER_ID_H_
