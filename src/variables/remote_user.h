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

#ifndef SRC_VARIABLES_REMOTE_USER_H_
#define SRC_VARIABLES_REMOTE_USER_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {


class RemoteUser : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: REMOTE_USER

    \verbatim
    This variable holds the username of the authenticated user. If there are no
    password access controls in place (Basic or Digest authentication), then
    this variable will be empty.

    = SecRule REMOTE_USER "@streq admin" "id:38"

    Note: In a reverse-proxy deployment, this information will not be available
    if the authentication is handled in the backend web server.
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit RemoteUser(std::string _name)
        : Variable(_name),
        m_retName("REMOTE_USER") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override;
    std::string m_retName;
};


}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_REMOTE_USER_H_

