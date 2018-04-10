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

#ifndef SRC_VARIABLES_REMOTE_HOST_H_
#define SRC_VARIABLES_REMOTE_HOST_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class RemoteHost : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: REMOTE_HOST

    \verbatim
    If the Apache directive HostnameLookups is set to On, then this variable
    will hold the remote hostname resolved through DNS. If the directive is set
    to Off, this variable it will hold the remote IP address (same as
    REMOTE_ADDR). Possible uses for this variable would be to deny known bad
    client hosts or network blocks, or conversely, to allow in authorized
    hosts.

    = SecRule REMOTE_HOST "\.evil\.network\org$" "id:36"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    RemoteHost()
        : Variable("REMOTE_HOST") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableRemoteHost.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_REMOTE_HOST_H_
