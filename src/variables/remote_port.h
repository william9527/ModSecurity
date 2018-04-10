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

#ifndef SRC_VARIABLES_REMOTE_PORT_H_
#define SRC_VARIABLES_REMOTE_PORT_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class RemotePort : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: REMOTE_PORT

    \verbatim
    This variable holds information on the source port that the client used
    when initiating the connection to our web server.

    In the following example, we are evaluating to see whether the REMOTE_PORT
    is less than 1024, which would indicate that the user is a privileged user:

    = SecRule REMOTE_PORT "@lt 1024" "id:37"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    RemotePort()
        : Variable("REMOTE_PORT") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableRemotePort.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_REMOTE_PORT_H_
