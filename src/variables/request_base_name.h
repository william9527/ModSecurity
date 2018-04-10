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

#ifndef SRC_VARIABLES_REQUEST_BASE_NAME_H_
#define SRC_VARIABLES_REQUEST_BASE_NAME_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class RequestBasename : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: REQUEST_BASENAME

    \verbatim
    This variable holds just the filename part of REQUEST_FILENAME (e.g.,
    index.php).

    = SecRule REQUEST_BASENAME "^login\.php$" phase:2,id:42,t:none,t:lowercase

    Note: Please note that anti-evasion transformations are not applied to this
    variable by default. REQUEST_BASENAME will recognise both / and \ as path
    separators. You should understand that the value of this variable depends
    on what was provided in request, and that it does not have to correspond to
    the resource (on disk) that will be used by the web server.
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    RequestBasename()
        : Variable("REQUEST_BASENAME") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableRequestBasename.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_REQUEST_BASE_NAME_H_
