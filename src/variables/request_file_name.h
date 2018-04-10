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

#ifndef SRC_VARIABLES_REQUEST_FILE_NAME_H_
#define SRC_VARIABLES_REQUEST_FILE_NAME_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class RequestFilename : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: REQUEST_FILENAME

    \verbatim
    This variable holds the relative request URL without the query string part
    (e.g., /index.php).

    = SecRule REQUEST_FILENAME "^/cgi-bin/login\.php$" phase:2,id:46,t:none,t:normalizePath

    Note: Please note that anti-evasion transformations are not used on
    REQUEST_FILENAME, which means that you will have to specify them in the
    rules that use this variable.
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    RequestFilename()
        : Variable("REQUEST_FILENAME") { }
    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableRequestFilename.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_REQUEST_FILE_NAME_H_
