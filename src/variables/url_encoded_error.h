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

#ifndef SRC_VARIABLES_URL_ENCODED_ERROR_H_
#define SRC_VARIABLES_URL_ENCODED_ERROR_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class UrlEncodedError : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: URLENCODED_ERROR

    \verbatim
    This variable is created when an invalid URL encoding is encountered during
    the parsing of a query string (on every request) or during the parsing of
    an application/x-www-form-urlencoded request body (only on the requests
    that use the URLENCODED request body processor).


    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    UrlEncodedError()
        : Variable("URLENCODED_ERROR") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableUrlEncodedError.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_URL_ENCODED_ERROR_H_
