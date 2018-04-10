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

#ifndef SRC_VARIABLES_QUERY_STRING_H_
#define SRC_VARIABLES_QUERY_STRING_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class QueryString : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: QUERY_STRING

    \verbatim
    Contains the query string part of a request URI. The value in QUERY_STRING
    is always provided raw, without URL decoding taking place.

    = SecRule QUERY_STRING "attack" "id:34"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    QueryString()
        : Variable("QUERY_STRING") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableQueryString.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_QUERY_STRING_H_
