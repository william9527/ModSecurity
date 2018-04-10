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

#ifndef SRC_VARIABLES_RESPONSE_CONTENT_LENGTH_H_
#define SRC_VARIABLES_RESPONSE_CONTENT_LENGTH_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class ResponseContentLength : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: RESPONSE_CONTENT_LENGTH

    \verbatim
    Response body length in bytes. Can be available starting with phase 3, but
    it does not have to be (as the length of response body is not always known
    in advance). If the size is not known, this variable will contain a zero.
    If RESPONSE_CONTENT_LENGTH contains a zero in phase 5 that means the actual
    size of the response body was 0. The value of this variable can change
    between phases if the body is modified. For example, in embedded mode,
    mod_deflate can compress the response body between phases 4 and 5.
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    ResponseContentLength()
        : Variable("RESPONSE_CONTENT_LENGTH") { }
    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableResponseContentLength.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_RESPONSE_CONTENT_LENGTH_H_
