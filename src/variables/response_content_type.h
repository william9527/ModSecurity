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

#ifndef SRC_VARIABLES_RESPONSE_CONTENT_TYPE_H_
#define SRC_VARIABLES_RESPONSE_CONTENT_TYPE_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class ResponseContentType : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: RESPONSE_CONTENT_TYPE

    \verbatim
    Response content type. Available only starting with phase 3. The value
    available in this variable is taken directly from the internal structures
    of Apache, which means that it may contain the information that is not yet
    available in response headers. In embedded deployments, you should always
    refer to this variable, rather than to RESPONSE_HEADERS:Content-Type.
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    ResponseContentType()
        : Variable("RESPONSE_CONTENT_TYPE") { }
    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableResponseContentType.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_RESPONSE_CONTENT_TYPE_H_
