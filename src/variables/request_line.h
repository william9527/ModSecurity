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

#ifndef SRC_VARIABLES_REQUEST_LINE_H_
#define SRC_VARIABLES_REQUEST_LINE_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class RequestLine : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: REQUEST_LINE

    \verbatim
    This variable holds the complete request line sent to the server (including
    the request method and HTTP version information).

    = # Allow only POST, GET and HEAD request methods, as well as only
    = # the valid protocol versions
    = SecRule REQUEST_LINE "!(^((?:(?:POS|GE)T|HEAD))|HTTP/(0\.9|1\.0|1\.1)$)" "phase:1,id:49,log,block,t:none"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    RequestLine()
        : Variable("REQUEST_LINE") { }
    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableRequestLine.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_REQUEST_LINE_H_
