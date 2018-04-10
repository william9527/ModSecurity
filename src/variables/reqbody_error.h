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

#ifndef SRC_VARIABLES_REQBODY_ERROR_H_
#define SRC_VARIABLES_REQBODY_ERROR_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class ReqbodyError : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: REQBODY_ERROR

    \verbatim
    Contains the status of the request body processor used for request body
    parsing. The values can be 0 (no error) or 1 (error). This variable will be
    set by request body processors (typically the multipart/request-data
    parser, JSON or the XML parser) when they fail to do their work.

    = SecRule REQBODY_ERROR "@eq 1" deny,phase:2,id:39

    Note: Your policies must have a rule to check for request body processor
    errors at the very beginning of phase 2. Failure to do so will leave the
    door open for impedance mismatch attacks. It is possible, for example, that
    a payload that cannot be parsed by ModSecurity can be successfully parsed
    by more tolerant parser operating in the application. If your policy
    dictates blocking, then you should reject the request if error is detected.
    When operating in detection-only mode, your rule should alert with high
    severity when request body processing fails.
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    ReqbodyError()
        : Variable("REQBODY_ERROR") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableReqbodyError.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_REQBODY_ERROR_H_
