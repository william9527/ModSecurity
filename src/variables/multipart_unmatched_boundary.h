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

#ifndef SRC_VARIABLES_MULTIPART_UNMATCHED_BOUNDARY_H_
#define SRC_VARIABLES_MULTIPART_UNMATCHED_BOUNDARY_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class MultipartUnmatchedBoundary : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: MULTIPART_UNMATCHED_BOUNDARY

    \verbatim
    Set to 1 when, during the parsing phase of a multipart/request-body,
    ModSecurity encounters what feels like a boundary but it is not. Such an
    event may occur when evasion of ModSecurity is attempted.

    The best way to use this variable is as in the example below:

    = SecRule MULTIPART_UNMATCHED_BOUNDARY "!@eq 0" \
"phase:2,id:31,t:none,log,deny,msg:'Multipart parser detected a possible unmatched boundary.'"

    Change the rule from blocking to logging-only if many false positives are
    encountered.
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    MultipartUnmatchedBoundary()
        : Variable("MULTIPART_UNMATCHED_BOUNDARY") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableMultipartUnmatchedBoundary.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_MULTIPART_UNMATCHED_BOUNDARY_H_
