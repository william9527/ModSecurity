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

#ifndef SRC_VARIABLES_MULTIPART_STRICT_ERROR_H_
#define SRC_VARIABLES_MULTIPART_STRICT_ERROR_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class MultipartStrictError : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: MULTIPART_STRICT_ERROR

    \verbatim
    MULTIPART_STRICT_ERROR will be set to 1 when any of the following variables
    is also set to 1: REQBODY_PROCESSOR_ERROR, MULTIPART_BOUNDARY_QUOTED,
    MULTIPART_BOUNDARY_WHITESPACE, MULTIPART_DATA_BEFORE, MULTIPART_DATA_AFTER,
    MULTIPART_HEADER_FOLDING, MULTIPART_LF_LINE, MULTIPART_MISSING_SEMICOLON
    MULTIPART_INVALID_QUOTING MULTIPART_INVALID_HEADER_FOLDING
    MULTIPART_FILE_LIMIT_EXCEEDED. Each of these variables covers one unusual
    (although sometimes legal) aspect of the request body in
    multipart/form-data format. Your policies should always contain a rule to
    check either this variable (easier) or one or more individual variables (if
    you know exactly what you want to accomplish). Depending on the rate of
    false positives and your default policy you should decide whether to block
    or just warn when the rule is triggered.

    The best way to use this variable is as in the example below:
    = SecRule MULTIPART_STRICT_ERROR "!@eq 0" "phase:2,id:30,t:none,log,deny,msg:'Multipart request body failed strict validation: PE %{REQBODY_PROCESSOR_ERROR}, BQ %{MULTIPART_BOUNDARY_QUOTED}, BW %{MULTIPART_BOUNDARY_WHITESPACE}, DB %{MULTIPART_DATA_BEFORE}, DA %{MULTIPART_DATA_AFTER}, HF %{MULTIPART_HEADER_FOLDING}, \
LF %{MULTIPART_LF_LINE}, SM %{MULTIPART_MISSING_SEMICOLON}, IQ %{MULTIPART_INVALID_QUOTING}, IQ %{MULTIPART_INVALID_HEADER_FOLDING}, FE %{MULTIPART_FILE_LIMIT_EXCEEDED}'"

    The multipart/form-data parser was upgraded in ModSecurity v2.1.3 to
    actively look for signs    of evasion. Many variables (as listed above)
    were added to expose various facts discovered during the parsing process.
    The MULTIPART_STRICT_ERROR variable is handy to check on all abnormalities
    at once. The individual variables allow detection to be fine-tuned
    according to your circumstances in order to reduce the number of false
    positives.
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    MultipartStrictError()
        : Variable("MULTIPART_STRICT_ERROR") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableMultipartStrictError.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_MULTIPART_STRICT_ERROR_H_
