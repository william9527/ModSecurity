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

#ifndef SRC_VARIABLES_MULTIPART_CRLF_LF_LINES_H_
#define SRC_VARIABLES_MULTIPART_CRLF_LF_LINES_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class MultipartCrlfLFLines : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: MULTIPART_CRLF_LF_LINES

    \verbatim
    This flag variable will be set to 1 whenever a multi-part request uses
    mixed line terminators. The multipart/form-data RFC requires CRLF sequence
    to be used to terminate lines. Since some client implementations use only
    LF to terminate lines you might want to allow them to proceed under certain
    circumstances (if you want to do this you will need to stop using
    MULTIPART_STRICT_ERROR and check each multi-part flag variable
    individually, avoiding MULTIPART_LF_LINE). However, mixing CRLF and LF line
    terminators is dangerous as it can allow for evasion. Therefore, in such
    cases, you will have to add a check for MULTIPART_CRLF_LF_LINES.
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    MultipartCrlfLFLines()
        : Variable("MULTIPART_CRLF_LF_LINES") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableMultipartCrlfLFLines.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_MULTIPART_CRLF_LF_LINES_H_
