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

#ifndef SRC_VARIABLES_FILES_COMBINED_SIZE_H_
#define SRC_VARIABLES_FILES_COMBINED_SIZE_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class FilesCombinedSize : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: FILES_COMBINED_SIZE

    \verbatim
    Contains the total size of the files transported in request body. Available
    only on inspected multipart/form-data requests.

    = SecRule FILES_COMBINED_SIZE "@gt 100000" "id:18"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    FilesCombinedSize()
        : Variable("FILES_COMBINED_SIZE") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableFilesCombinedSize.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_FILES_COMBINED_SIZE_H_
