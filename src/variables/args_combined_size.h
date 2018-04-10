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

#ifndef SRC_VARIABLES_ARGS_COMBINED_SIZE_H_
#define SRC_VARIABLES_ARGS_COMBINED_SIZE_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class ArgsCombinedSize : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: ARGS_COMBINED_SIZE

    \verbatim
    Contains the combined size of all request parameters. Files are excluded
    from the calculation. This variable can be useful, for example, to create a
    rule to ensure that the total size of the argument data is below a certain
    threshold. The following rule detects a request whose para- meters are more
    than 2500 bytes long:

    = SecRule ARGS_COMBINED_SIZE "@gt 2500" "id:12"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    ArgsCombinedSize()
        : Variable("ARGS_COMBINED_SIZE") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) {
        transaction->m_variableARGScombinedSize.evaluate(l);
    }
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_ARGS_COMBINED_SIZE_H_
