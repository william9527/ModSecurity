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

#include <vector>
#include <string>
#include <list>
#include <utility>

#ifndef SRC_VARIABLES_TIME_MIN_H_
#define SRC_VARIABLES_TIME_MIN_H_

#include "src/variables/variable.h"

namespace modsecurity {

class Transaction;
namespace Variables {

class TimeMin : public Variable {
    /** @ingroup ModSecurity_Variables ModSecurity_RefManual ModSecurity_RefManualVar */
    /**

    Description

    Name: TIME_MIN

    \verbatim
    This variable holds the current minute value (0–59). The following rule
    triggers during the last half hour of every hour:

    = SecRule TIME_MIN "^(3|4|5)" "id:77"
    \endverbatim


    Details

    \verbatim
    \endverbatim

    */
 public:
    explicit TimeMin(std::string _name)
        : Variable(_name),
        m_retName("TIME_MIN") { }

    void evaluate(Transaction *transaction,
        Rule *rule,
        std::vector<const VariableValue *> *l) override;
    std::string m_retName;
};

}  // namespace Variables
}  // namespace modsecurity

#endif  // SRC_VARIABLES_TIME_MIN_H_
